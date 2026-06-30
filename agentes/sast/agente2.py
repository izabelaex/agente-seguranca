"""
Agente 2 — SAST (Analisador Estático)
Responsável: Izabela

Varre arquivos Python buscando três padrões de risco priorizados no MVP:
  - SQL Injection  (CWE-89)
  - XSS            (CWE-79)
  - Segredo exposto / hardcoded credential (CWE-798)

Estratégia em duas camadas:
  1. Regex: captura padrões óbvios de forma rápida e determinística.
  2. LLM:   analisa trechos suspeitos para reduzir falsos positivos e
            identificar casos mais sutis que regex não cobre.
"""

import re
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from contratos.schemas import EntradaSistema, SaidaSAST, AchadoSAST
from orquestrador.llm_client import llm


#regex por vulnerabilidade

# SQL Injection: concatenação de variáveis em strings de query
_REGEX_SQLI = re.compile(
    r'(execute|query|raw)\s*\(\s*["\'].*?["\']'   # execute("SELECT ...
    r'|\bexecute\s*\(\s*f["\']'                    # execute(f"SELECT ...")
    r'|\bexecute\s*\(\s*["\'][^"\']*%[s|d]'        # execute("... %s")
    r'|\bexecute\s*\(\s*["\'][^"\']*\+',           # execute("..." + var)
    re.IGNORECASE,
)

# XSS: interpolação de variável em HTML sem escape
_REGEX_XSS = re.compile(
    r'(render_template_string|Markup|mark_safe)\s*\('           # Flask/Django unsafe render
    r'|\.format\s*\(.*?\)\s*.*?(html|template)'                 # "html {}".format(var)
    r'|f["\'].*?<[a-z]+.*?{'                                    # f"<p>{variavel}"
    r'|return\s+["\']<[^"\']+["\']\s*\+',  # return "<html...>" + var
    re.IGNORECASE,
)

# Segredos expostos: atribuições com palavras-chave sensíveis e valor literal
_REGEX_SEGREDO = re.compile(
    r'(?:password|passwd|secret|api_key|apikey|token|access_key|private_key'
    r'|auth_token|client_secret|pass)\w*\s*=\s*["\'][^"\']{4,}["\']',
    re.IGNORECASE,
)

PADROES = [
    ("sqli",           _REGEX_SQLI,    "CWE-89"),
    ("xss",            _REGEX_XSS,     "CWE-79"),
    ("segredo_exposto", _REGEX_SEGREDO, "CWE-798"),
]


#Varredura por regex

def _varrer_arquivo(caminho: str, conteudo: str) -> list[dict]:
    """
    Aplica os padrões de regex linha a linha e retorna candidatos suspeitos.

    Returns:
        Lista de dicts com tipo, linha, trecho, cwe para análise posterior pelo LLM.
    """
    candidatos = []
    linhas = conteudo.splitlines()

    for tipo, regex, cwe in PADROES:
        for num, linha in enumerate(linhas, start=1):
            if regex.search(linha):
                candidatos.append({
                    "tipo": tipo,
                    "arquivo": caminho,
                    "linha": num,
                    "trecho": linha.strip(),
                    "cwe": cwe,
                })

    return candidatos


#Confirmação via LLM

_PROMPT_SISTEMA = """Você é um especialista em segurança de código Python.
Receberá trechos de código suspeitos de conter vulnerabilidades.
Para cada trecho, responda APENAS com um JSON válido (sem markdown) no formato:
{{
  "confirmado": true | false,
  "cve": "CVE-XXXX-XXXX ou null",
  "descricao": "explicação objetiva em uma frase"
}}
Se o trecho contiver uma senha, chave, token ou segredo literal atribuído diretamente a uma variável, SEMPRE confirme como verdadeiro positivo.
Se o trecho concatenar uma variável diretamente em HTML sem escape (XSS), SEMPRE confirme como verdadeiro positivo.
Se o trecho NÃO for vulnerável (falso positivo), responda com confirmado: false."""

_chain_confirmacao = (
    ChatPromptTemplate.from_messages([
        ("system", _PROMPT_SISTEMA),
        ("human", "{input}"),
    ])
    | llm
    | JsonOutputParser()
)


def _confirmar_com_llm(candidato: dict) -> dict | None:
    """
    Usa o LLM para confirmar se o candidato é realmente vulnerável.

    Returns:
        AchadoSAST completo se confirmado, None se for falso positivo.
    """
    prompt = (
        f"Tipo suspeito: {candidato['tipo'].upper()} ({candidato['cwe']})\n"
        f"Arquivo: {candidato['arquivo']}, linha {candidato['linha']}\n"
        f"Trecho:\n{candidato['trecho']}\n\n"
        "Este trecho representa uma vulnerabilidade real?"
    )

    try:
        dados = _chain_confirmacao.invoke({"input": prompt})
    except Exception as e:
        # Em caso de falha do LLM, mantém o achado como suspeito
        print(f"  [SAST] Aviso: LLM não disponível para {candidato['arquivo']}:{candidato['linha']} — {e}")
        dados = {"confirmado": True, "cve": None, "descricao": "Padrão suspeito detectado por regex (LLM indisponível)."}

    if not dados.get("confirmado", False):
        return None

    cve_raw = dados.get("cve")
    cve = cve_raw if isinstance(cve_raw, str) and cve_raw.upper().startswith("CVE-") else None

    return {
        "tipo": candidato["tipo"],
        "arquivo": candidato["arquivo"],
        "linha": candidato["linha"],
        "trecho": candidato["trecho"],
        "cwe": candidato["cwe"],
        "cve": cve,
        "descricao": dados.get("descricao", ""),
    }


#Função principal

def analisar_codigo(entrada: EntradaSistema) -> SaidaSAST:
    """
    Recebe os arquivos do projeto e retorna achados de padrões de risco no código.

    Args:
        entrada: Payload no formato EntradaSistema.

    Returns:
        SaidaSAST com lista de achados confirmados (SQLi, XSS, segredo exposto).
    """
    print("[Agente 2 - SAST] Iniciando varredura estática...")

    candidatos = []

    for arq in entrada["arquivos"]:
        caminho = arq["caminho"]
        # Analisa apenas arquivos Python
        if not caminho.endswith(".py"):
            continue
        print(f"  Varrendo {caminho}...")
        encontrados = _varrer_arquivo(caminho, arq["conteudo"])
        candidatos.extend(encontrados)

    print(f"[Agente 2 - SAST] {len(candidatos)} candidato(s) encontrado(s). Confirmando com LLM...")

    achados: list[AchadoSAST] = []

    for candidato in candidatos:
        resultado = _confirmar_com_llm(candidato)
        if resultado:
            achados.append(resultado)
            print(f"  ✓ Confirmado: {resultado['tipo'].upper()} em {resultado['arquivo']}:{resultado['linha']}")
        else:
            print(f"  ✗ Falso positivo descartado: {candidato['arquivo']}:{candidato['linha']}")

    print(f"[Agente 2 - SAST] {len(achados)} achado(s) confirmado(s).")

    return {
        "projeto_id": entrada["projeto_id"],
        "achados_sast": achados,
    }
