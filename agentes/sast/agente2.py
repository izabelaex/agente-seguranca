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

import ast
import re
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from contratos.schemas import EntradaSistema, SaidaSAST, AchadoSAST
from orquestrador.llm_client import llm
from agentes.regras_seguranca import REGRA_SQL_PARAMETRIZADO, REGRA_MARK_SAFE_MARKUP


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

def _capturar_trecho_completo(linhas: list[str], indice: int, max_linhas: int = 15) -> str:
    """
    A partir da linha onde a regex bateu, estende a captura para as linhas
    seguintes enquanto a instrução continuar "aberta" — parênteses não
    fechados (chamadas como execute(...) que quebram linha) ou uma string
    triplamente citada (\"\"\"/''') ainda não fechada.

    Sem isso, uma instrução como:
        cur.execute(\"\"\"DELETE FROM foo
        WHERE id = '%s'\"\"\", identifier)
    manda pro LLM só a primeira linha, escondendo o ", identifier)" que
    prova que a query é parametrizada — o LLM nunca vê a informação
    necessária para decidir corretamente.

    Returns:
        Trecho (uma ou mais linhas, unidas por \\n) representando a
        instrução completa a partir da linha do candidato.
    """
    def _aspas_ao_final_da_linha(linha: str, delimitador_aberto: str | None) -> str | None:
        """
        Varre a linha caractere a caractere e retorna qual delimitador de string
        tripla (\"\"\" ou ''') continua aberto ao final, ou None se fechado.

        Precisa ser um único estado (não duas contagens independentes) porque uma
        ocorrência de ''' dentro de uma string \"\"\" já fechada (ex.: `x = \"\"\"a'''b\"\"\"`)
        não deve ser tratada como abertura de uma nova string tripla.
        """
        i = 0
        n = len(linha)
        while i < n:
            if delimitador_aberto:
                if linha[i:i + 3] == delimitador_aberto:
                    delimitador_aberto = None
                    i += 3
                    continue
            elif linha[i:i + 3] in ('"""', "'''"):
                delimitador_aberto = linha[i:i + 3]
                i += 3
                continue
            i += 1
        return delimitador_aberto

    linha_inicial = linhas[indice]
    trecho = [linha_inicial.strip()]
    parens = linha_inicial.count("(") - linha_inicial.count(")")
    aspas_abertas = _aspas_ao_final_da_linha(linha_inicial, None)

    i = indice
    while (
        (parens > 0 or aspas_abertas)
        and i + 1 < len(linhas)
        and len(trecho) < max_linhas
    ):
        i += 1
        linha = linhas[i]
        trecho.append(linha.strip())
        parens += linha.count("(") - linha.count(")")
        aspas_abertas = _aspas_ao_final_da_linha(linha, aspas_abertas)

    return "\n".join(trecho)


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
                    "trecho": _capturar_trecho_completo(linhas, num - 1),
                    "cwe": cwe,
                })

    return candidatos


#Verificação determinística via AST — perguntas puramente sintáticas (número de
#argumentos de uma chamada, presença de variável numa expressão) não exigem
#julgamento do LLM. Testes repetidos mostraram o LLM inconsistente justamente
#nesses dois casos mecânicos (SQL parametrizado, mark_safe/Markup só com
#literal) mesmo depois de ajuste de prompt e temperatura baixa — resolvendo em
#código, a resposta deixa de depender de amostragem do modelo.

def _nome_chamada(no_func: ast.expr) -> str | None:
    """Extrai o nome de uma chamada (ex.: 'execute' de cur.execute(...), ou 'Markup' de Markup(...))."""
    if isinstance(no_func, ast.Name):
        return no_func.id
    if isinstance(no_func, ast.Attribute):
        return no_func.attr
    return None


def _contem_variavel(no: ast.AST) -> bool:
    """True se a subárvore contiver qualquer referência a variável (ast.Name)."""
    return any(isinstance(sub, ast.Name) for sub in ast.walk(no))


def _sqli_parametrizada(trecho: str) -> bool | None:
    """
    Decide via AST se uma chamada a execute() está parametrizada corretamente
    (valores como argumento separado da query).

    Returns:
        True se claramente parametrizada (segura), False se claramente não
        parametrizada (só 1 argumento), None se não deu pra analisar (ex.: o
        trecho não contém um execute() isolado) — nesse caso o LLM decide.
    """
    try:
        arvore = ast.parse(trecho)
    except SyntaxError:
        return None
    for no in ast.walk(arvore):
        if isinstance(no, ast.Call) and _nome_chamada(no.func) == "execute":
            return len(no.args) >= 2
    return None


def _xss_mark_safe_com_variavel(trecho: str) -> bool | None:
    """
    Decide via AST se uma chamada a mark_safe()/Markup()/render_template_string()
    recebe uma variável (perigoso) ou só literais fixos (seguro).

    Returns:
        True/False se encontrar a chamada, None se não encontrar (ex.: o trecho
        é o outro padrão de XSS, concatenação direta em HTML) — nesse caso o LLM decide.
    """
    try:
        arvore = ast.parse(trecho)
    except SyntaxError:
        return None
    alvo = {"mark_safe", "Markup", "render_template_string"}
    for no in ast.walk(arvore):
        if isinstance(no, ast.Call) and _nome_chamada(no.func) in alvo:
            argumentos = list(no.args) + [kw.value for kw in no.keywords]
            return any(_contem_variavel(arg) for arg in argumentos)
    return None


def _decidir_deterministicamente(candidato: dict) -> bool | None:
    """Tenta decidir confirmado/descartado via AST antes de gastar uma chamada ao LLM."""
    if candidato["tipo"] == "sqli":
        parametrizada = _sqli_parametrizada(candidato["trecho"])
        return None if parametrizada is None else not parametrizada
    if candidato["tipo"] == "xss":
        return _xss_mark_safe_com_variavel(candidato["trecho"])
    return None


#Confirmação via LLM

_PROMPT_SISTEMA = f"""Você é um especialista em segurança de código Python.
Receberá trechos de código suspeitos de conter vulnerabilidades.
Para cada trecho, responda APENAS com um JSON válido (sem markdown) no formato:
{{{{
  "confirmado": true | false,
  "cve": "CVE-XXXX-XXXX ou null",
  "descricao": "explicação objetiva em uma frase"
}}}}
Se o trecho contiver uma senha, chave, token ou segredo literal atribuído diretamente a uma variável, SEMPRE confirme como verdadeiro positivo.
Se o trecho concatenar uma variável diretamente em HTML sem escape (XSS), SEMPRE confirme como verdadeiro positivo.
{REGRA_MARK_SAFE_MARKUP} Se houver XSS real, responda confirmado: true. Se não houver, responda confirmado: false.
{REGRA_SQL_PARAMETRIZADO} Se for parametrizada corretamente, responda confirmado: false. Caso contrário (perigosa), responda confirmado: true.
Se o trecho NÃO for vulnerável (falso positivo), responda com confirmado: false."""

_chain_confirmacao = (
    ChatPromptTemplate.from_messages([
        ("system", _PROMPT_SISTEMA),
        ("human", "{input}"),
    ])
    | llm
    | JsonOutputParser()
)


def _montar_achado(candidato: dict, descricao: str, cve: str | None = None) -> dict:
    return {
        "tipo": candidato["tipo"],
        "arquivo": candidato["arquivo"],
        "linha": candidato["linha"],
        "trecho": candidato["trecho"],
        "cwe": candidato["cwe"],
        "cve": cve,
        "descricao": descricao,
    }


def _confirmar_com_llm(candidato: dict) -> dict | None:
    """
    Usa o LLM para confirmar se o candidato é realmente vulnerável.

    Returns:
        AchadoSAST completo se confirmado, None se for falso positivo.
    """
    decisao = _decidir_deterministicamente(candidato)
    if decisao is not None:
        if not decisao:
            return None
        return _montar_achado(
            candidato,
            "Confirmado por análise sintática determinística (AST) — não depende de julgamento do LLM.",
        )

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

    return _montar_achado(candidato, dados.get("descricao", ""), cve)


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
