import time
"""
Agente 4 — Gerador de Relatórios e Correções
Responsável: Izabela

Recebe os achados validados pelo Agente 3 e gera o relatório final com:
  - Priorização por severidade
  - Explicação legível de cada vulnerabilidade
  - Sugestão concreta de correção em Python
  - Referências CWE/CVE

Usa o LLM para gerar as explicações e sugestões em linguagem natural,
garantindo que o desenvolvedor entenda o problema e saiba como corrigi-lo.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from contratos.schemas import SaidaAvaliador, SaidaRelatorio, VulnerabilidadeRelatorio, AchadoValidado
from orquestrador.llm_client import llm


#Ordenação por severidade
_ORDEM_SEVERIDADE = {
    "critica": 1,
    "alta": 2,
    "media": 3,
    "baixa": 4,
    "informativo": 5,
}


def _ordenar_por_severidade(achados: list[AchadoValidado]) -> list[AchadoValidado]:
    return sorted(
        achados,
        key=lambda a: _ORDEM_SEVERIDADE.get(a["severidade"], 99),
    )


#Explicação via LLM

_PROMPT_SISTEMA = """Você é um especialista em segurança de código Python escrevendo para desenvolvedores.
Receberá um achado de vulnerabilidade confirmado e deve gerar:
  1. Uma explicação clara do problema (máximo 2 frases, sem jargão desnecessário).
  2. Uma sugestão concreta de correção em Python (trecho de código ou instrução direta).

Responda APENAS com JSON válido (sem markdown):
{{
  "explicacao": "...",
  "sugestao_correcao": "..."
}}"""

_chain_relatorio = (
    ChatPromptTemplate.from_messages([
        ("system", _PROMPT_SISTEMA),
        ("human", "{input}"),
    ])
    | llm
    | JsonOutputParser()
)


def _gerar_explicacao_e_correcao(achado: AchadoValidado) -> tuple[str, str]:
    """
    Usa o LLM para gerar explicação legível e sugestão de correção.

    Returns:
        Tupla (explicacao, sugestao_correcao).
    """
    localizacao = achado["localizacao"]
    local_str = localizacao["arquivo"]
    if localizacao.get("linha"):
        local_str += f", linha {localizacao['linha']}"

    prompt = (
        f"Vulnerabilidade: {achado['tipo']} ({achado['referencia_cwe_cve']})\n"
        f"Severidade: {achado['severidade'].upper()}\n"
        f"Localização: {local_str}\n"
        f"Descrição técnica: {achado['descricao']}\n"
        f"Justificativa de contexto: {achado['justificativa']}\n\n"
        "Gere a explicação para o desenvolvedor e a sugestão de correção."
    )

    try:
        time.sleep(3)
        dados = _chain_relatorio.invoke({"input": prompt})
        return dados.get("explicacao", achado["descricao"]), dados.get("sugestao_correcao", "Consulte a documentação do CWE referenciado.")
    except Exception as e:
        print(f"  [Relatório] Aviso: LLM indisponível para gerar explicação — {e}")
        return achado["descricao"], f"Corrija o padrão identificado. Referência: {achado['referencia_cwe_cve']}"


#Montagem do relatório

def _montar_vulnerabilidade(achado: AchadoValidado, prioridade: int) -> VulnerabilidadeRelatorio:
    """Monta uma VulnerabilidadeRelatorio a partir de um AchadoValidado."""
    explicacao, sugestao = _gerar_explicacao_e_correcao(achado)

    # Extrai trecho de código da descrição quando disponível
    trecho = ""
    if achado["localizacao"].get("linha"):
        trecho = f"Linha {achado['localizacao']['linha']} em {achado['localizacao']['arquivo']}"

    return {
        "tipo": achado["tipo"],
        "severidade": achado["severidade"],
        "prioridade": prioridade,
        "localizacao": achado["localizacao"],
        "trecho_codigo": trecho,
        "explicacao": explicacao,
        "sugestao_correcao": sugestao,
        "referencia_cwe_cve": achado["referencia_cwe_cve"],
    }


#Função principal

def gerar_relatorio(entrada: SaidaAvaliador) -> SaidaRelatorio:
    """
    Consolida achados validados em relatório final priorizado.

    Args:
        entrada: SaidaAvaliador com lista de achados validados e severidade.

    Returns:
        SaidaRelatorio com relatório final estruturado e priorizado.
    """
    # Filtra apenas os confirmados
    confirmados = [a for a in entrada["achados_validados"] if a["status"] == "confirmado"]

    print(f"[Agente 4 - Relatório] Gerando relatório com {len(confirmados)} vulnerabilidade(s) confirmada(s)...")

    if not confirmados:
        print("[Agente 4 - Relatório] Nenhuma vulnerabilidade confirmada. Relatório limpo.")
        return {
            "relatorio": {
                "projeto_id": entrada["projeto_id"],
                "total_vulnerabilidades": 0,
                "vulnerabilidades": [],
            }
        }

    # Ordena por severidade antes de numerar prioridade
    ordenados = _ordenar_por_severidade(confirmados)

    vulnerabilidades: list[VulnerabilidadeRelatorio] = []
    for prioridade, achado in enumerate(ordenados, start=1):
        print(f"  Gerando explicação {prioridade}/{len(ordenados)}: {achado['tipo']} ({achado['severidade']})...")
        vuln = _montar_vulnerabilidade(achado, prioridade)
        vulnerabilidades.append(vuln)

    print(f"[Agente 4 - Relatório] Relatório final gerado com {len(vulnerabilidades)} item(ns).")

    return {
        "relatorio": {
            "projeto_id": entrada["projeto_id"],
            "total_vulnerabilidades": len(vulnerabilidades),
            "vulnerabilidades": vulnerabilidades,
        }
    }
