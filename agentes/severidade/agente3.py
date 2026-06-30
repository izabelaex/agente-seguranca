import time
"""
Agente 3 — Avaliador de Contexto e Severidade
Responsável: Izabela

Recebe os achados preliminares do SCA (Agente 1) e do SAST (Agente 2),
cruza com o contexto real do sistema fornecido pelo desenvolvedor e:
  - Confirma ou descarta cada achado (reduz falsos positivos contextuais)
  - Calcula a severidade efetiva usando critérios baseados em CVSS

Usa o LLM para raciocinar sobre cada achado individualmente no contexto
do sistema, produzindo justificativas legíveis para o desenvolvedor.
"""

import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from contratos.schemas import (
    EntradaAvaliador,
    SaidaAvaliador,
    AchadoValidado,
    AchadoSCA,
    AchadoSAST,
    ContextoProjeto,
)
from orquestrador.llm_client import chamar_llm


#Prompt do sistema

_PROMPT_SISTEMA = """Você é um especialista em segurança de aplicações (AppSec).
Receberá um achado de vulnerabilidade e o contexto real do sistema analisado.
Sua tarefa é:
  1. Decidir se o achado é real neste contexto (confirmado) ou um falso positivo contextual (descartado).
  2. Atribuir uma severidade efetiva considerando o contexto.

Critérios de severidade (baseados em CVSS):
  - critica : exploração remota trivial, dado sensível exposto, sem mitigação
  - alta    : exploração viável, impacto significativo, mitigações fracas
  - media   : exploração possível mas com requisitos, impacto moderado
  - baixa   : difícil de explorar ou impacto mínimo
  - informativo: boa prática, sem risco imediato

Responda APENAS com um JSON válido (sem markdown):
{
  "status": "confirmado" | "descartado",
  "severidade": "critica" | "alta" | "media" | "baixa" | "informativo",
  "justificativa": "explicação objetiva em 1-2 frases considerando o contexto"
}"""


#Formatação do contexto apra o LLM

def _formatar_contexto(contexto: ContextoProjeto) -> str:
    exposto = "Sim" if contexto["exposto_internet"] else "Não"
    return (
        f"Contexto do sistema:\n"
        f"  - Exposto à internet: {exposto}\n"
        f"  - Tipo de aplicação: {contexto['tipo_aplicacao']}\n"
        f"  - Validações existentes: {contexto['validacoes_existentes']}"
    )


def _formatar_achado_sca(achado: AchadoSCA) -> str:
    return (
        f"Tipo: Dependência vulnerável (SCA)\n"
        f"Dependência: {achado['dependencia']}=={achado['versao']}\n"
        f"CVE: {achado['cve']}\n"
        f"Severidade base (base de dados): {achado['severidade_base']}\n"
        f"Arquivo: {achado['arquivo']}"
    )


def _formatar_achado_sast(achado: AchadoSAST) -> str:
    cve = achado.get("cve") or "N/A"
    return (
        f"Tipo: {achado['tipo'].upper()} (SAST)\n"
        f"Referência: {achado['cwe']} / CVE: {cve}\n"
        f"Arquivo: {achado['arquivo']}, linha {achado['linha']}\n"
        f"Trecho: {achado['trecho']}\n"
        f"Descrição: {achado['descricao']}"
    )


#Avaliação de cada achado via LLM

def _avaliar_achado(descricao_achado: str, contexto: ContextoProjeto, referencia: str, localizacao: dict) -> AchadoValidado | None:
    """
    Envia um achado + contexto ao LLM e retorna o AchadoValidado resultante.

    Returns:
        AchadoValidado preenchido, ou None em caso de falha irrecuperável.
    """
    contexto_str = _formatar_contexto(contexto)
    prompt = f"{descricao_achado}\n\n{contexto_str}\n\nEste achado é real e relevante neste contexto?"

    try:
        time.sleep(3)
        resposta = chamar_llm(prompt, system=_PROMPT_SISTEMA)
        dados = json.loads(resposta.strip())
    except Exception as e:
        print(f"  [Severidade] Aviso: erro ao avaliar achado — {e}. Mantendo como confirmado/alta.")
        dados = {
            "status": "confirmado",
            "severidade": "alta",
            "justificativa": "Avaliação automática indisponível (LLM inacessível). Revisão manual recomendada.",
        }

    tipo_raw = descricao_achado.split("\n")[0].replace("Tipo: ", "").strip()

    return {
        "tipo": tipo_raw,
        "localizacao": localizacao,
        "referencia_cwe_cve": referencia,
        "descricao": descricao_achado.split("\n")[-1].replace("Descrição: ", "").strip(),
        "status": dados.get("status", "confirmado"),
        "severidade": dados.get("severidade", "media"),
        "justificativa": dados.get("justificativa", ""),
    }


#Função principal do Agente

def avaliar_severidade(entrada: EntradaAvaliador) -> SaidaAvaliador:
    """
    Cruza achados do SCA e do SAST com o contexto do sistema e calcula severidade.

    Args:
        entrada: Payload com achados_sca, achados_sast e contexto do projeto.

    Returns:
        SaidaAvaliador com achados validados (confirmados ou descartados) e severidade.
    """
    contexto = entrada["contexto"]
    projeto_id = entrada["projeto_id"]
    achados_validados: list[AchadoValidado] = []

    total = len(entrada["achados_sca"]) + len(entrada["achados_sast"])
    print(f"[Agente 3 - Severidade] Avaliando {total} achado(s) no contexto do sistema...")

    # Avalia achados do SCA
    for achado in entrada["achados_sca"]:
        print(f"  Avaliando SCA: {achado['dependencia']}=={achado['versao']} ({achado['cve']})...")
        descricao = _formatar_achado_sca(achado)
        localizacao = {"arquivo": achado["arquivo"], "linha": None}
        resultado = _avaliar_achado(descricao, contexto, achado["cve"], localizacao)
        if resultado:
            resultado["descricao"] = f"{achado['dependencia']}=={achado['versao']} possui {achado['cve']} ({achado['severidade_base']} na base)"
            achados_validados.append(resultado)
            print(f"    → {resultado['status'].upper()} / {resultado['severidade'].upper()}")

    # Avalia achados do SAST
    for achado in entrada["achados_sast"]:
        print(f"  Avaliando SAST: {achado['tipo'].upper()} em {achado['arquivo']}:{achado['linha']}...")
        descricao = _formatar_achado_sast(achado)
        localizacao = {"arquivo": achado["arquivo"], "linha": achado["linha"]}
        referencia = achado["cwe"] + (f" / {achado['cve']}" if achado.get("cve") else "")
        resultado = _avaliar_achado(descricao, contexto, referencia, localizacao)
        if resultado:
            resultado["descricao"] = achado["descricao"]
            achados_validados.append(resultado)
            print(f"    → {resultado['status'].upper()} / {resultado['severidade'].upper()}")

    confirmados = sum(1 for a in achados_validados if a["status"] == "confirmado")
    print(f"[Agente 3 - Severidade] {confirmados} confirmado(s), {len(achados_validados) - confirmados} descartado(s).")

    return {
        "projeto_id": projeto_id,
        "achados_validados": achados_validados,
    }
