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

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from contratos.schemas import (
    EntradaAvaliador,
    SaidaAvaliador,
    AchadoValidado,
    AchadoSCA,
    AchadoSAST,
    ContextoProjeto,
)
from orquestrador.llm_client import llm
from agentes.regras_seguranca import REGRA_SQL_PARAMETRIZADO, REGRA_MARK_SAFE_MARKUP


#Prompt do sistema

_PROMPT_SISTEMA = f"""Você é um especialista em segurança de aplicações (AppSec).
Receberá um achado de vulnerabilidade e o contexto real do sistema analisado.
Sua tarefa é:
  1. Decidir se o achado é real neste contexto (confirmado) ou um falso positivo contextual (descartado).
  2. Atribuir uma severidade efetiva considerando o contexto.

Antes de decidir, reavalie o trecho de código tecnicamente:
  - {REGRA_SQL_PARAMETRIZADO} Se for parametrizada corretamente: descarte. Caso contrário: mantenha confirmado.
  - {REGRA_MARK_SAFE_MARKUP} Se houver XSS real: mantenha confirmado. Caso contrário: descarte.

O status deve ser CONSISTENTE com a justificativa: se a justificativa conclui que não há
vulnerabilidade real, o status DEVE ser "descartado" (nunca "confirmado" com uma justificativa
que diz o contrário).

Critérios de severidade (baseados em CVSS):
  - critica : exploração remota trivial, dado sensível exposto, sem mitigação
  - alta    : exploração viável, impacto significativo, mitigações fracas
  - media   : exploração possível mas com requisitos, impacto moderado
  - baixa   : difícil de explorar ou impacto mínimo
  - informativo: boa prática, sem risco imediato

A exposição à internet (campo "Exposto à internet" no contexto) é o principal fator que
diferencia "crítica" de "alta": "crítica" pressupõe que um atacante remoto, sem acesso prévio
à rede interna, consegue explorar a falha diretamente pela internet. Se o contexto disser que
a aplicação NÃO está exposta à internet, um atacante precisaria antes de acesso à rede interna
— rebaixe a severidade em pelo menos um nível em relação ao que seria se a mesma falha estivesse
exposta (ex.: o que seria "critica" se exposta vira no máximo "alta" se não exposta), a menos
que outro fator justifique manter o nível mais alto mesmo assim (explique esse fator na
justificativa).

Responda APENAS com um JSON válido (sem markdown):
{{{{
  "status": "confirmado" | "descartado",
  "severidade": "critica" | "alta" | "media" | "baixa" | "informativo",
  "justificativa": "explicação objetiva em 1-2 frases considerando o contexto"
}}}}"""

_chain_severidade = (
    ChatPromptTemplate.from_messages([
        ("system", _PROMPT_SISTEMA),
        ("human", "{input}"),
    ])
    | llm
    | JsonOutputParser()
)


#Formatação do contexto para o LLM

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


#Ajuste determinístico de severidade (fora do LLM)

def _aplicar_teto_severidade(severidade: str, contexto: ContextoProjeto, justificativa: str) -> tuple[str, str]:
    """
    Aplica um teto determinístico à severidade retornada pelo LLM: sem exposição à
    internet, a falha não pode ser "critica" (que pressupõe exploração remota trivial,
    conforme os próprios critérios do prompt).

    Isso existe porque, na prática, o LLM não aplica essa distinção de forma confiável
    sozinho (testado repetidamente: mesmo achado, mesmo contexto "não exposto", manteve
    "critica" em 4 de 5 execuções) — pedir isso só por texto no prompt não é suficiente
    para garantir consistência, então a regra é forçada em código.

    Returns:
        Tupla (severidade_ajustada, justificativa_ajustada).
    """
    if not contexto["exposto_internet"] and severidade == "critica":
        nota = (
            " [Severidade ajustada de 'critica' para 'alta' pelo sistema: a aplicação "
            "não está exposta à internet, então a exploração remota trivial que "
            "justificaria 'critica' não se aplica.]"
        )
        return "alta", justificativa + nota
    return severidade, justificativa


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
        dados = _chain_severidade.invoke({"input": prompt})
        if not isinstance(dados, dict):
            raise ValueError(f"Resposta inesperada do LLM (não é dict): {type(dados)}")
    except Exception as e:
        print(f"  [Severidade] Aviso: erro ao avaliar achado — {e}. Mantendo como confirmado/alta.")
        dados = {
            "status": "confirmado",
            "severidade": "alta",
            "justificativa": "Avaliação automática indisponível (LLM inacessível). Revisão manual recomendada.",
        }

    tipo_raw = descricao_achado.split("\n")[0].replace("Tipo: ", "").strip()

    severidade, justificativa = _aplicar_teto_severidade(
        dados.get("severidade", "media"),
        contexto,
        dados.get("justificativa", ""),
    )

    return {
        "tipo": tipo_raw,
        "localizacao": localizacao,
        "referencia_cwe_cve": referencia,
        "descricao": descricao_achado.split("\n")[-1].replace("Descrição: ", "").strip(),
        "status": dados.get("status", "confirmado"),
        "severidade": severidade,
        "justificativa": justificativa,
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
