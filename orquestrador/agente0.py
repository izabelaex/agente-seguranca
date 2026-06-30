"""
Agente 0 — Orquestrador
Responsável: Izabela

Ponto de entrada do sistema. Constrói e executa o pipeline de análise de
segurança como um grafo LangGraph, onde cada agente especialista é um nó.

Fluxo do grafo:
                    ┌─► [sca]  ─┐
  [entrada] ──► [distribuir] ─┤           ├─► [severidade] ──► [relatorio]
                    └─► [sast] ─┘

  - SCA e SAST rodam em paralelo (independentes entre si).
  - Severidade aguarda os dois antes de executar (join automático).
  - Relatório gera a saída final.

O grafo é visível como nós interativos no LangSmith (aba Traces).
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from langgraph.graph import StateGraph, END

from contratos.schemas import (
    EstadoPipeline,
    EntradaSistema,
    EntradaAvaliador,
    SaidaAvaliador,
    Arquivo,
    ContextoProjeto,
)
from agentes.sca.agente1 import analisar_dependencias
from agentes.sast.agente2 import analisar_codigo
from agentes.severidade.agente3 import avaliar_severidade
from agentes.relatorio.agente4 import gerar_relatorio
from orquestrador.llm_client import verificar_conexao


# ---------------------------------------------------------------------------
# Coleta de entrada (fora do grafo — acontece antes de invocar o pipeline)
# ---------------------------------------------------------------------------

def coletar_arquivos(caminhos: list[str]) -> list[Arquivo]:
    """Lê arquivos do disco e retorna no formato do contrato."""
    arquivos = []
    for caminho in caminhos:
        try:
            with open(caminho, "r", encoding="utf-8") as f:
                arquivos.append({"caminho": caminho, "conteudo": f.read()})
        except FileNotFoundError:
            print(f"[Aviso] Arquivo não encontrado: {caminho}")
    return arquivos


def coletar_contexto() -> ContextoProjeto:
    """Coleta contexto do projeto via diálogo com o desenvolvedor."""
    print("\n--- Contexto do projeto ---")
    exposto = input("A aplicação está exposta à internet? (s/n): ").strip().lower()
    tipo = input("Tipo de aplicação (ex.: API REST, web app, script interno): ").strip()
    validacoes = input("Descreva validações de entrada já existentes (ou 'nenhuma'): ").strip()
    return {
        "exposto_internet": exposto == "s",
        "tipo_aplicacao": tipo or "não informado",
        "validacoes_existentes": validacoes or "nenhuma",
    }


# ---------------------------------------------------------------------------
# Nós do grafo LangGraph
# ---------------------------------------------------------------------------

def _no_distribuir(estado: EstadoPipeline) -> dict:
    """Nó de entrada — distribui o estado para SCA e SAST em paralelo."""
    arquivos = estado.get("arquivos", [])
    print(f"\n[Agente 0] {len(arquivos)} arquivo(s) carregado(s). Delegando análise...")
    return {}


def _no_sca(estado: EstadoPipeline) -> dict:
    """Nó SCA — análise de dependências vulneráveis."""
    entrada: EntradaSistema = {
        "projeto_id": estado["projeto_id"],
        "arquivos": estado["arquivos"],
        "contexto": estado["contexto"],
    }
    saida = analisar_dependencias(entrada)
    return {"achados_sca": saida["achados_sca"]}


def _no_sast(estado: EstadoPipeline) -> dict:
    """Nó SAST — varredura estática do código."""
    entrada: EntradaSistema = {
        "projeto_id": estado["projeto_id"],
        "arquivos": estado["arquivos"],
        "contexto": estado["contexto"],
    }
    saida = analisar_codigo(entrada)
    return {"achados_sast": saida["achados_sast"]}


def _no_severidade(estado: EstadoPipeline) -> dict:
    """Nó Severidade — aguarda SCA + SAST e avalia cada achado com contexto."""
    entrada: EntradaAvaliador = {
        "projeto_id": estado["projeto_id"],
        "achados_sca": estado.get("achados_sca", []),
        "achados_sast": estado.get("achados_sast", []),
        "contexto": estado["contexto"],
    }
    saida = avaliar_severidade(entrada)
    return {"achados_validados": saida["achados_validados"]}


def _no_relatorio(estado: EstadoPipeline) -> dict:
    """Nó Relatório — gera o relatório final priorizado."""
    entrada: SaidaAvaliador = {
        "projeto_id": estado["projeto_id"],
        "achados_validados": estado.get("achados_validados", []),
    }
    saida = gerar_relatorio(entrada)
    return {"relatorio": saida["relatorio"]}


# ---------------------------------------------------------------------------
# Construção do grafo
# ---------------------------------------------------------------------------

def _construir_pipeline():
    builder = StateGraph(EstadoPipeline)

    builder.add_node("distribuir",  _no_distribuir)
    builder.add_node("sca",         _no_sca)
    builder.add_node("sast",        _no_sast)
    builder.add_node("severidade",  _no_severidade)
    builder.add_node("relatorio",   _no_relatorio)

    # Ponto de entrada → distribuidor
    builder.set_entry_point("distribuir")

    # Fan-out paralelo: distribuidor → SCA e SAST ao mesmo tempo
    builder.add_edge("distribuir", "sca")
    builder.add_edge("distribuir", "sast")

    # Fan-in: severidade aguarda ambos
    builder.add_edge("sca",        "severidade")
    builder.add_edge("sast",       "severidade")

    # Sequência final
    builder.add_edge("severidade", "relatorio")
    builder.add_edge("relatorio",  END)

    return builder.compile()


_pipeline = _construir_pipeline()


# ---------------------------------------------------------------------------
# Exibição do relatório
# ---------------------------------------------------------------------------

ICONE_SEVERIDADE = {
    "critica":     "🔴",
    "alta":        "🟠",
    "media":       "🟡",
    "baixa":       "🟢",
    "informativo": "⚪",
}


def exibir_relatorio(relatorio: dict) -> None:
    """Exibe o relatório final de forma legível no terminal."""
    total = relatorio["total_vulnerabilidades"]

    print("\n" + "=" * 60)
    print(f"  RELATÓRIO DE SEGURANÇA — Projeto: {relatorio['projeto_id']}")
    print("=" * 60)
    print(f"  Total de vulnerabilidades confirmadas: {total}")
    print("=" * 60)

    if total == 0:
        print("\n  Nenhuma vulnerabilidade confirmada. Bom trabalho!")
        return

    for vuln in relatorio["vulnerabilidades"]:
        icone = ICONE_SEVERIDADE.get(vuln["severidade"], "❓")
        print(f"\n[#{vuln['prioridade']}] {icone} {vuln['severidade'].upper()} — {vuln['tipo'].upper()}")
        print(f"  Localização : {vuln['localizacao']['arquivo']}", end="")
        if vuln["localizacao"]["linha"]:
            print(f", linha {vuln['localizacao']['linha']}")
        else:
            print()
        print(f"  Referência  : {vuln['referencia_cwe_cve']}")
        print(f"  Problema    : {vuln['explicacao']}")
        print(f"  Trecho      :\n    {vuln['trecho_codigo']}")
        print(f"  Correção    :\n    {vuln['sugestao_correcao']}")

    print("\n" + "=" * 60)


# ---------------------------------------------------------------------------
# Orquestração principal
# ---------------------------------------------------------------------------

def orquestrar(projeto_id: str, caminhos_arquivos: list[str]) -> dict:
    """
    Executa o pipeline de análise via grafo LangGraph.

    Args:
        projeto_id: Identificador único da análise.
        caminhos_arquivos: Lista de caminhos dos arquivos Python a analisar.

    Returns:
        Estado final do pipeline (inclui relatório).
    """
    verificar_conexao()
    print(f"\n[Agente 0] Iniciando análise do projeto '{projeto_id}'...")

    arquivos = coletar_arquivos(caminhos_arquivos)
    if not arquivos:
        print("[Agente 0] Nenhum arquivo válido encontrado. Encerrando.")
        return {}

    contexto = coletar_contexto()

    estado_inicial: EstadoPipeline = {
        "projeto_id": projeto_id,
        "arquivos":   arquivos,
        "contexto":   contexto,
    }

    estado_final = _pipeline.invoke(estado_inicial)

    if "relatorio" in estado_final:
        exibir_relatorio(estado_final["relatorio"])

    return estado_final


# ---------------------------------------------------------------------------
# Entrada via CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python agente0.py <projeto_id> <arquivo1.py> [arquivo2.py ...]")
        print("Exemplo: python agente0.py analise-001 src/app.py")
        sys.exit(1)

    projeto_id = sys.argv[1]
    arquivos   = sys.argv[2:]

    orquestrar(projeto_id, arquivos)
