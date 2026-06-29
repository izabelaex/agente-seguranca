"""
Agente 0 — Orquestrador
Responsável: Izabela

Ponto de entrada do sistema. Responsável por:
  1. Coletar arquivos Python a analisar
  2. Coletar contexto do sistema via diálogo com o desenvolvedor
  3. Delegar análise aos agentes especialistas (SCA, SAST)
  4. Encaminhar achados ao Avaliador de Severidade
  5. Solicitar geração do relatório final
  6. Apresentar o relatório ao desenvolvedor
"""

import json
import sys
import os

# Garante que o projeto raiz está no path para imports funcionarem
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from contratos.schemas import EntradaSistema, Arquivo, ContextoProjeto, EntradaAvaliador
from agentes.sca.agente1 import analisar_dependencias
from agentes.sast.agente2 import analisar_codigo
from agentes.severidade.agente3 import avaliar_severidade
from agentes.relatorio.agente4 import gerar_relatorio
from orquestrador.llm_client import verificar_conexao


# ---------------------------------------------------------------------------
# Coleta de entrada
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
# Exibição do relatório
# ---------------------------------------------------------------------------

ICONE_SEVERIDADE = {
    "critica": "🔴",
    "alta": "🟠",
    "media": "🟡",
    "baixa": "🟢",
    "informativo": "⚪",
}


def exibir_relatorio(saida_relatorio: dict) -> None:
    """Exibe o relatório final de forma legível no terminal."""
    relatorio = saida_relatorio["relatorio"]
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
    Executa o pipeline completo de análise de segurança.

    Args:
        projeto_id: Identificador único da análise.
        caminhos_arquivos: Lista de caminhos dos arquivos Python a analisar.

    Returns:
        Relatório final como dicionário.
    """
    verificar_conexao()
    print(f"\n[Agente 0] Iniciando análise do projeto '{projeto_id}'...")

    # 1. Montar entrada
    arquivos = coletar_arquivos(caminhos_arquivos)
    if not arquivos:
        print("[Agente 0] Nenhum arquivo válido encontrado. Encerrando.")
        return {}

    contexto = coletar_contexto()

    entrada: EntradaSistema = {
        "projeto_id": projeto_id,
        "arquivos": arquivos,
        "contexto": contexto,
    }

    print(f"\n[Agente 0] {len(arquivos)} arquivo(s) carregado(s). Delegando análise...")

    # 2. Delegar aos especialistas (independentes entre si)
    saida_sca = analisar_dependencias(entrada)
    saida_sast = analisar_codigo(entrada)

    # 3. Encaminhar ao Avaliador de Severidade
    entrada_avaliador: EntradaAvaliador = {
        "projeto_id": projeto_id,
        "achados_sca": saida_sca["achados_sca"],
        "achados_sast": saida_sast["achados_sast"],
        "contexto": contexto,
    }
    saida_avaliador = avaliar_severidade(entrada_avaliador)

    # 4. Gerar relatório final
    saida_relatorio = gerar_relatorio(saida_avaliador)

    # 5. Apresentar ao desenvolvedor
    exibir_relatorio(saida_relatorio)

    return saida_relatorio


# ---------------------------------------------------------------------------
# Ponto de entrada via CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python agente0.py <projeto_id> <arquivo1.py> [arquivo2.py ...]")
        print("Exemplo: python agente0.py analise-001 src/app.py")
        sys.exit(1)

    projeto_id = sys.argv[1]
    arquivos = sys.argv[2:]

    resultado = orquestrar(projeto_id, arquivos)
