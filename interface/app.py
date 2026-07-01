"""
Interface Streamlit — Sistema Multiagente de Segurança
Executa o pipeline LangGraph e exibe o relatório de vulnerabilidades.
"""

import sys
import os
import io
import threading
import traceback

import streamlit as st

# Garante que o projeto raiz está no path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orquestrador.agente0 import _pipeline
from orquestrador.llm_client import verificar_conexao
from contratos.schemas import EstadoPipeline

# ---------------------------------------------------------------------------
# Configuração da página
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Analisador de Segurança",
    page_icon="🔒",
    layout="wide",
)

st.title("🔒 Analisador de Segurança de Código Python")
st.caption("Sistema multiagente para detecção de vulnerabilidades — SCA · SAST · Severidade · Relatório")

# ---------------------------------------------------------------------------
# Sidebar — entrada do usuário
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("📁 Arquivo")
    arquivo = st.file_uploader(
        "Selecione um arquivo .py para analisar",
        type=["py"],
        help="O arquivo será analisado em busca de SQLi, XSS, segredos expostos e dependências vulneráveis.",
    )

    st.divider()
    st.header("⚙️ Contexto do projeto")

    exposto = st.radio(
        "A aplicação está exposta à internet?",
        ["Sim", "Não"],
        horizontal=True,
    ) == "Sim"

    tipo = st.text_input(
        "Tipo de aplicação",
        placeholder="ex: API REST, web app, script interno",
    )

    validacoes = st.text_area(
        "Validações de entrada existentes",
        value="nenhuma",
        placeholder="Descreva ou escreva 'nenhuma'",
        height=80,
    )

    st.divider()
    analisar = st.button(
        "🔍 Analisar",
        type="primary",
        disabled=arquivo is None,
        use_container_width=True,
    )

    if arquivo is None:
        st.info("Faça upload de um arquivo .py para começar.")

# ---------------------------------------------------------------------------
# Captura de stdout para log em tempo real
# ---------------------------------------------------------------------------

class _LogCapture(io.StringIO):
    """Coleta prints dos agentes de forma thread-safe e exibe no placeholder."""

    def __init__(self, placeholder):
        super().__init__()
        self._placeholder = placeholder
        self._lines = []
        self._lock = threading.Lock()

    def write(self, text):
        if text and text.strip():
            with self._lock:
                self._lines.append(text.strip())
                snapshot = list(self._lines[-30:])
            try:
                self._placeholder.code("\n".join(snapshot), language=None)
            except Exception:
                pass  # thread sem contexto Streamlit — ignora, exibe depois
        return len(text)

    def flush(self):
        pass

    def get_all(self) -> str:
        with self._lock:
            return "\n".join(self._lines)


# ---------------------------------------------------------------------------
# Constantes de exibição
# ---------------------------------------------------------------------------

_ICONE = {
    "critica":     "🔴",
    "alta":        "🟠",
    "media":       "🟡",
    "baixa":       "🟢",
    "informativo": "⚪",
}

_COR_BORDA = {
    "critica":     "#ef4444",
    "alta":        "#f97316",
    "media":       "#eab308",
    "baixa":       "#22c55e",
    "informativo": "#94a3b8",
}


# ---------------------------------------------------------------------------
# Execução do pipeline
# ---------------------------------------------------------------------------

if analisar and arquivo is not None:
    conteudo = arquivo.read().decode("utf-8")

    estado_inicial: EstadoPipeline = {
        "projeto_id": arquivo.name.replace(".py", ""),
        "arquivos": [{"caminho": arquivo.name, "conteudo": conteudo}],
        "contexto": {
            "exposto_internet": exposto,
            "tipo_aplicacao": tipo or "não informado",
            "validacoes_existentes": validacoes or "nenhuma",
        },
    }

    col_log, col_relatorio = st.columns([1, 1], gap="large")

    with col_log:
        st.subheader("⚡ Progresso")
        log_placeholder = st.empty()
        logger = _LogCapture(log_placeholder)

    # Redireciona stdout e roda o pipeline
    old_stdout = sys.stdout
    sys.stdout = logger

    estado_final = {}
    erro = None
    erro_traceback = ""

    try:
        with st.spinner("Analisando... (pode levar 1–3 minutos)"):
            estado_final = _pipeline.invoke(estado_inicial)
    except Exception as e:
        erro = e
        erro_traceback = traceback.format_exc()
    finally:
        sys.stdout = old_stdout
        # Garante que os logs coletados em threads aparecem no placeholder
        log_placeholder.code(logger.get_all() or "(sem logs)", language=None)

    # ---------------------------------------------------------------------------
    # Exibição do relatório
    # ---------------------------------------------------------------------------

    with col_relatorio:
        st.subheader("📋 Relatório")

        if erro:
            st.error(f"Erro durante a análise: {erro}")
            with st.expander("Detalhes do erro"):
                st.code(erro_traceback, language="python")

        elif "relatorio" not in estado_final:
            st.warning("O pipeline não gerou um relatório. Verifique os logs.")

        else:
            relatorio = estado_final["relatorio"]
            total = relatorio["total_vulnerabilidades"]

            if total == 0:
                st.success("✅ Nenhuma vulnerabilidade encontrada!")
            else:
                st.markdown(f"**{total} vulnerabilidade(s) confirmada(s)** no arquivo `{arquivo.name}`")
                st.divider()

                for vuln in relatorio["vulnerabilidades"]:
                    sev = vuln["severidade"]
                    icone = _ICONE.get(sev, "❓")
                    cor = _COR_BORDA.get(sev, "#94a3b8")
                    linha = vuln["localizacao"].get("linha")
                    loc = f"`{vuln['localizacao']['arquivo']}`"
                    if linha:
                        loc += f", linha **{linha}**"

                    with st.expander(
                        f"{icone} #{vuln['prioridade']} — {vuln['tipo'].upper()} · {sev.upper()}",
                        expanded=True,
                    ):
                        st.markdown(f"**Localização:** {loc}")
                        st.markdown(f"**Referência:** `{vuln['referencia_cwe_cve']}`")
                        st.markdown(f"**Problema:**")
                        st.info(vuln["explicacao"])
                        st.markdown(f"**Correção sugerida:**")
                        st.success(vuln["sugestao_correcao"])
