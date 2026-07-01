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

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orquestrador.agente0 import _pipeline
from orquestrador.llm_client import verificar_conexao
from contratos.schemas import EstadoPipeline

# ---------------------------------------------------------------------------
# Configuração da página
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Análise de Segurança por Agentes",
    layout="wide",
)

# ---------------------------------------------------------------------------
# CSS + Google Font
# ---------------------------------------------------------------------------

st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">

<style>
/* ─── Base — sem !important global para não quebrar Material Icons ───────── */
html, body { font-family: 'Inter', sans-serif; }
p, h1, h2, h3, h4, h5, h6, input, textarea, a, label, li, td, th {
    font-family: 'Inter', sans-serif;
}

[data-testid="stAppViewContainer"] { background: #f8fafc; }
[data-testid="stMain"] { background: transparent; }
.main .block-container { padding-top: 2rem; max-width: 900px; }

/* ─── Sidebar — mais estreita ────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    min-width: 230px !important;
    max-width: 230px !important;
    background: linear-gradient(180deg, #0f172a 0%, #1a2744 100%) !important;
    border-right: 1px solid rgba(255,255,255,0.06) !important;
}
[data-testid="stSidebar"] > div:first-child {
    min-width: 230px !important;
    max-width: 230px !important;
}

[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] div  { color: #94a3b8; }
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] strong { color: #f1f5f9 !important; }
[data-testid="stSidebar"] hr {
    border-color: rgba(255,255,255,0.07) !important;
    margin: 12px 0 !important;
}

/* Labels da sidebar */
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] [data-testid="stWidgetLabel"],
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p {
    color: #475569 !important;
    font-size: 0.6rem !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
}
[data-testid="stSidebar"] .stRadio label {
    color: #cbd5e1 !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    text-transform: none !important;
    letter-spacing: 0 !important;
}

/* Inputs da sidebar — fundo branco, texto preto */
[data-testid="stSidebar"] input,
[data-testid="stSidebar"] textarea {
    background-color: #ffffff !important;
    color: #000000 !important;
    border: 1px solid rgba(255,255,255,0.18) !important;
    border-radius: 7px !important;
}
[data-testid="stSidebar"] input::placeholder,
[data-testid="stSidebar"] textarea::placeholder {
    color: #9ca3af !important;
    font-size: 0.73rem !important;
}
[data-testid="stSidebar"] [data-testid="InputInstructions"] {
    font-size: 0.56rem !important;
    color: #334155 !important;
}

/* File uploader */
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {
    background: rgba(255,255,255,0.03) !important;
    border: 1.5px dashed rgba(255,255,255,0.14) !important;
    border-radius: 8px !important;
}
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"]:hover {
    background: rgba(99,102,241,0.08) !important;
    border-color: #6366f1 !important;
}
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] p,
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] span,
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] small {
    color: #475569 !important;
    font-size: 0.7rem !important;
}

/* Botão Analisar */
[data-testid="stSidebar"] .stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #6366f1 0%, #3b82f6 100%) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
    font-size: 0.82rem !important;
    box-shadow: 0 4px 14px rgba(99,102,241,0.35) !important;
}
[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover {
    box-shadow: 0 6px 20px rgba(99,102,241,0.5) !important;
    transform: translateY(-1px) !important;
}
[data-testid="stSidebar"] .stButton > button[kind="primary"]:disabled {
    background: rgba(99,102,241,0.22) !important;
    box-shadow: none !important;
    transform: none !important;
}

/* ─── Main typography ────────────────────────────────────────────────────── */
h2 { font-size: 1.4rem !important; font-weight: 800 !important; color: #0f172a !important; }

/* ─── Terminal dentro do expander de progresso ───────────────────────────── */
[data-testid="stExpander"] [data-testid="stCode"] > div,
[data-testid="stExpander"] [data-testid="stCode"] pre {
    background: #0d1117 !important;
    border: 1px solid #21262d !important;
    border-radius: 8px !important;
}
[data-testid="stExpander"] [data-testid="stCode"] code,
[data-testid="stExpander"] [data-testid="stCode"] pre {
    color: #58a6ff !important;
    font-size: 0.72rem !important;
    line-height: 1.75 !important;
    font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
}

/* ─── Vuln cards ─────────────────────────────────────────────────────────── */
.vuln-card {
    background: #ffffff;
    border-radius: 12px;
    border: 1px solid #e2e8f0;
    border-left: 4px solid #e2e8f0;
    padding: 16px 18px;
    margin-bottom: 10px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.03);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}
.vuln-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 16px rgba(0,0,0,0.1);
}
.vuln-card.critica     { border-left-color: #ef4444; }
.vuln-card.alta        { border-left-color: #f97316; }
.vuln-card.media       { border-left-color: #eab308; }
.vuln-card.baixa       { border-left-color: #22c55e; }
.vuln-card.informativo { border-left-color: #94a3b8; }

.vuln-title { font-weight: 700; font-size: 0.875rem; color: #0f172a; letter-spacing: -0.01em; }
.vuln-meta  { font-size: 0.75rem; color: #94a3b8; margin-top: 6px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.vuln-meta code {
    background: #f8fafc; border: 1px solid #e2e8f0;
    padding: 1px 7px; border-radius: 5px;
    font-size: 0.7rem; color: #475569;
    font-family: 'JetBrains Mono', monospace;
}

/* ─── Severity badges ────────────────────────────────────────────────────── */
.badge { display: inline-block; padding: 3px 11px; border-radius: 999px; font-size: 0.63rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; }
.badge.critica     { background: #fee2e2; color: #991b1b; }
.badge.alta        { background: #ffedd5; color: #9a3412; }
.badge.media       { background: #fefce8; color: #854d0e; }
.badge.baixa       { background: #dcfce7; color: #166534; }
.badge.informativo { background: #f1f5f9; color: #475569; }

/* ─── Summary chips ──────────────────────────────────────────────────────── */
.resumo { display: flex; gap: 8px; margin-bottom: 18px; flex-wrap: wrap; }
.resumo-item { display: flex; align-items: center; gap: 8px; padding: 8px 16px; border-radius: 10px; font-size: 0.78rem; font-weight: 600; }
.resumo-item span { font-size: 1.5rem; font-weight: 800; line-height: 1; }
.resumo-item.critica      { background: #fef2f2; color: #991b1b; }
.resumo-item.critica span { color: #ef4444; }
.resumo-item.alta         { background: #fff7ed; color: #9a3412; }
.resumo-item.alta span    { color: #f97316; }
.resumo-item.media        { background: #fefce8; color: #854d0e; }
.resumo-item.media span   { color: #eab308; }
.resumo-item.baixa        { background: #f0fdf4; color: #166534; }
.resumo-item.baixa span   { color: #22c55e; }

/* ─── Empty state ────────────────────────────────────────────────────────── */
.empty-state { text-align: center; padding: 52px 24px; }
.empty-state svg { margin: 0 auto 14px; display: block; opacity: 0.25; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar — entrada do usuário
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("""
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;padding:4px 0 12px;">
      <div style="background:linear-gradient(135deg,#6366f1,#3b82f6);border-radius:9px;width:34px;height:34px;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="white">
          <path d="M12 1L3 5v6c0 5.25 3.75 10.15 9 11.25C17.25 21.15 21 16.25 21 11V5L12 1z"/>
        </svg>
      </div>
      <div>
        <div style="color:#f1f5f9;font-weight:800;font-size:0.96rem;letter-spacing:-0.01em;">Análise de Segurança por Agentes</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    st.markdown("<span style='color:#475569;font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;'>Arquivo</span>", unsafe_allow_html=True)
    arquivos = st.file_uploader(
        "Arquivos .py",
        type=["py", "txt"],
        help="Selecione um ou mais arquivos Python (.py) ou texto (.txt) para analisar.",
        accept_multiple_files=True,
        label_visibility="collapsed",
    )

    st.divider()

    st.markdown("<span style='color:#475569;font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;'>Contexto</span>", unsafe_allow_html=True)

    exposto = st.radio(
        "Exposição",
        ["Sim — exposto", "Não — interno"],
        horizontal=True,
        label_visibility="collapsed",
    ) == "Sim — exposto"

    tipo = st.text_input(
        "Tipo de aplicação",
        placeholder="API REST, web app...",
    )

    validacoes = st.text_area(
        "Validações existentes",
        value="nenhuma",
        placeholder="Descreva ou 'nenhuma'",
        height=68,
    )

    st.divider()

    analisar = st.button(
        "Analisar",
        type="primary",
        disabled=not arquivos,
        use_container_width=True,
    )

    if not arquivos:
        st.markdown("<p style='font-size:0.68rem;text-align:center;color:#334155;margin-top:4px;'>Envie um .py para começar</p>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Cabeçalho principal
# ---------------------------------------------------------------------------

st.markdown("""
<div style="margin-bottom:28px;">
  <h2 style="margin:0 0 4px;">Analisador de Segurança de Código</h2>
  <p style="margin:0;color:#94a3b8;font-size:0.8rem;">
    Detecção automatizada via SAST &amp; SCA com verificação por Agentes     
  </p>
  <div style="display:flex;gap:6px;margin-top:10px;flex-wrap:wrap;">
    <span style="background:#f1f5f9;color:#475569;font-size:0.6rem;font-weight:700;padding:3px 9px;border-radius:99px;letter-spacing:0.06em;text-transform:uppercase;">SCA</span>
    <span style="background:#f1f5f9;color:#475569;font-size:0.6rem;font-weight:700;padding:3px 9px;border-radius:99px;letter-spacing:0.06em;text-transform:uppercase;">SAST</span>
    <span style="background:#f1f5f9;color:#475569;font-size:0.6rem;font-weight:700;padding:3px 9px;border-radius:99px;letter-spacing:0.06em;text-transform:uppercase;">CVE</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Captura de stdout para log em tempo real (lógica original intacta)
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
                pass
        return len(text)

    def flush(self):
        pass

    def get_all(self) -> str:
        with self._lock:
            return "\n".join(self._lines)

# ---------------------------------------------------------------------------
# Mapeamento de severidade
# ---------------------------------------------------------------------------

_LABEL_SEV = {
    "critica":     "Crítica",
    "alta":        "Alta",
    "media":       "Média",
    "baixa":       "Baixa",
    "informativo": "Informativo",
}

# ---------------------------------------------------------------------------
# Execução do pipeline (lógica original intacta)
# ---------------------------------------------------------------------------

if analisar and arquivos:
    arquivos_dados = [
        {"caminho": f.name, "conteudo": f.read().decode("utf-8")}
        for f in arquivos
    ]
    projeto_id = (
        arquivos[0].name.replace(".py", "")
        if len(arquivos) == 1
        else f"analise-{len(arquivos)}-arquivos"
    )

    estado_inicial: EstadoPipeline = {
        "projeto_id": projeto_id,
        "arquivos": arquivos_dados,
        "contexto": {
            "exposto_internet": exposto,
            "tipo_aplicacao": tipo or "não informado",
            "validacoes_existentes": validacoes or "nenhuma",
        },
    }

    # ── Expander de progresso (colapsável) ──────────────────────────────────
    with st.expander("Progresso da análise", expanded=True):
        log_placeholder = st.empty()
        logger = _LogCapture(log_placeholder)

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
        log_placeholder.code(logger.get_all() or "(sem logs)", language=None)

    # ── Relatório ────────────────────────────────────────────────────────────
    st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
    st.markdown("""
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px;
                padding-bottom:10px;border-bottom:1px solid #e2e8f0;">
      <div style="width:8px;height:8px;border-radius:50%;background:#22c55e;"></div>
      <span style="font-size:0.85rem;font-weight:700;color:#374151;">Relatório de vulnerabilidades</span>
    </div>
    """, unsafe_allow_html=True)

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
            st.success("Nenhuma vulnerabilidade encontrada.")
        else:
            contagem = {}
            for v in relatorio["vulnerabilidades"]:
                contagem[v["severidade"]] = contagem.get(v["severidade"], 0) + 1

            resumo_html = '<div class="resumo">'
            for sev in ["critica", "alta", "media", "baixa"]:
                if sev in contagem:
                    resumo_html += (
                        f'<div class="resumo-item {sev}">'
                        f'<span>{contagem[sev]}</span>'
                        f'{_LABEL_SEV[sev]}'
                        f'</div>'
                    )
            resumo_html += "</div>"
            st.markdown(resumo_html, unsafe_allow_html=True)

            nomes = ", ".join(f.name for f in arquivos)
            st.markdown(
                f"<p style='font-size:0.78rem;color:#64748b;margin-bottom:18px;'>"
                f"<strong style='color:#0f172a;'>{total}</strong> vulnerabilidade(s) em "
                f"<code style='background:#f8fafc;border:1px solid #e2e8f0;padding:1px 7px;"
                f"border-radius:5px;font-size:0.7rem;color:#475569;'>{nomes}</code>"
                f"</p>",
                unsafe_allow_html=True,
            )

            for vuln in relatorio["vulnerabilidades"]:
                sev = vuln["severidade"]
                label = _LABEL_SEV.get(sev, sev)
                linha = vuln["localizacao"].get("linha")
                loc = vuln["localizacao"]["arquivo"]
                if linha:
                    loc += f":{linha}"

                st.markdown(f"""
<div class="vuln-card {sev}">
  <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
    <span class="vuln-title">#{vuln['prioridade']} — {vuln['tipo'].upper()}</span>
    <span class="badge {sev}">{label}</span>
  </div>
  <div class="vuln-meta">
    <code>{loc}</code>
    <span style="color:#cbd5e1;">·</span>
    <code>{vuln['referencia_cwe_cve']}</code>
  </div>
</div>
""", unsafe_allow_html=True)

                with st.expander(f"Detalhes — #{vuln['prioridade']} {vuln['tipo'].upper()}"):
                    st.markdown("**Problema identificado**")
                    st.info(vuln["explicacao"])
                    st.markdown("**Correção sugerida**")
                    st.success(vuln["sugestao_correcao"])

# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------

else:
    st.markdown("""
    <div class="empty-state">
      <svg width="54" height="54" viewBox="0 0 24 24" fill="none" stroke="#94a3b8"
           stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 1L3 5v6c0 5.25 3.75 10.15 9 11.25C17.25 21.15 21 16.25 21 11V5L12 1z"/>
      </svg>
      <p style="font-size:0.95rem;font-weight:700;color:#64748b;margin-bottom:4px;">Nenhuma análise iniciada</p>
      <p style="font-size:0.78rem;color:#94a3b8;">Envie um arquivo .py e clique em Analisar</p>
    </div>
    """, unsafe_allow_html=True)
