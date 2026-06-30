"""
Camada de abstração para chamadas ao LLM.

Usa LangChain (ChatOllama) com o servidor Ollama da disciplina
e rastreamento automático via LangSmith.

Variáveis de ambiente necessárias:

  Obrigatória:
    LLM_API_KEY          Chave individual fornecida pelo professor

  LangSmith (opcional, mas recomendado para análise e artigo):
    LANGCHAIN_TRACING_V2    true
    LANGCHAIN_API_KEY       chave do LangSmith (https://smith.langchain.com)
    LANGCHAIN_PROJECT       nome do projeto no LangSmith (ex: agente-seguranca)

Modelos disponíveis no servidor:
    ticlazau/meta-llama-3.1-8b-instruct:latest  — padrão (balanceado)
    llama3.2:3b                                  — mais rápido para testes
    deepseek-r1:8b                               — melhor raciocínio
    deepseek-coder:latest                        — otimizado para código
    qwen2.5:7b
    mixtral:8x7b                                 — mais capaz, mais lento
"""

import os
import json
import requests
from langsmith import traceable

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

BASE_URL = "https://ollama.futurelab.dcc.ufmg.br"
MODELO_PADRAO = "ticlazau/meta-llama-3.1-8b-instruct:latest"


def _get_headers() -> dict:
    api_key = os.getenv("LLM_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "Variável de ambiente LLM_API_KEY não definida.\n"
            "Configure com: export LLM_API_KEY='sua-chave-individual'\n"
            "Ou defina em um arquivo .env na raiz do projeto."
        )
    return {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }


# ---------------------------------------------------------------------------
# Verificação de conexão
# ---------------------------------------------------------------------------

def verificar_conexao() -> None:
    """
    Verifica se o servidor e a API key estão funcionando.
    Chame antes de rodar o pipeline completo.
    """
    print("Verificando conexão com o servidor Ollama...", end=" ", flush=True)
    try:
        r = requests.get(
            f"{BASE_URL}/api/tags",
            headers=_get_headers(),
            timeout=10,
        )
    except requests.exceptions.ConnectionError:
        raise SystemExit(f"\n[ERRO] Não foi possível conectar ao servidor: {BASE_URL}")
    except requests.exceptions.Timeout:
        raise SystemExit("\n[ERRO] Timeout ao conectar ao servidor.")

    if r.status_code == 401:
        raise SystemExit("\n[ERRO 401] API key ausente ou inválida.")
    if r.status_code == 403:
        raise SystemExit(f"\n[ERRO 403] API key rejeitada: {r.json().get('detail', {})}")
    if r.status_code != 200:
        raise SystemExit(f"\n[ERRO {r.status_code}] Resposta inesperada: {r.text[:200]}")

    modelos = [m["name"] for m in r.json().get("models", [])]
    print("✓")
    print(f"  Servidor : {BASE_URL}")
    print(f"  Modelos  : {', '.join(modelos)}")

    # Informa se LangSmith está ativo
    if os.getenv("LANGCHAIN_TRACING_V2") == "true":
        projeto = os.getenv("LANGCHAIN_PROJECT", "default")
        print(f"  LangSmith: ativo (projeto: {projeto})")
    else:
        print("  LangSmith: inativo (defina LANGCHAIN_TRACING_V2=true para ativar)")
    print()


# ---------------------------------------------------------------------------
# Função principal de chamada ao LLM
# ---------------------------------------------------------------------------

@traceable(name="chamar_llm")
def chamar_llm(prompt: str, system: str = "", modelo: str = MODELO_PADRAO) -> str:
    """
    Envia um prompt ao servidor Ollama e retorna a resposta como string.
    Rastreada automaticamente pelo LangSmith via @traceable.

    Args:
        prompt: Mensagem do usuário/agente.
        system: Instrução de sistema (papel do agente, contexto fixo).
        modelo: Modelo a usar. Padrão: ticlazau/meta-llama-3.1-8b-instruct:latest

    Returns:
        Resposta do LLM como string.
    """
    mensagens = []
    if system:
        mensagens.append({"role": "system", "content": system})
    mensagens.append({"role": "user", "content": prompt})

    payload = {
        "model": modelo,
        "messages": mensagens,
        "stream": False,
    }

    try:
        r = requests.post(
            f"{BASE_URL}/api/chat",
            headers=_get_headers(),
            json=payload,
            timeout=120,
        )
        r.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Timeout ao chamar o modelo '{modelo}'.")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Erro na chamada ao LLM: {e}")

    data = r.json()
    if "error" in data:
        raise RuntimeError(f"Ollama retornou erro: {data['error']}")

    return data["message"]["content"]
