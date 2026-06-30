"""
Camada de abstração para chamadas ao LLM.

Usa o servidor Ollama da disciplina (https://ollama.futurelab.dcc.ufmg.br)
com autenticação via cabeçalho X-API-Key.

Configuração necessária — defina as variáveis de ambiente antes de rodar:
    export LLM_API_KEY="sua-chave-individual"

Ou crie um arquivo .env na raiz do projeto:
    LLM_API_KEY=sua-chave-individual

Modelos disponíveis no servidor:
    llama3.2:3b        — rápido, bom para testes
    llama3.1:8b        — balanceado, recomendado para produção
    deepseek-r1:8b     — melhor raciocínio (mais lento)
    deepseek-coder     — otimizado para código
    qwen2.5:7b
    mixtral:8x7b       — mais capaz, mais lento
"""

import os
import json
import requests

#Config
BASE_URL = "https://ollama.futurelab.dcc.ufmg.br"

# Modelo padrão por bom equilíbrio entre velocidade e qualidade para análise de segurança
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


#Verifica coonexão
def verificar_conexao() -> None:
    """
    Verifica se o servidor e a API key estão funcionando.
    Chame antes de rodar o pipeline completo.
    """
    print("Verificando conexão com o servidor Ollama...", end=" ", flush=True)
    try:
        r = requests.get(f"{BASE_URL}/api/tags", headers=_get_headers(), timeout=10)
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
    print(f"  Modelos  : {', '.join(modelos)}\n")


#Chamada principal ao LLM
def chamar_llm(prompt: str, system: str = "", modelo: str = MODELO_PADRAO) -> str:
    """
    Envia um prompt ao servidor Ollama e retorna a resposta como string.

    Args:
        prompt: Mensagem do usuário/agente.
        system: Instrução de sistema (papel do agente, contexto fixo).
        modelo: Modelo a usar. Padrão: llama3.1:8b.

    Returns:
        Resposta do LLM como string.

    Raises:
        EnvironmentError: Se LLM_API_KEY não estiver definida.
        RuntimeError: Se a chamada à API falhar.
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
        raise RuntimeError(f"Timeout ao chamar o modelo '{modelo}'. Tente um modelo mais rápido (ex.: llama3.2:3b).")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Erro na chamada ao LLM: {e}")

    data = r.json()
    if "error" in data:
        raise RuntimeError(f"Ollama retornou erro: {data['error']}")

    return data["message"]["content"]
