"""
Camada de abstração para chamadas ao LLM.

Implementa OllamaAuth, uma subclasse de BaseChatModel do LangChain,
que faz chamadas ao servidor Ollama com autenticação via header X-API-Key.
(ChatOllama não suporta headers customizados — por isso a subclasse própria.)

Compatível com LCEL (operador |), ChatPromptTemplate, JsonOutputParser
e rastreamento automático via LangSmith sem precisar de @traceable manual.

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
import requests
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, AIMessage, SystemMessage
from langchain_core.outputs import ChatResult, ChatGeneration

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

    if os.getenv("LANGCHAIN_TRACING_V2") == "true":
        projeto = os.getenv("LANGCHAIN_PROJECT", "default")
        print(f"  LangSmith: ativo (projeto: {projeto})")
    else:
        print("  LangSmith: inativo (defina LANGCHAIN_TRACING_V2=true para ativar)")
    print()


# ---------------------------------------------------------------------------
# Subclasse BaseChatModel com autenticação customizada
# ---------------------------------------------------------------------------

class OllamaAuth(BaseChatModel):
    """
    Implementação de BaseChatModel que autentica via X-API-Key no Ollama.

    Uso com LCEL:
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import JsonOutputParser
        from orquestrador.llm_client import llm

        chain = ChatPromptTemplate.from_messages([
            ("system", "Você é um especialista..."),
            ("human", "{input}"),
        ]) | llm | JsonOutputParser()

        resultado = chain.invoke({"input": "analise este trecho..."})
    """

    model: str = MODELO_PADRAO
    base_url: str = BASE_URL
    # Baixa de propósito: os agentes usam o LLM para classificação de segurança
    # (confirmado/descartado, severidade), não para geração criativa de texto. Testes
    # mostraram a mesma entrada produzindo severidades diferentes entre execuções
    # (ex.: "critica" vs "alta") com a temperatura padrão do Ollama (~0.8) — baixar para
    # perto de zero reduz essa variância sem custo de chamadas extras ao LLM.
    temperature: float = 0.1

    @property
    def _llm_type(self) -> str:
        return "ollama-custom-auth"

    @property
    def _identifying_params(self) -> dict:
        return {"model": self.model, "base_url": self.base_url, "temperature": self.temperature}

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager=None,
        **kwargs,
    ) -> ChatResult:
        msgs = []
        for m in messages:
            role = (
                "system" if isinstance(m, SystemMessage) else
                "assistant" if isinstance(m, AIMessage) else
                "user"
            )
            msgs.append({"role": role, "content": m.content})

        payload = {
            "model": self.model,
            "messages": msgs,
            "stream": False,
            "options": {"temperature": self.temperature},
        }

        try:
            r = requests.post(
                f"{self.base_url}/api/chat",
                headers=_get_headers(),
                json=payload,
                timeout=120,
            )
            r.raise_for_status()
        except requests.exceptions.Timeout:
            raise RuntimeError(f"Timeout ao chamar o modelo '{self.model}'.")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Erro na chamada ao LLM: {e}")

        data = r.json()
        if "error" in data:
            raise RuntimeError(f"Ollama retornou erro: {data['error']}")

        content = data["message"]["content"]
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=content))])


# Instância padrão — importada pelos agentes
llm = OllamaAuth()
