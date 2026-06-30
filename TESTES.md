# Guia de Testes — Sistema Multiagente de Segurança

Siga este guia para testar o pipeline e reportar resultados ao grupo.

---

## Fase 1 — Setup e primeiro teste

### 1.1 Clone e instale

```bash
git clone https://github.com/izabelaex/agente-seguranca.git
cd agente-seguranca
pip install -r requirements.txt
```

### 1.2 Configure sua API key

Cada pessoa usa a chave individual fornecida pelo professor.

**Linux / macOS:**
```bash
export LLM_API_KEY="sua-chave-aqui"
```

**Windows (PowerShell):**
```powershell
$env:LLM_API_KEY = "sua-chave-aqui"
```

> A chave não deve ser colocada no código nem commitada no repositório.

### 1.3 Rode o teste com o arquivo de exemplo

O repositório já inclui um arquivo Python com vulnerabilidades intencionais:

```bash
python orquestrador/agente0.py analise-001 exemplos_codigo/app_vulneravel.py
```

O sistema vai pedir 3 informações sobre o projeto analisado:
- A aplicação está exposta à internet? → `s`
- Tipo de aplicação → `API REST`
- Validações existentes → `nenhuma`

---

## Fase 1 — O que verificar

Anote o resultado de cada ponto abaixo e reporte no grupo.

### Agente 1 (SCA)
- [ ] Detectou as dependências vulneráveis do `requirements.txt`?
- [ ] Consultou a OSV.dev e retornou CVEs reais?
- [ ] Se não há internet disponível, exibiu aviso claro em vez de travar?

### Agente 2 (SAST)
- [ ] Detectou o SQL Injection em `app_vulneravel.py`?
- [ ] Detectou o segredo exposto (`DB_PASSWORD`)?
- [ ] O LLM confirmou ou descartou os achados? A decisão faz sentido?

### Agente 3 (Severidade)
- [ ] Recebeu os achados dos dois agentes anteriores?
- [ ] A severidade atribuída faz sentido dado o contexto ("exposto à internet", "sem validações")?
- [ ] A justificativa gerada pelo LLM é legível e coerente?

### Agente 4 (Relatório)
- [ ] O relatório foi gerado com as vulnerabilidades ordenadas por severidade?
- [ ] As sugestões de correção são práticas e específicas para Python?
- [ ] O relatório final é legível e útil para um desenvolvedor?

---

## Fase 1 — Teste com código próprio

Crie um arquivo `.py` com vulnerabilidades do seu próprio código (ou invente um) e rode:

```bash
python orquestrador/agente0.py teste-proprio seu_arquivo.py
```

Isso ajuda a validar se o sistema funciona além do exemplo controlado.

---

## Fase 2 — Reportar e ajustar

### Como reportar problemas

Abra uma **Issue** no GitHub com:
- Qual agente falhou (0, 1, 2, 3 ou 4)
- O que era esperado vs. o que aconteceu
- O trecho de output relevante (copie do terminal)

Exemplo de título: `[Agente 2] Falso positivo em variável 'token' sem valor literal`

### Problemas comuns e soluções

| Problema | Causa provável | O que fazer |
|---|---|---|
| `EnvironmentError: LLM_API_KEY não definida` | Variável de ambiente não configurada | Rode `export LLM_API_KEY=...` antes de executar |
| `[ERRO 403] API key rejeitada` | Chave errada ou expirada | Confirme sua chave com o professor |
| `Timeout ao chamar o modelo` | Modelo sobrecarregado | Tente `llama3.2:3b` (mais rápido) — edite `MODELO_PADRAO` em `llm_client.py` |
| `JSONDecodeError` na resposta do LLM | LLM retornou texto fora do formato JSON esperado | Anote o output e abra uma issue — é um ajuste de prompt |
| OSV.dev não retorna nada | Sem acesso à internet ou pacote não encontrado na base | Verifique conexão; pacotes muito novos podem não estar na base ainda |
| Agente 2 não detectou vulnerabilidade óbvia | Regex não cobriu o padrão | Anote o trecho de código e abra uma issue |

### Mudança de modelo (se necessário)

Se o modelo padrão (`llama3.1:8b`) estiver lento ou com respostas ruins, edite a linha em `orquestrador/llm_client.py`:

```python
MODELO_PADRAO = "ticlazau/meta-llama-3.1-8b-instruct:latest"   # mais rápido
# ou
MODELO_PADRAO = "deepseek-r1:8b"  # melhor raciocínio
```

---

## Resumo do fluxo esperado

```
python agente0.py analise-001 arquivo.py
        │
        ├── Verifica conexão com Ollama ✓
        ├── Coleta contexto (3 perguntas)
        ├── [Agente 1] Extrai deps → consulta OSV.dev → lista CVEs
        ├── [Agente 2] Varre código → LLM confirma achados
        ├── [Agente 3] LLM avalia severidade com contexto
        ├── [Agente 4] LLM gera relatório final
        └── Exibe relatório no terminal
```

Tempo estimado por análise: **1 a 3 minutos** dependendo do modelo e do número de achados.
