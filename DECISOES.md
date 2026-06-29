# Decisões do Projeto — Sistema Multiagente de Segurança

## Fase 0 — Decisões base (definidas por Izabela)

| Decisão | Escolha | Justificativa |
|---------|---------|---------------|
| Linguagem analisada no MVP | Python | Escopo controlado para o MVP |
| Tipo de entrada | Arquivos avulsos | Mais simples de implementar e testar |
| Stack de orquestração | Python puro + LLM via API | Menos dependências, mais fácil de debugar; migração para LangChain possível depois isolando a camada em `llm_client.py` |
| Serialização entre agentes | JSON | Fácil de versionar, validar e debugar |

## Pontos ainda a confirmar com o grupo

- [ ] Qual LLM/API será usada (OpenAI, Anthropic, outra)?
- [ ] Critério prático de severidade (CWSS/CVSS citados, mas sem fórmula definida)
- [ ] Métricas de avaliação formais
- [ ] Prazo do projeto
