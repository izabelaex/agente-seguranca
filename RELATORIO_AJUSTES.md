# Relatório de Testes e Ajustes — Pipeline Multiagente de Segurança

**Data:** 2026-06-30 a 2026-07-01
**Branch:** `teste-dataset-bandit-ajustes-prompts` (commit `a860a83`)
**Escopo:** validação técnica de funcionamento integral do pipeline (Agentes 1-4), com foco em testes com dataset público, análise de erros e ajuste de prompts/código.

---

## 1. Contexto e objetivo

O pipeline (Agente 0 orquestrador → Agente 1 SCA → Agente 2 SAST → Agente 3 Severidade → Agente 4 Relatório) nunca tinha sido testado além do arquivo de exemplo controlado (`app_vulneravel.py`, 2 achados). O objetivo desta fase foi:

1. Testar contra um dataset mais diverso, com casos "bons" e "ruins" lado a lado.
2. Analisar os erros encontrados.
3. Ajustar prompts (e, quando prompt não bastasse, código) com base nesses erros.

O critério de aceite adotado ao longo do processo: **toda correção precisa ser validada rodando o pipeline de verdade** (não só lida no código), e **revalidada em mais de uma execução** sempre que possível, já que o comportamento do LLM se mostrou não-determinístico.

---

## 2. Metodologia

### 2.1 Dataset

Criado `exemplos_codigo/dataset_bandit/`: 6 arquivos do projeto [Bandit](https://github.com/PyCQA/bandit) (ferramenta SAST de referência para Python, Apache-2.0), escolhidos por cobrirem os 3 padrões do MVP (SQLi, XSS, segredo exposto) com casos "bons" e "ruins" lado a lado — útil para achar tanto falso positivo quanto falso negativo. Gabarito documentado em `exemplos_codigo/dataset_bandit/README.md` (e corrigido ao longo do processo conforme suposições iniciais se mostraram erradas na prática).

### 2.2 Execução

- Ambiente: `.venv` local, `LLM_API_KEY` em `.env` (nunca commitado), conexão real com o servidor Ollama da disciplina.
- Rodadas salvas em três momentos, para comparação antes/depois:
  - `resultados_2026-06-30/` — baseline, antes de qualquer ajuste.
  - `resultados_final_pre_ast/` — depois dos ajustes de prompt e temperatura, antes da correção via AST.
  - `resultados_final/` — versão final, com todos os ajustes aplicados.
- Testes pontuais adicionais (matriz de contexto, repetições para medir não-determinismo, testes unitários das funções novas) não foram todos salvos como dataset formal, mas estão descritos abaixo com os números medidos.

---

## 3. Linha do tempo das descobertas e ajustes

### 3.1 Primeira rodada — 3 bugs encontrados

Rodando o dataset pela primeira vez (`resultados_2026-06-30/`):

| # | Bug | Onde | Evidência |
|---|---|---|---|
| 1 | SQL parametrizado (`execute(query, valores)`, padrão seguro) confirmado como SQLi | Agente 2/3 | `sql_statements.py` linhas 35,36,37,39; `sql_multiline_statements.py` linhas 105,107,109 |
| 2 | `mark_safe()`/`Markup()` só com literal fixo quase sempre confirmado como XSS | Agente 3 | `mark_safe_secure.py`: 18/19 confirmados (94,7%), incluindo casos em que a própria justificativa do LLM dizia "não é vulnerabilidade" mas o `status` saía `confirmado` |
| 3 | `Markup(f"...")` com variável real sendo descartado (falso negativo) | Agente 2 | `markupsafe_markup_xss.py` linha 5, marcada como vulnerabilidade real pelo próprio Bandit (`# B704`) |

Também corrigi, nesta fase, duas suposições erradas que eu mesmo tinha documentado no gabarito antes de rodar: achava que a regex de XSS não cobria `mark_safe`/`Markup` (cobre) e que a regex de SQLi tinha gap em strings multilinha (não tem — o problema real era o julgamento do LLM, não a regex).

### 3.2 Ajuste de prompt (rodada 1)

**Mudança:** `agentes/sast/agente2.py` e `agentes/severidade/agente3.py` ganharam regras explícitas sobre parametrização SQL e `mark_safe`/`Markup` variável-vs-literal.

**Resultado:** melhora real, mas não completa — 3→2→1 falso positivo em rodadas sucessivas de refinamento no caso multilinha; melhora de 94,7%→38,9% de falso positivo em `mark_safe_secure.py`; falso negativo do `Markup(f"...")` corrigido.

**Causa raiz do resíduo identificada:** confusão entre `'%s'` como placeholder do driver de banco (seguro) e o operador `%` de formatação Python (perigoso) — corrigida com uma segunda rodada de refinamento textual explicando a distinção.

### 3.3 Revisão de código — 2 bugs encontrados na própria implementação

Ao revisar o código que eu mesmo tinha escrito para capturar trechos multilinha (`_capturar_trecho_completo`), 3 agentes de revisão em paralelo encontraram:

| Bug | Descrição | Correção |
|---|---|---|
| Lógica de aspas triplas errada | XOR combinava a paridade de `"""` e `'''` num único estado; uma string `"""..."""` fechada contendo `'''` como dado (ex.: `x = """a'''b"""`) era tratada como ainda aberta | Reescrito como scanner caractere-a-caractere rastreando um único delimitador ativo |
| Perda de `.strip()` | Trecho passou a incluir indentação (regressão de whitespace) | `.strip()` reaplicado em cada linha capturada |

Ambos corrigidos e validados sem regressão no dataset.

### 3.4 Validação técnica sistemática (6 itens)

| # | Item | Como foi tratado |
|---|---|---|
| 1 | SCA (Agente 1) nunca testado | Testado caminho feliz (23 CVEs reais da OSV.dev) e caminho de falha (endpoint inacessível → aviso claro, sem crash) |
| 2 | Severidade insensível à exposição à internet | Testes mostraram severidade não diferenciava exposto/não-exposto; **corrigido com regra determinística em código** (`_aplicar_teto_severidade`), não mais dependente do LLM |
| 3 | Qualidade das correções do Agente 4 | Revisão dos relatórios já gerados achou alucinações graves em correções de XSS (`{% autoescape off %}`, funções inexistentes como `mark_escape`, recomendar `mark_safe()` como a própria correção) — prompt ajustado |
| 4 | Não-determinismo do LLM | Quantificado (status 100% estável, severidade variando 20-40% entre execuções idênticas) — **corrigido setando `temperature=0.1`** no cliente Ollama |
| 5 | Falso positivo residual (SQL multilinha) | Investigado a fundo — ver seção 3.5 |
| 6 | Duplicação de regras entre Agente 2 e 3 | Centralizada em `agentes/regras_seguranca.py` |

### 3.5 Correção final via AST (fora do LLM)

Uma bateria completa consolidada (todos os 5 casos, todos os ajustes de prompt aplicados) revelou que os fixes de prompt **não se sustentavam de forma confiável** numa execução independente maior — o problema de SQL parametrizado voltou a aparecer (4 de 5 linhas), assim como o de `mark_safe` literal (16 de 20).

**Diagnóstico:** essas duas perguntas não são de julgamento semântico — são puramente sintáticas ("essa chamada tem 1 ou 2 argumentos?", "o argumento é uma variável ou um literal?"). Delegar isso ao LLM era desnecessário.

**Correção:** `agentes/sast/agente2.py` ganhou verificação via módulo `ast` do Python (`_sqli_parametrizada`, `_xss_mark_safe_com_variavel`) que decide essas duas perguntas de forma determinística, pulando o LLM inteiramente quando consegue decidir com certeza.

**Validação:** rodado 2x de forma idêntica (prova de determinismo) e depois através do pipeline completo (Agente 0→1→2→3→4) — resultado 100% reprodutível em ambas as vezes.

---

## 4. Mudanças por arquivo

### `agentes/sast/agente2.py`
- `_capturar_trecho_completo`: captura a instrução completa quando cruza várias linhas (antes só pegava a primeira linha, escondendo informação crítica do LLM).
- `_sqli_parametrizada`, `_xss_mark_safe_com_variavel`, `_decidir_deterministicamente`: verificação via AST que substitui o julgamento do LLM para as duas perguntas mecânicas identificadas.
- `_montar_achado`: helper para eliminar duplicação na montagem do achado final.
- Prompt (`_PROMPT_SISTEMA`): regras sobre `mark_safe`/`Markup`/parametrização, agora importadas de `agentes/regras_seguranca.py`.

### `agentes/severidade/agente3.py`
- `_aplicar_teto_severidade`: regra determinística — sem exposição à internet, severidade nunca fica "crítica" (rebaixada para "alta"), com nota transparente na justificativa.
- Prompt: mesmas regras técnicas compartilhadas (import de `agentes/regras_seguranca.py`) + instrução de consistência status/justificativa + critério explícito de severidade vs. exposição à internet.

### `agentes/relatorio/agente4.py`
- Prompt: proibição explícita de recomendar desativar autoescape, de recomendar `mark_safe()`/`Markup()` como a própria correção, e de citar funções que não existem de verdade.

### `orquestrador/llm_client.py`
- `temperature: float = 0.1` no payload do Ollama (antes usava o padrão do servidor, ~0.8).

### `agentes/regras_seguranca.py` (novo)
- Módulo compartilhado com o fato técnico central de cada regra (parametrização SQL, `mark_safe`/`Markup` literal-vs-variável), evitando duplicação divergente entre os prompts do Agente 2 e do Agente 3.

### `exemplos_codigo/dataset_bandit/` (novo)
- Dataset de teste + gabarito + 3 gerações de resultados salvos (baseline, pré-AST, final) para rastreabilidade do processo.

### `TESTES.md`
- Nova seção "Fase 1.5" descrevendo como rodar o dataset.

---

## 5. Melhorias mensuradas (resumo)

| Problema | Antes | Depois | Como foi resolvido |
|---|---|---|---|
| SQL parametrizado confirmado como SQLi (linha única) | 4 de 5 linhas erradas | 0 de 5, reprodutível 2x | AST (determinístico) |
| SQL parametrizado confirmado como SQLi (multilinha) | 3 de 3 linhas erradas | 0 de 3, reprodutível 2x, inclusive via pipeline completo | Captura de trecho multilinha + AST |
| `Markup(f"...")` real descartado (falso negativo) | Descartado | Confirmado corretamente, inclusive caso não detectado pelo próprio Bandit (`Markup(object=...)`) | Prompt + AST (incluindo argumentos nomeados) |
| Severidade ignora exposição à internet | Mesma severidade exposto/não-exposto em 4 de 5 combinações testadas | 100% consistente (3 de 3 repetições), nunca mais "crítica" sem exposição | Regra determinística em código |
| Não-determinismo geral de severidade | 2 de 5 execuções idênticas divergiam | 0 de 5 | `temperature=0.1` |
| Alucinações nas correções do Agente 4 (XSS) | 8 de 39 sugestões erradas/perigosas | 1 de 8 na amostra revalidada (residual leve, falha seguramente) | Prompt |
| SCA nunca testado | Sem cobertura | Caminho feliz e de falha validados | Testes diretos |
| Duplicação de regras entre agentes | Risco de divergência silenciosa | Fonte única (`regras_seguranca.py`) | Refatoração |

---

## 6. Pontos de fragilidade que persistem

Estes **não são bugs no sentido comum** — são limitações estruturais da abordagem que continuam presentes mesmo depois de todas as correções, e valem como material de "limitações"/"trabalho futuro":

### 6.1 `mark_safe_secure.py` — falso positivo por falta de rastreamento de fluxo de dados (taint tracking)

A maioria dos casos "seguros" desse arquivo atribui um literal a uma variável ANTES de passá-la para `mark_safe()` (ex.: `x = '<b>seguro</b>'; mark_safe(x)`). A verificação via AST (e o LLM, antes dela) só enxerga que `x` é uma variável — não consegue provar que o valor de `x` é seguro, porque isso exigiria rastrear a origem do valor através de atribuições anteriores (taint tracking), uma classe de análise estática bem mais complexa do que qualquer coisa implementada aqui.

- **Antes da correção via AST**: taxa de falso positivo instável entre execuções (94,7% → 38,9% → 80%, dependendo da rodada).
- **Depois**: **100% consistente, sempre confirmado (16 de 16)**. O determinismo não corrigiu o problema — ele **eliminou a variância, cristalizando o erro no pior caso possível** em vez de reduzi-lo. Achado importante: determinismo não é sinônimo de acerto.

### 6.2 Qualidade do Agente 4 revisada de forma desigual

A revisão de correções alucinadas foi profunda para XSS/`mark_safe` (onde o problema foi descoberto), mas rasa para SQLi e segredo exposto — apenas uma amostragem, sem o mesmo nível de escrutínio. Não há garantia de que problemas equivalentes não existam nessas categorias.

### 6.3 Escopo estreito de alguns testes

- SCA testado com apenas 1 arquivo `requirements.txt` sintético — não testado com entradas mais "sujas"/realistas (múltiplos formatos, extras de pacote, URLs git, etc.).
- Sensibilidade a contexto (exposição/validações) testada apenas com achados de SQLi — não confirmado que generaliza para achados de SCA ou segredo exposto.

### 6.4 Resíduo de falha de infraestrutura (não é bug de prompt)

Em pelo menos duas ocasiões durante os testes, uma chamada ao LLM falhou de verdade (`"Avaliação automática indisponível (LLM inacessível)"`), acionando o fallback de segurança do próprio código (`confirmado`/`alta` por padrão). Isso é esperado do design (fail-safe), mas mostra que o servidor compartilhado da disciplina tem instabilidade real, fora do controle do time.

### 6.5 O que fica de aprendizado geral

A distinção mais importante encontrada ao longo do processo: **quando a decisão certa pode ser expressa como regra determinística sobre dado estruturado ou sintaxe (exposição à internet, parametrização SQL, presença de variável), mover a decisão do LLM para código resolveu de forma permanente e 100% reprodutível.** Quando a decisão exige reasoning semântico real (rastrear a origem de uma variável, avaliar nuance de contexto de negócio, gerar texto livre sem alucinar), nenhuma quantidade de ajuste de prompt ou redução de temperatura eliminou completamente a fragilidade — no melhor caso, reduziu a variância; no pior caso (`mark_safe_secure.py`), a reduziu para zero em torno da resposta errada.

---

## 7. Estado do repositório

Todas as mudanças estão commitadas na branch `teste-dataset-bandit-ajustes-prompts` (commit `a860a83`), sem alterar `main`. Push para o remoto não foi feito.
