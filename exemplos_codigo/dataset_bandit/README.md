# Dataset — Bandit examples

Arquivos retirados de [PyCQA/bandit](https://github.com/PyCQA/bandit/tree/main/examples)
(licença Apache-2.0), usados pelo próprio Bandit (ferramenta SAST de referência para
Python) para testar suas regras. Escolhidos por cobrirem exatamente os 3 tipos do MVP
(SQLi, XSS, segredo exposto) com casos "ruins" e "bons" lado a lado — bom para achar
falso-positivo e falso-negativo no Agente 2 (SAST) e nas decisões do Agente 3 (Severidade).

Use o roteiro de `TESTES.md` (seção "Fase 1.5") para rodar cada arquivo e comparar com o
gabarito abaixo.

## Gabarito (resultado esperado)

### `sql_statements.py` — SQL Injection (CWE-89)
- ~19 ocorrências de concatenação/format/`%`/f-string direto em query → **devem ser confirmadas**
  (linhas com `cur.execute(...)` e variáveis `query = ...` montadas de forma insegura).
- Bloco final marcado `# good` (linhas 35-39, `cur.execute("...", identifier)`, parametrizado) →
  **não deveriam ser confirmadas** (teste de falso positivo).
- **Bug real encontrado (execução em 2026-06-30):** as linhas 35, 36, 37 e 39 — todas do bloco
  `# good`, query parametrizada corretamente — foram **confirmadas como SQL Injection** com
  severidade alta/crítica. O LLM não reconhece que passar os parâmetros como segundo argumento
  de `execute()` (em vez de interpolar na string) é justamente o padrão seguro recomendado.
  Candidato direto a ajuste de prompt no Agente 2 e/ou Agente 3.

### `sql_multiline_statements.py` — SQL Injection (CWE-89), strings multilinha
- Mesmos padrões de `sql_statements.py`, mas em strings `"""..."""` que cruzam várias linhas.
- **Correção (validado em execução real em 2026-06-30):** a regex do Agente 2 casa pela
  linha de abertura do `execute(`/`"""` e cobre corretamente as 19 ocorrências — não há gap
  de regex aqui como eu tinha suposto antes de rodar. O problema real está um nível acima:
  o LLM do Agente 2 (`_confirmar_com_llm`) descartou como falso positivo duas linhas
  genuinamente vulneráveis (linha 33, `% value` dentro de `execute("""INSERT...`, e linha 69,
  f-string com `{column_name}` não escapado) — falso negativo real, não de regex.
- Bloco final com `# nosec` → não deveriam ser confirmadas (mas nosso agente não interpreta
  `# nosec`, então isso por si só não é bug nosso).

### `hardcoded-passwords.py` — Segredo exposto (CWE-798)
- Maioria das atribuições `algo_password = "literal"` / `senha == "literal"` →
  **devem ser confirmadas**.
- Casos com `password == ''` (string vazia) e variáveis recebendo outra variável
  (ex.: `"password": password`) → **não devem ser confirmadas** (teste de falso positivo).

### `mark_safe_insecure.py` / `mark_safe_secure.py` — XSS (CWE-79), Django `mark_safe`
- **Correção:** a regex `_REGEX_XSS` cobre `mark_safe(` normalmente (está na primeira
  alternativa junto com `Markup`/`render_template_string`) — não há gap de regex aqui. Eu
  tinha documentado isso errado antes de rodar o teste de verdade.
- `_insecure`: várias funções retornam HTML não escapado para `safestring.mark_safe(...)`.
  Deveriam ser confirmadas — e na execução real (2026-06-30) foram, corretamente.
- `_secure`: só strings literais seguras, sem dado de usuário. **Bug real encontrado:** dos
  19 candidatos que a regex encontrou neste arquivo, 18 foram confirmados como XSS pelo
  Agente 3 e só 1 descartado — mesmo quando a `justificativa` gerada pelo próprio LLM dizia
  coisas como "não representa uma vulnerabilidade XSS" ou "parece ser um false positive", o
  campo `status` ainda saía como `confirmado` (ver linhas 41, 45, 54 do resultado salvo em
  `bandit-xss-django.json`). Ou seja: o raciocínio em texto livre do modelo às vezes acerta,
  mas o campo estruturado que o sistema realmente usa não reflete esse raciocínio.

### `markupsafe_markup_xss.py` — XSS (CWE-79), Flask + `markupsafe.Markup`
- **Correção:** mesma coisa — a regex cobre `Markup(`, não há gap. A regex encontrou 8
  candidatos (linhas 5,6,7,8,10,11,12,13).
- Linhas marcadas `# B704` no bandit original (5, 6, 10, 11) → deveriam ser confirmadas.
- **Bug real encontrado:** a linha 5 (`Markup(f"unsafe {content}")`), que É uma vulnerabilidade
  real segundo o bandit (`# B704`), foi descartada pelo Agente 2 antes mesmo de chegar ao
  Agente 3 — falso negativo. As linhas 6, 8, 10, 11, 12, 13 foram confirmadas (incluindo 12,
  `Markup(object="safe")`, que é literal fixo sem dado de usuário — possível falso positivo
  também, a validar).
- `escape(content)` (linha 9) → corretamente nem virou candidato (não casa com a regex).

## Como rodar

```bash
python orquestrador/agente0.py teste-bandit-sqli exemplos_codigo/dataset_bandit/sql_statements.py
python orquestrador/agente0.py teste-bandit-sqli-multiline exemplos_codigo/dataset_bandit/sql_multiline_statements.py
python orquestrador/agente0.py teste-bandit-segredo exemplos_codigo/dataset_bandit/hardcoded-passwords.py
python orquestrador/agente0.py teste-bandit-xss-django exemplos_codigo/dataset_bandit/mark_safe_insecure.py exemplos_codigo/dataset_bandit/mark_safe_secure.py
python orquestrador/agente0.py teste-bandit-xss-flask exemplos_codigo/dataset_bandit/markupsafe_markup_xss.py
```

Para cada execução, registre achados confirmados/descartados e compare com o gabarito acima.
