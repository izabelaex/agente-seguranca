# Agente 2 — SAST (Analisador Estático)

**Responsável:** Fabrício

## O que entra

Recebe do Agente 0 uma lista de arquivos Python do projeto analisado.

```json
{
  "projeto_id": "string",
  "arquivos": [
    { "caminho": "string", "conteudo": "string" }
  ]
}
```

## O que sai

Lista de achados SAST no schema definido em `contratos/schemas.py`.

```json
{
  "achados_sast": [
    {
      "tipo": "sqli | xss | segredo_exposto",
      "arquivo": "string",
      "linha": "integer",
      "trecho": "string",
      "cwe": "string",
      "cve": "string | null",
      "descricao": "string"
    }
  ]
}
```

## Responsabilidade

Varrer o código-fonte Python buscando padrões de risco:
- SQL Injection (CWE-89)
- XSS — Cross-Site Scripting (CWE-79)
- Segredos expostos / hardcoded credentials (CWE-798)
