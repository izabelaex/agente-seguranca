# Agente 4 — Gerador de Relatórios e Correções

**Responsável:** Juan

## O que entra

Lista de achados validados produzida pelo Agente 3.

```json
{
  "achados_validados": [ /* schema do Agente 3 */ ]
}
```

## O que sai

Relatório final estruturado.

```json
{
  "relatorio": {
    "projeto_id": "string",
    "total_vulnerabilidades": "integer",
    "vulnerabilidades": [
      {
        "tipo": "string",
        "severidade": "critica | alta | media | baixa | informativo",
        "prioridade": "integer",
        "localizacao": { "arquivo": "string", "linha": "integer | null" },
        "trecho_codigo": "string",
        "explicacao": "string",
        "sugestao_correcao": "string",
        "referencia_cwe_cve": "string"
      }
    ]
  }
}
```

## Responsabilidade

Consolidar os achados validados em um relatório final legível, ordenado por prioridade, com trechos de código problemáticos e sugestões de correção.
