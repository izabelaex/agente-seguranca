# Agente 3 — Avaliador de Contexto e Severidade

**Responsável:** Juan

## O que entra

Lista consolidada de achados do SCA (Agente 1) e do SAST (Agente 2), mais contexto do sistema fornecido pelo desenvolvedor via Agente 0.

```json
{
  "achados_sca": [ /* schema do Agente 1 */ ],
  "achados_sast": [ /* schema do Agente 2 */ ],
  "contexto": {
    "exposto_internet": "boolean",
    "tipo_aplicacao": "string",
    "validacoes_existentes": "string"
  }
}
```

## O que sai

Lista de achados validados (confirmados ou descartados), com severidade calculada.

```json
{
  "achados_validados": [
    {
      "tipo": "string",
      "localizacao": { "arquivo": "string", "linha": "integer | null" },
      "referencia_cwe_cve": "string",
      "descricao": "string",
      "status": "confirmado | descartado",
      "severidade": "critica | alta | media | baixa | informativo",
      "justificativa": "string"
    }
  ]
}
```

## Responsabilidade

Cruzar achados preliminares com o contexto real do sistema para confirmar ou descartar cada achado e calcular a severidade efetiva.
