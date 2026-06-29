# Agente 1 — SCA (Analisador de Dependências)

**Responsável:** Amanda

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

Lista de achados SCA no schema definido em `contratos/schemas.py`.

```json
{
  "achados_sca": [
    {
      "dependencia": "string",
      "versao": "string",
      "cve": "string",
      "severidade_base": "string",
      "arquivo": "string"
    }
  ]
}
```

## Responsabilidade

Verificar bibliotecas importadas nos arquivos Python contra base de CVEs conhecidas.
