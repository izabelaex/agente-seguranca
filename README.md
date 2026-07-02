# Sistema Multiagente de Revisão de Segurança

Sistema multiagente para revisão de segurança em código-fonte Python, atuando como um "agente de segurança" que analisa arquivos de código e identifica vulnerabilidades.

## Arquitetura

```
Desenvolvedor
     │
     ▼
[Agente 0 — Orquestrador]  ← Izabela
     │
     ├──► [Agente 1 — SCA]        ← Amanda
     │         (CVEs em dependências)
     │
     ├──► [Agente 2 — SAST]       ← Fabrício
     │         (SQLi, XSS, segredos expostos)
     │
     ▼
[Agente 3 — Severidade]    ← Juan
     │    (cruza achados com contexto)
     ▼
[Agente 4 — Relatório]     ← Juan
     │    (relatório final priorizado)
     ▼
[Agente 0 entrega ao desenvolvedor]
```

## Estrutura de pastas

```
projeto-agente-seguranca/
├── DECISOES.md          # Decisões de tecnologia e escopo
├── README.md
├── requirements.txt
├── orquestrador/        # Agente 0 (Izabela)
├── agentes/
│   ├── sca/             # Agente 1 (Amanda)
│   ├── sast/            # Agente 2 (Fabrício)
│   ├── severidade/      # Agente 3 (Juan)
│   └── relatorio/       # Agente 4 (Juan)
├── contratos/           # Schemas e exemplos de payload JSON
│   └── exemplos/
├── exemplos_codigo/     # Arquivos Python de teste com vulnerabilidades
└── tests/
```

## MVP — Vulnerabilidades priorizadas

- SQL Injection
- XSS (Cross-Site Scripting)
- Exposição de segredos (hardcoded credentials)

## Como rodar

- Instalação das dependências:
```pip install -r requirements.txt```

- Para a interface visual:
```streamlit run interface/app.py```

- Para o LangGraph: