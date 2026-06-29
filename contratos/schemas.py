"""
Contratos de dados do Sistema Multiagente de Segurança.

Define os schemas (usando TypedDict) de cada interface entre os agentes.
Todos os agentes DEVEM seguir estes contratos para garantir integração sem retrabalho.

Fluxo:
  EntradaSistema
      │
      ├──► AchadoSCA   (Agente 1 — Amanda)
      ├──► AchadoSAST  (Agente 2 — Fabrício)
      │
      ▼
  EntradaAvaliador  (Agente 3 — Juan)
      ▼
  AchadoValidado
      ▼
  Relatorio         (Agente 4 — Juan)
"""

from typing import TypedDict, Literal, Optional


#Entrada do sistema pelo Agente 0

class Arquivo(TypedDict):
    caminho: str       # Caminho relativo do arquivo, ex.: "src/app.py"
    conteudo: str      # Conteúdo completo do arquivo


class ContextoProjeto(TypedDict):
    exposto_internet: bool         # A aplicação está exposta à internet?
    tipo_aplicacao: str            # Ex.: "API REST", "script interno", "web app"
    validacoes_existentes: str     # Descrição de validações já implementadas pelo dev


class EntradaSistema(TypedDict):
    projeto_id: str                # Identificador único da análise
    arquivos: list[Arquivo]        # Arquivos Python a analisar
    contexto: ContextoProjeto      # Contexto fornecido pelo desenvolvedor


#Achado do SCA pelo Agente 1

class AchadoSCA(TypedDict):
    dependencia: str       # Nome da biblioteca, ex.: "requests"
    versao: str            # Versão usada, ex.: "2.19.0"
    cve: str               # Identificador CVE, ex.: "CVE-2023-32681"
    severidade_base: str   # Severidade da base de dados, ex.: "HIGH"
    arquivo: str           # Arquivo onde a dependência é usada, ex.: "requirements.txt"


class SaidaSCA(TypedDict):
    projeto_id: str
    achados_sca: list[AchadoSCA]



# Achado do SAST pelo Agente 2 

TipoVulnerabilidade = Literal["sqli", "xss", "segredo_exposto"]


class AchadoSAST(TypedDict):
    tipo: TipoVulnerabilidade   # Tipo de vulnerabilidade identificada
    arquivo: str                # Arquivo onde foi encontrada
    linha: int                  # Número da linha
    trecho: str                 # Trecho de código problemático
    cwe: str                    # Referência CWE, ex.: "CWE-89"
    cve: Optional[str]          # Referência CVE se aplicável (pode ser None)
    descricao: str              # Descrição do padrão identificado


class SaidaSAST(TypedDict):
    projeto_id: str
    achados_sast: list[AchadoSAST]



# Entrada do Avaliador de Contexto e Severidade pelo Agente 3

class EntradaAvaliador(TypedDict):
    projeto_id: str
    achados_sca: list[AchadoSCA]
    achados_sast: list[AchadoSAST]
    contexto: ContextoProjeto


# Achado validado pela saída do Agente 3 com entrada do Agente 4 

StatusAchado = Literal["confirmado", "descartado"]
NivelSeveridade = Literal["critica", "alta", "media", "baixa", "informativo"]


class Localizacao(TypedDict):
    arquivo: str
    linha: Optional[int]   # None quando não se aplica (ex.: dependência)


class AchadoValidado(TypedDict):
    tipo: str                        # Tipo do achado (herdado do SCA ou SAST)
    localizacao: Localizacao
    referencia_cwe_cve: str          # Ex.: "CWE-89" ou "CVE-2023-32681"
    descricao: str
    status: StatusAchado             # "confirmado" ou "descartado"
    severidade: NivelSeveridade      # Severidade calculada pelo Agente 3
    justificativa: str               # Por que foi confirmado/descartado e com essa severidade


class SaidaAvaliador(TypedDict):
    projeto_id: str
    achados_validados: list[AchadoValidado]


# Relatório final pela saída do Agente 4

class VulnerabilidadeRelatorio(TypedDict):
    tipo: str
    severidade: NivelSeveridade
    prioridade: int               # 1 = mais urgente
    localizacao: Localizacao
    trecho_codigo: str
    explicacao: str
    sugestao_correcao: str
    referencia_cwe_cve: str


class Relatorio(TypedDict):
    projeto_id: str
    total_vulnerabilidades: int
    vulnerabilidades: list[VulnerabilidadeRelatorio]


class SaidaRelatorio(TypedDict):
    relatorio: Relatorio
