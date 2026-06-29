"""
Agente 1 — SCA (Analisador de Dependências)
Responsável: Izabela

Extrai dependências de arquivos requirements.txt e consulta a API do OSV.dev
para identificar CVEs conhecidos em cada versão declarada.
"""

import re
import json
import urllib.request
from typing import Optional

from contratos.schemas import EntradaSistema, SaidaSCA, AchadoSCA


#Extração de dependências

# Regex que captura "pacote==versao" (ignora extras, URLs, comentários)
_REQUISITO = re.compile(
    r"^\s*([A-Za-z0-9_\-\.]+)\s*==\s*([A-Za-z0-9_\.\-]+)",
    re.MULTILINE,
)


def _extrair_dependencias(arquivos: list[dict]) -> list[tuple[str, str, str]]:
    """
    Lê arquivos do projeto e extrai dependências com versão fixada.

    Suporta:
      - requirements.txt  (pacote==versao)
      - qualquer arquivo .txt com o mesmo padrão

    Returns:
        Lista de tuplas (nome_pacote, versao, caminho_arquivo).
    """
    dependencias = []
    for arq in arquivos:
        caminho: str = arq["caminho"]
        conteudo: str = arq["conteudo"]

        # Considera apenas arquivos de dependências
        nome_arquivo = caminho.split("/")[-1].split("\\")[-1].lower()
        if not (nome_arquivo == "requirements.txt" or nome_arquivo.endswith(".txt")):
            continue

        for match in _REQUISITO.finditer(conteudo):
            pacote = match.group(1).lower().replace("_", "-")
            versao = match.group(2)
            dependencias.append((pacote, versao, caminho))

    return dependencias


#Consulta à API OSV.DEV

OSV_API_URL = "https://api.osv.dev/v1/query"


def _consultar_osv(pacote: str, versao: str) -> list[dict]:
    """
    Consulta a API do OSV.dev e retorna lista de vulnerabilidades encontradas.

    Args:
        pacote: Nome do pacote PyPI (lowercase, hifenizado).
        versao: Versão exata declarada no requirements.txt.

    Returns:
        Lista de dicts com os campos relevantes de cada vulnerabilidade.
        Retorna lista vazia se não houver vulnerabilidades ou em caso de erro.
    """
    payload = json.dumps({
        "package": {"name": pacote, "ecosystem": "PyPI"},
        "version": versao,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            OSV_API_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        print(f"  [SCA] Aviso: falha ao consultar OSV para {pacote}=={versao}: {e}")
        return []

    return data.get("vulns", [])


def _extrair_cve(vuln: dict) -> Optional[str]:
    """Tenta extrair um identificador CVE dos aliases da vulnerabilidade."""
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id")  # fallback para o ID do OSV (ex.: GHSA-...)


def _extrair_severidade(vuln: dict) -> str:
    """Extrai a severidade da vulnerabilidade (HIGH, MEDIUM, LOW, UNKNOWN)."""
    # OSV pode trazer severidade em 'database_specific' ou em 'severity'
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if db_sev:
        return db_sev.upper()

    scores = vuln.get("severity", [])
    if scores:
        score = scores[0].get("score", "")
        # CVSS scores: >= 9 CRITICAL, >= 7 HIGH, >= 4 MEDIUM, else LOW
        try:
            valor = float(score)
            if valor >= 9.0:
                return "CRITICAL"
            elif valor >= 7.0:
                return "HIGH"
            elif valor >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        except ValueError:
            return score.upper() if score else "UNKNOWN"

    return "UNKNOWN"


#Função principal 
def analisar_dependencias(entrada: EntradaSistema) -> SaidaSCA:
    """
    Recebe os arquivos do projeto e retorna achados de dependências vulneráveis.

    Args:
        entrada: Payload no formato EntradaSistema.

    Returns:
        SaidaSCA com lista de dependências vulneráveis encontradas.
    """
    print("[Agente 1 - SCA] Extraindo dependências...")

    dependencias = _extrair_dependencias(entrada["arquivos"])

    if not dependencias:
        print("[Agente 1 - SCA] Nenhuma dependência com versão fixada encontrada.")
        return {"projeto_id": entrada["projeto_id"], "achados_sca": []}

    print(f"[Agente 1 - SCA] {len(dependencias)} dependência(s) encontrada(s). Consultando OSV.dev...")

    achados: list[AchadoSCA] = []

    for pacote, versao, arquivo in dependencias:
        print(f"  Verificando {pacote}=={versao}...")
        vulns = _consultar_osv(pacote, versao)

        for vuln in vulns:
            cve = _extrair_cve(vuln)
            severidade = _extrair_severidade(vuln)
            achados.append({
                "dependencia": pacote,
                "versao": versao,
                "cve": cve,
                "severidade_base": severidade,
                "arquivo": arquivo,
            })

    print(f"[Agente 1 - SCA] {len(achados)} vulnerabilidade(s) encontrada(s).")

    return {
        "projeto_id": entrada["projeto_id"],
        "achados_sca": achados,
    }
