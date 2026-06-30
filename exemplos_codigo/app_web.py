# Arquivo de exemplo com vulnerabilidades intencionais para testar o pipeline.
# NÃO usar em produção.

from flask import Flask, request

app = Flask(__name__)

SECRET_KEY = "chave-super-secreta-123"  # segredo exposto (CWE-798)

@app.route("/buscar")
def buscar():
    termo = request.args.get("q", "")
    # XSS (CWE-79): entrada do usuário refletida diretamente no HTML sem escape
    return "<html><body>Resultado para: " + termo + "</body></html>"

@app.route("/perfil")
def perfil():
    nome = request.args.get("nome", "")
    # XSS (CWE-79): mesma falha em outro endpoint
    return "<p>Bem-vindo, " + nome + "!</p>"
