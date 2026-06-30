# Arquivo de exemplo com vulnerabilidades intencionais para testar o pipeline.
# NÃO usar em produção.

import sqlite3

API_TOKEN = "tok_prod_abc123secret"  # segredo exposto (CWE-798)
DB_PASS = "admin@2024"              # segredo exposto (CWE-798)

def buscar_produto(categoria):
    conn = sqlite3.connect("loja.db")
    cursor = conn.cursor()
    # SQL Injection (CWE-89): categoria vem direto do usuário
    cursor.execute("SELECT * FROM produtos WHERE categoria = '" + categoria + "'")
    return cursor.fetchall()

def buscar_pedido(usuario_id):
    conn = sqlite3.connect("loja.db")
    cursor = conn.cursor()
    # SQL Injection (CWE-89): segundo ponto de injeção
    cursor.execute("SELECT * FROM pedidos WHERE usuario = '" + usuario_id + "'")
    return cursor.fetchall()
