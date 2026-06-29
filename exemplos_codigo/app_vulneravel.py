# Arquivo de exemplo com vulnerabilidades intencionais para testar o pipeline.
# NÃO usar em produção.

import sqlite3

DB_PASSWORD = "senha123"  # segredo exposto (CWE-798)

def buscar_usuario(nome):
    conn = sqlite3.connect("banco.db")
    cursor = conn.cursor()
    # SQL Injection (CWE-89): entrada concatenada diretamente na query
    cursor.execute("SELECT * FROM usuarios WHERE nome = '" + nome + "'")
    return cursor.fetchall()
