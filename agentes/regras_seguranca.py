"""
Regras técnicas de segurança compartilhadas entre os prompts do Agente 2 (SAST) e
do Agente 3 (Severidade).

Os dois agentes precisam avaliar os MESMOS fatos técnicos (é uma consulta SQL
parametrizada? é um mark_safe()/Markup() com dado confiável ou não?) para decidir
coisas diferentes (Agente 2: confirmar/descartar o achado; Agente 3: confirmar/
descartar considerando contexto e atribuir severidade). Antes, cada prompt repetia
o texto da regra de forma independente — se alguém ajustasse um e esquecesse o
outro, os agentes podiam divergir silenciosamente na mesma decisão técnica.

Este módulo centraliza o fato técnico em si; cada agente só adiciona, em volta
dele, a ação específica que deve tomar com base nesse fato.
"""

REGRA_SQL_PARAMETRIZADO = (
    "A consulta SQL usa execute(query, valores) com os valores como argumento "
    "SEPARADO da string da query (não interpolados nela via %, .format(), f-string "
    "ou +): isso é uma consulta parametrizada e SEGURA. Isso vale mesmo que a "
    "própria string da query contenha marcadores como '%s', '?' ou ':nome' entre "
    "aspas — são placeholders que o driver do banco substitui internamente pelos "
    "valores do argumento separado, não o operador de formatação do Python. Só é "
    "perigoso quando a string e a variável estão no MESMO argumento (ex.: "
    '"...%s" % identifier, ou "...".format(identifier), tudo dentro de um único '
    "argumento de execute())."
)

REGRA_MARK_SAFE_MARKUP = (
    "Se mark_safe(), Markup() ou render_template_string() recebem uma variável — "
    "direta ou via f-string, .format() ou % — o escape automático do template "
    "engine foi pulado: há XSS real. Se recebem apenas uma string literal fixa, "
    "sem nenhuma variável envolvida, não há XSS real."
)
