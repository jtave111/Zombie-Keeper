# core/
# ─────────────────────────────────────────────────────────────────────────────
# Utilitários compartilhados por todos os módulos de automação.
#
# O que pertence aqui:
#   client.py    → cliente HTTP para a API do ZombieKeeper (auth, requests)
#   auth.py      → gerenciamento de token JWT
#   models.py    → dataclasses/TypedDicts que espelham os DTOs do backend
#   config.py    → leitura de variáveis de ambiente e configurações
#
# Regra: nenhum módulo em automations/ faz requests HTTP diretamente.
#        Tudo passa pelo client.py daqui.
# ─────────────────────────────────────────────────────────────────────────────
