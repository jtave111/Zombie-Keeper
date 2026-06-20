# ZombieKeeper Automations

Automações Python para o ecossistema ZombieKeeper.
Comunica com a API do Spring Boot para automatizar tarefas de operação do C2.

---

## Estrutura

```
ZombieKeeper-Automations/
├── core/                        # utilitários compartilhados
│   ├── client.py                # cliente HTTP para a API ZK
│   ├── auth.py                  # gerenciamento de token JWT
│   ├── models.py                # tipos que espelham os DTOs do backend
│   └── config.py                # leitura de .env e configurações
│
├── automations/                 # módulos por domínio
│   ├── network/
│   │   └── recon_request.py     # dispara sessões de recon via API  ← ativo
│   ├── agents/                  # monitoramento de agentes          ← planejado
│   ├── reports/                 # geração de relatórios             ← planejado
│   └── payloads/                # automação de payloads             ← planejado
│
├── scripts/                     # CLIs standalone (entrypoints)
├── config/                      # arquivos de configuração estática
├── tests/                       # testes por módulo
│
├── pyproject.toml               # dependências e metadados
├── Makefile                     # atalhos de desenvolvimento
├── .env.example                 # template de variáveis de ambiente
└── .gitignore
```

---

## Setup

```bash
# 1. Clonar e entrar na pasta
cd ZombieKeeper-Automations

# 2. Criar ambiente e instalar dependências
make setup

# 3. Ativar o virtualenv
source .venv/bin/activate

# 4. Configurar variáveis de ambiente
cp .env.example .env
# editar .env com a URL da API e credenciais
```

---

## Como usar

### Recon request (ativo)

Dispara e acompanha uma sessão de reconhecimento de rede via API:

```bash
python automations/network/recon_request.py <JSESSIONID> <URL_ALVO>
```

---

## Como adicionar um novo módulo

1. Escolha o domínio: `network/`, `agents/`, `reports/` ou crie um novo
2. Crie o arquivo `.py` dentro do domínio
3. Atualize o `__init__.py` do domínio com a descrição do módulo
4. Se for um CLI, crie um entrypoint em `scripts/` e registre em `pyproject.toml`
5. Adicione testes em `tests/test_<modulo>.py`

---

## Variáveis de ambiente

| Variável | Descrição | Padrão |
|---|---|---|
| `ZK_API_URL` | URL base da API Spring Boot | `http://localhost:8080` |
| `ZK_USERNAME` | Usuário para autenticação | — |
| `ZK_PASSWORD` | Senha para autenticação | — |

---

## Testes

```bash
make test
# ou diretamente:
python -m pytest tests/ -v
```
