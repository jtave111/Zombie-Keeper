# Mudanças necessárias no ZombieKeeper-Api após migração para Tauri

## 1. CORS — adicionar origens do Tauri

O cliente agora é um app desktop, não um browser acessando `localhost:3000`.
Adicionar ao `CorsConfig.java`:

```java
// Dev (Vite)
"http://localhost:1420",
// Produção Tauri (Linux/Windows)
"tauri://localhost",
// Produção Tauri (macOS)
"https://tauri.localhost",
```

## 2. Login — retornar token no body

O endpoint `POST /api/auth/login` deve retornar o JWT no body da resposta.
O frontend agora lê `data.token` diretamente (antes era o Next.js que extraía e setava cookie).

Formato esperado:
```json
{
  "token": "eyJ...",
  "username": "operator",
  "status": "ONLINE"
}
```

Se o endpoint já retorna isso, nenhuma mudança necessária.

## 3. WebSocket — CORS para ws://

O handshake WebSocket também precisa das origens acima liberadas.
Verificar `JwtHandshakeInterceptor` e `WebSocketsConfig`.

Endpoints WebSocket usados pelo frontend:
- `ws://localhost:8080/term?token=JWT`         ← C2 shell
- `ws://localhost:8080/term/{agentId}?token=JWT` ← shell de agente específico

## 4. Remoção do proxy Next.js

Antes: browser → Next.js `/api/*` → Spring Boot
Agora: app Tauri → Spring Boot diretamente

Todos os endpoints chamados diretamente pelo frontend:
| Antes (proxy)          | Agora (direto)                    |
|------------------------|-----------------------------------|
| POST /api/auth/login   | POST /api/auth/login              |
| GET  /api/agents       | GET  /api/c2-server/agents        |
| GET  /api/agents/:id   | GET  /api/c2-server/agents/:id    |
| GET  /api/c2           | GET  /api/c2-server/info          |
| GET  /api/users        | GET  /api/auth/users              |
| GET  /api/users/roles  | GET  /api/auth/roles              |
| POST /api/users        | POST /api/auth/register           |

## 5. Variáveis de ambiente do frontend

Criar `ZombieKeeper-Web/.env`:
```
VITE_API_URL=http://localhost:8080
VITE_WS_URL=ws://localhost:8080
```

Em produção apontar para o IP/domínio real do servidor C2.
