# ZombieKeeper Web — Guia de Segurança

Tudo que precisa ser feito para transformar o frontend no padrão de uma
aplicação real: Next.js como proxy, token em cookie HttpOnly, URL do Spring Boot
nunca exposta ao browser.

---

## Status atual da implementação

> Atualize esta tabela conforme for concluindo cada etapa.

| Etapa | Status | O que foi feito / falta fazer |
|---|---|---|
| 1 — Variáveis de ambiente | ✅ feito | `.env` criado com `API_URL` e `API_WS_URL`. Nenhuma variável secreta usa `NEXT_PUBLIC_` |
| 2 — `middleware.ts` | ✅ feito | Criado em `src/middleware.ts`. Redireciona `/login` ↔ `/` conforme o cookie `zk_token` |
| 3 — `lib/server/api.ts` | ✅ feito | Reescrito como cliente server-only com `cookies()`. Usa `proxyTo` utilitário |
| 4 — API Routes (proxy) | ✅ feito | `auth/login`, `auth/logout`, `agents`, `agents/[id]`, `c2`, `users`, `users/roles`, `users/[id]`, `users/[id]/role`, `users/[id]/password` |
| 5 — `lib/client/api.ts` | ✅ feito | Criado com todos os exports: `auth`, `agentsApi`, `c2Api`, `usersApi`, `toAgent`, `toAgentGeo`, `mapStatus`, tipos `C2Info`, `BackendUser`, `BackendRole` |
| 6 — Atualizar componentes | ✅ feito | `App.tsx`, `DashboardView.tsx`, `AgentTableHeader.tsx`, `WorldMap.tsx`, `ShellModule.tsx`, `LoginPage.tsx`, `UsersView.tsx` — todos migrados para `@/lib/client/api` |
| 7 — WebSocket do AgentShell | ❌ pendente | `ShellModule.tsx` ainda usa `localStorage` e URL direta do Spring Boot. Requer criar `src/app/api/shell/route.ts` com upgrade WebSocket |
| 8 — Security headers | ✅ feito | `next.config.js` com `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` |

### Por que essa ordem importa

- **Etapa 3 antes da 5**: o `lib/server/api.ts` é usado por Server Components e
  precisa estar correto antes de você criar o `lib/client/api.ts` para os
  componentes cliente — se os dois conviverem errados ao mesmo tempo, fica
  difícil rastrear bugs.
- **Etapa 4 antes da 5 e 6**: as API Routes são o proxy que o `lib/client/api.ts`
  vai chamar. Se as routes não existirem, o cliente vai receber 404 em tudo.
- **Etapa 2 por último era o ideal**, mas já está feita — ok. O risco era: se o
  middleware redirecionar para `/login` antes do login estar funcionando via
  cookie, você trava fora do sistema. Como já implementou, **teste o fluxo de
  login antes de mais nada**.
- **Etapa 7 pode ser feita por último**: o WebSocket do shell é a parte mais
  complexa e não bloqueia o resto do sistema.

### Próximo passo imediato

Reescrever `src/lib/server/api.ts` conforme a **Etapa 3** abaixo, depois criar
as API Routes da **Etapa 4**, e só então criar `lib/client/api.ts` (Etapa 5).

---

---

## O problema atual em uma linha

O browser fala **diretamente** com o Spring Boot, manda o token JWT no header,
e vê o endereço do seu C2. Qualquer um com DevTools aberto vê tudo isso.

---

## O que vai mudar

```
HOJE:
Browser ──────────────────────────────→ Spring Boot :8080
        Authorization: Bearer eyJ...    (token e URL expostos)

DEPOIS:
Browser ──→ Next.js /api/* ──→ Spring Boot :8080
        (sem token, sem URL)   (tudo fica aqui)
```

---

## Checklist de implementação

### ETAPA 1 — Variáveis de ambiente

- [x] Renomear `NEXT_PUBLIC_API_URL` para `API_URL` no `.env`
- [x] Garantir que **nenhuma** variável com segredo use o prefixo `NEXT_PUBLIC_`
- [ ] Atualizar `.env.example` com a nova chave `API_URL` (se for criar um .env.example)

```bash
# .env — o que fica assim
API_URL=http://localhost:8080        # servidor apenas — nunca vai ao browser
NEXT_PUBLIC_APP_NAME=ZombieKeeper   # browser — só o que realmente precisa
```

> **Dica:** qualquer variável com `NEXT_PUBLIC_` é embutida no bundle JavaScript
> em tempo de build e fica visível no DevTools → Sources. Se tiver dúvida,
> omita o prefixo — se o Next.js reclamar que não consegue ler no cliente,
> então precisa ser pública. Se não reclamar, não precisa.

---

### ETAPA 2 — `middleware.ts`

Cria o arquivo em `src/middleware.ts`. Ele roda **antes de qualquer página**
e redireciona para `/login` se não houver cookie.

```typescript
import { NextRequest, NextResponse } from 'next/server'

export function middleware(req: NextRequest) {
  const token = req.cookies.get('zk_token')?.value
  const isLoginPage = req.nextUrl.pathname.startsWith('/login')
  const isApiAuth   = req.nextUrl.pathname.startsWith('/api/auth/login')

  if (!token && !isLoginPage && !isApiAuth) {
    return NextResponse.redirect(new URL('/login', req.url))
  }

  if (token && isLoginPage) {
    return NextResponse.redirect(new URL('/', req.url))
  }

  return NextResponse.next()
}

export const config = {
  // Ignora arquivos estáticos e a rota de login do proxy
  matcher: ['/((?!_next/static|_next/image|favicon.ico|api/auth/login).*)'],
}
```

> **Dica:** o `matcher` é importante. Sem ele, o middleware roda até em
> requisições de imagem e CSS, o que causa redirecionamentos em loop.
> Sempre exclua `_next/static` e `_next/image`.

---

### ETAPA 3 — `lib/server/api.ts`

Cria a pasta `src/lib/server/` e o arquivo `api.ts`. Este arquivo só pode ser
importado em Server Components e API Routes — nunca em componentes com
`'use client'`.

```typescript
import { cookies } from 'next/headers'
import type { BackendAgentDto }  from '@/lib/models/agents/agentDto'
import type { C2ServerInfo }     from '@/lib/models/c2Server/c2ServerModel'
import type { NetworkSession }   from '@/lib/models/localNetwork/networkModel'

const SPRING = process.env.API_URL ?? 'http://localhost:8080'

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = (await cookies()).get('zk_token')?.value

  const res = await fetch(`${SPRING}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.headers ?? {}),
    },
    cache: 'no-store',
  })

  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  if (res.status === 204) return undefined as T
  return res.json()
}

export const serverApi = {
  agents: {
    list: ()           => req<BackendAgentDto[]>('/api/c2-server/agents'),
    get:  (id: string) => req<BackendAgentDto>(`/api/c2-server/agents/${id}`),
  },
  c2: {
    info: () => req<C2ServerInfo>('/api/c2-server/info'),
  },
  network: {
    sessions: () => req<NetworkSession[]>('/api/network/sessions'),
  },
  users: {
    list:  () => req<BackendUser[]>('/api/auth/users'),
    roles: () => req<BackendRole[]>('/api/auth/roles'),
  },
}
```

> **Dica:** se você tentar importar `cookies` do `next/headers` num arquivo
> com `'use client'`, o build vai quebrar com um erro claro. Isso é intencional
> — o Next.js te impede de vazar código servidor para o cliente.
> Use isso como proteção: se o build passou, o arquivo está no lugar certo.

---

### ETAPA 4 — API Routes (proxy)

Cria uma rota por recurso dentro de `src/app/api/`. Cada uma lê o cookie
e repassa a requisição para o Spring Boot.

#### `src/app/api/auth/login/route.ts`

```typescript
import { NextRequest, NextResponse } from 'next/server'

const SPRING = process.env.API_URL ?? 'http://localhost:8080'

export async function POST(req: NextRequest) {
  const body = await req.json()

  const upstream = await fetch(`${SPRING}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!upstream.ok) {
    return NextResponse.json({ message: 'Credenciais inválidas' }, { status: 401 })
  }

  const data = await upstream.json()

  const res = NextResponse.json({ username: data.username, status: data.status })

  res.cookies.set('zk_token', data.token, {
    httpOnly: true,   // JavaScript não lê
    sameSite: 'strict',
    path: '/',
    maxAge: 60 * 60 * 24,  // 24h — igual ao JWT_EXPIRATION do .env
  })

  return res
}
```

#### `src/app/api/auth/logout/route.ts`

```typescript
import { NextResponse } from 'next/server'

export async function POST() {
  const res = NextResponse.json({ ok: true })
  res.cookies.delete('zk_token')
  return res
}
```

#### `src/app/api/agents/route.ts`

```typescript
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

const SPRING = process.env.API_URL ?? 'http://localhost:8080'

export async function GET() {
  const token = (await cookies()).get('zk_token')?.value
  if (!token) return NextResponse.json(null, { status: 401 })

  const res = await fetch(`${SPRING}/api/c2-server/agents`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: 'no-store',
  })

  return NextResponse.json(await res.json(), { status: res.status })
}
```

#### `src/app/api/agents/[id]/route.ts`

```typescript
import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'

const SPRING = process.env.API_URL ?? 'http://localhost:8080'

async function handler(req: NextRequest, { params }: { params: { id: string } }) {
  const token = (await cookies()).get('zk_token')?.value
  if (!token) return NextResponse.json(null, { status: 401 })

  const res = await fetch(`${SPRING}/api/c2-server/agents/${params.id}`, {
    method: req.method,
    headers: { Authorization: `Bearer ${token}` },
    cache: 'no-store',
  })

  if (res.status === 204) return new NextResponse(null, { status: 204 })
  return NextResponse.json(await res.json(), { status: res.status })
}

export const GET    = handler
export const PUT    = handler
export const DELETE = handler
```

> **Dica:** para não repetir a lógica de `cookies + fetch + token` em cada
> arquivo, crie uma função utilitária em `src/lib/server/proxy.ts`:
> ```typescript
> export async function proxyTo(path: string, init?: RequestInit) {
>   const token = (await cookies()).get('zk_token')?.value
>   if (!token) return NextResponse.json(null, { status: 401 })
>   const res = await fetch(`${process.env.API_URL}${path}`, {
>     ...init,
>     headers: { Authorization: `Bearer ${token}` },
>     cache: 'no-store',
>   })
>   return NextResponse.json(await res.json(), { status: res.status })
> }
> ```

---

### ETAPA 5 — `lib/client/api.ts`

Substitui o `lib/api.ts` atual. Sem token, sem URL do Spring Boot.

```typescript
// Roda no browser — fala só com o Next.js

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers ?? {}),
    },
    credentials: 'include',  // envia o cookie automaticamente
  })

  if (res.status === 401) {
    // Sessão expirou — redireciona para login
    window.location.href = '/login'
    throw new Error('Não autorizado')
  }

  if (!res.ok) {
    const msg = await res.text().catch(() => `HTTP ${res.status}`)
    throw new Error(msg)
  }

  if (res.status === 204) return undefined as T
  return res.json()
}

export const auth = {
  login:  (username: string, password: string) =>
    req('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: async () => {
    await req('/api/auth/logout', { method: 'POST' })
    window.location.href = '/login'
  },
}

export const agentsApi = {
  list:   ()           => req<BackendAgentDto[]>('/api/agents'),
  get:    (id: string) => req<BackendAgentDto>(`/api/agents/${id}`),
  ping:   (id: string) => req<void>(`/api/agents/${id}/ping`,   { method: 'PUT' }),
  remove: (id: string) => req<void>(`/api/agents/${id}/delete`, { method: 'PUT' }),
}

export const c2Api = {
  info: () => req<C2ServerInfo>('/api/c2'),
}

export const usersApi = {
  list:          ()                                     => req<BackendUser[]>('/api/users'),
  roles:         ()                                     => req<BackendRole[]>('/api/users/roles'),
  create:        (body: CreateUserBody)                 => req<void>('/api/users',                  { method: 'POST',   body: JSON.stringify(body) }),
  delete:        (id: number)                           => req<void>(`/api/users/${id}`,             { method: 'DELETE' }),
  updateRole:    (id: number, roleName: string)         => req<BackendUser>(`/api/users/${id}/role`, { method: 'PUT',    body: JSON.stringify({ name: roleName }) }),
  resetPassword: (id: number, password: string)         => req<void>(`/api/users/${id}/password`,   { method: 'PUT',    body: JSON.stringify({ password }) }),
}
```

---

### ETAPA 6 — Atualizar os componentes

Nos componentes que usam `api.ts`, trocar o import:

```typescript
// ANTES
import { agentsApi, auth } from '@/lib/api'

// DEPOIS
import { agentsApi, auth } from '@/lib/client/api'
```

O `LoginPage` para de manipular token manualmente — o cookie é setado
automaticamente pelo `/api/auth/login`.

```typescript
// ANTES — LoginPage.tsx
const data = await auth.login(username, password)
localStorage.setItem('zk_token', data.token)  // ← remover isso

// DEPOIS — LoginPage.tsx
await auth.login(username, password)
// cookie já foi setado pelo Next.js — não precisa fazer mais nada
```

---

### ETAPA 7 — WebSocket do AgentShell

O WebSocket atual manda o token na URL:
```
ws://localhost:8080/term?token=eyJ...   ← URL e token expostos
```

A forma correta é usar uma API Route do Next.js que faz o upgrade para
WebSocket já autenticado. O Next.js 15 suporta isso nativamente:

```typescript
// src/app/api/shell/[id]/route.ts
import { cookies } from 'next/headers'

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const token = (await cookies()).get('zk_token')?.value
  if (!token) return new Response(null, { status: 401 })

  const { socket, response } = Reflect.get(req, Symbol.for('nextjs.request'))
    .upgrade()  // upgrade para WebSocket

  // Conecta ao Spring Boot com o token já validado
  const upstream = new WebSocket(
    `${process.env.API_WS_URL}/term/${params.id}`,
    { headers: { Authorization: `Bearer ${token}` } }
  )

  // Ponte bidirecional
  socket.on('message', (msg) => upstream.send(msg))
  upstream.on('message', (msg) => socket.send(msg))
  upstream.on('close',   ()    => socket.close())
  socket.on('close',    ()     => upstream.close())

  return response
}
```

No `AgentShell.tsx`, a URL do WebSocket vira:
```typescript
// ANTES
const ws = new WebSocket(`ws://localhost:8080/term?token=${token}`)

// DEPOIS
const ws = new WebSocket(`/api/shell/${agentId}`)
// sem token, sem URL do Spring Boot
```

> **Dica:** adicione `API_WS_URL` no `.env` separado do `API_URL`:
> ```bash
> API_URL=http://localhost:8080
> API_WS_URL=ws://localhost:8080
> ```

---

### ETAPA 8 — Headers de segurança no `next.config.js`

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          // Impede o site de ser carregado em iframe (clickjacking)
          { key: 'X-Frame-Options', value: 'DENY' },
          // Impede o browser de adivinhar o tipo de arquivo
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          // Não envia o endereço de origem em requisições externas
          { key: 'Referrer-Policy', value: 'no-referrer' },
          // Força HTTPS (ativar só quando tiver certificado)
          // { key: 'Strict-Transport-Security', value: 'max-age=63072000' },
        ],
      },
    ]
  },
}

module.exports = nextConfig
```

---

## Estrutura final de arquivos novos/modificados

```
src/
├── middleware.ts                          ← NOVO
├── app/
│   └── api/
│       ├── auth/
│       │   ├── login/route.ts             ← NOVO
│       │   └── logout/route.ts            ← NOVO
│       ├── agents/
│       │   ├── route.ts                   ← NOVO
│       │   └── [id]/route.ts              ← NOVO
│       ├── c2/route.ts                    ← NOVO
│       ├── users/route.ts                 ← NOVO
│       └── shell/[id]/route.ts            ← NOVO (WebSocket)
└── lib/
    ├── server/
    │   ├── api.ts                         ← NOVO
    │   └── proxy.ts                       ← NOVO (utilitário)
    └── client/
        └── api.ts                         ← substitui lib/api.ts
```

Arquivos modificados:
```
next.config.js                             ← adicionar headers
src/lib/api.ts                             ← deletar após migrar
src/components/layout/LoginPage.tsx        ← remover localStorage
src/components/shell/AgentShell.tsx        ← trocar URL do WebSocket
Todos os componentes que importam api.ts   ← trocar o import path
```

---

## O que o DevTools vai mostrar depois

```
ANTES                                   DEPOIS
──────────────────────────────────────────────────────────────
GET  http://localhost:8080/api/agents   GET  /api/agents
     Authorization: Bearer eyJ...            (sem header)
                                             Cookie: (httpOnly, invisível)

WS   ws://localhost:8080/term?token=eyJ WS   /api/shell/ZK-1
     (token na URL)                          (sem token visível)
```

---

## Dicas gerais

**Ordem de implementação sugerida:**
Faça nessa ordem para nunca quebrar o sistema no meio:

1. Cria `lib/client/api.ts` sem remover o `lib/api.ts` antigo ainda
2. Cria as API Routes uma por uma e testa cada endpoint no browser
3. Migra os componentes um a um para o novo `lib/client/api.ts`
4. Cria o `middleware.ts` por último — quando o login já estiver funcionando
5. Remove `lib/api.ts` quando todos os imports estiverem migrados

**Testando se o token não vaza:**
Abra o DevTools → Network → clique em qualquer request para `/api/agents`.
Não deve aparecer `Authorization` nos headers da requisição. O cookie
`zk_token` deve aparecer em Application → Cookies com a flag `HttpOnly`.

**Se o Spring Boot estiver em outro servidor:**
Adicione a URL real no `.env` de produção. A URL fica só no servidor Next.js —
nunca no browser:
```bash
# .env.production
API_URL=http://192.168.1.50:8080
API_WS_URL=ws://192.168.1.50:8080
```

**Sobre o `sameSite: 'strict'` do cookie:**
Significa que o cookie só é enviado em requisições que partem do mesmo site.
Protege contra CSRF. Se o dashboard e a API Next.js estiverem em domínios
diferentes, troque para `'lax'`.

**HTTPS em produção:**
Quando for usar com certificado TLS, adicione `secure: true` no cookie:
```typescript
res.cookies.set('zk_token', data.token, {
  httpOnly: true,
  sameSite: 'strict',
  secure: true,   // só envia em HTTPS
  path: '/',
  maxAge: 60 * 60 * 24,
})
```
E descomente o header `Strict-Transport-Security` no `next.config.js`.
