# Encurtador de Links para SMS

Encurtador de links profissional para envio por SMS, com painel de gestão protegido por senha.

## Recursos

- 🔗 Criação de links curtos com código personalizado ou aleatório
- 📊 Painel admin com senha: criar, renomear, editar e excluir links
- 👆 Contador de cliques por link
- 🗄️ Armazenamento no MongoDB Atlas (grátis) — links nunca somem
- ⚡ Deploy serverless na Vercel (grátis)
- 📱 Redirecionamento 301, ideal para SMS

## Como rodar localmente

```bash
npm install
npm start
```

- Página pública: http://localhost:3000
- Painel admin: http://localhost:3000/admin (senha padrão: `admin123`)

## Variáveis de ambiente

Copie `.env.example` para `.env` e configure:

| Variável | Descrição |
|---|---|
| `MONGODB_URI` | String de conexão do MongoDB Atlas |
| `ADMIN_PASSWORD` | Senha do painel admin |
| `SECRET` | Chave aleatória para os cookies de login |

Sem `MONGODB_URI`, o sistema usa arquivo `data/links.json` (modo local).

## Deploy na Vercel

1. Suba o projeto no GitHub
2. Na Vercel: **Add New Project** → importe o repositório
3. Adicione as variáveis de ambiente acima em Settings → Environment Variables
4. Deploy!

## API

- `POST /api/shorten` — `{"url": "...", "code": "opcional"}` → `{"shortUrl": "..."}`
- `GET /:code` — redireciona para o link original
- `POST /api/admin/login` — `{"password": "..."}`
- `GET /api/admin/links` — lista todos os links (requer login)
- `PATCH /api/admin/links/:code` — renomeia/edita (requer login)
- `DELETE /api/admin/links/:code` — exclui (requer login)

## Dica para SMS

Para as operadoras não bloquearem seus links, o ideal é usar um **domínio próprio** com HTTPS. Na Vercel, é só adicionar seu domínio em Settings → Domains. O domínio gratuito (`*.vercel.app`) funciona, mas domínio próprio tem entrega muito melhor.
