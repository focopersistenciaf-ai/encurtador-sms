# Encurtador de Links para SMS

Encurtador de links simples em Node.js + Express, ideal para enviar links curtos por SMS.

## Como rodar

```bash
npm install
npm start
```

Abra http://localhost:3000 no navegador, cole o link e clique em **Encurtar link**.

## Como funciona

- `GET /` — página para criar links curtos
- `POST /api/shorten` — recebe `{"url": "https://..."}` e devolve `{"shortUrl": "..."}`
- `GET /:codigo` — redireciona (301) para o link original e conta os cliques
- `GET /api/stats/:codigo` — mostra cliques e data de criação

Os links ficam salvos em `data/links.json` (arquivo criado automaticamente).

## Dica para SMS (importante)

Para as operadoras não bloquearem seu link, o ideal é usar um **domínio próprio** (ex.: `https://seulink.com/abc123`) com HTTPS ativo. Links de domínios de encurtadores conhecidos (bit.ly, etc.) costumam ser bloqueados pelas operadoras.

### Hospedagem gratuita com domínio próprio

1. Compre um domínio curto e barato (ex.: em Registro.br ou Namecheap)
2. Hospede de graça no **Render.com** ou **Railway.app** (basta enviar esta pasta para o GitHub e conectar)
3. Aponte o domínio para o serviço e ative o HTTPS

## Usando via API (sem a página)

```bash
curl -X POST http://localhost:3000/api/shorten -H "Content-Type: application/json" -d "{\"url\":\"https://seusite.com/pagina\"}"
```
