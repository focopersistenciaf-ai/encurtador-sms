const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const dns = require('dns');
const cookieParser = require('cookie-parser');
const { MongoClient } = require('mongodb');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

const MONGODB_URI = process.env.MONGODB_URI || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
const VERCEL_TOKEN = process.env.VERCEL_TOKEN || '';
const VERCEL_PROJECT_ID = process.env.VERCEL_PROJECT_ID || '';
const VERCEL_TEAM_ID = process.env.VERCEL_TEAM_ID || '';

const DB_NAME = 'encurtador';
const COLLECTION = 'links';
const DATA_FILE = path.join(__dirname, 'data', 'links.json');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

let mongoClient = null;

async function getCollection() {
  if (MONGODB_URI) {
    if (!mongoClient) {
      mongoClient = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
      await mongoClient.connect();
    }
    return mongoClient.db(DB_NAME).collection(COLLECTION);
  }
  return null;
}

async function getLinks() {
  const col = await getCollection();
  if (col) {
    const docs = await col.find({}).toArray();
    const links = {};
    for (const doc of docs) {
      links[doc.code] = { url: doc.url, clicks: doc.clicks, createdAt: doc.createdAt };
    }
    return links;
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return {};
  }
}

async function setLink(code, data) {
  const col = await getCollection();
  if (col) {
    await col.updateOne({ code }, { $set: { code, ...data } }, { upsert: true });
    return;
  }
  const links = await getLinks();
  links[code] = data;
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(links, null, 2));
}

async function deleteLink(code) {
  const col = await getCollection();
  if (col) {
    await col.deleteOne({ code });
    return;
  }
  const links = await getLinks();
  delete links[code];
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(links, null, 2));
}

function generateCode(length = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  return Array.from(crypto.randomBytes(length))
    .map((b) => chars[b % chars.length])
    .join('');
}

function validUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function validCode(code) {
  return /^[a-zA-Z0-9_-]{2,30}$/.test(code);
}

const RESERVED = ['api', 'admin', 'stats', 'favicon.ico', 'robots.txt'];

function createToken() {
  const payload = JSON.stringify({ exp: Date.now() + 7 * 24 * 3600 * 1000 });
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return Buffer.from(payload).toString('base64url') + '.' + sig;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return false;
  const [payloadB64, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SECRET).update(Buffer.from(payloadB64, 'base64url').toString()).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    return payload.exp > Date.now();
  } catch {
    return false;
  }
}

function requireAuth(req, res, next) {
  const token = req.cookies ? req.cookies.admin_token : null;
  if (verifyToken(token)) return next();
  return res.status(401).json({ error: 'Não autorizado. Faça login.' });
}

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/:code', async (req, res) => {
  const code = req.params.code;
  if (RESERVED.includes(code.toLowerCase())) {
    return res.redirect('/');
  }

  const links = await getLinks();
  const link = links[code];

  if (!link) {
    return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }

  await setLink(code, { ...link, clicks: link.clicks + 1 });

  res.redirect(301, link.url);
});

app.post('/api/shorten', async (req, res) => {
  const url = (req.body.url || '').trim();
  const customCode = (req.body.code || '').trim();

  if (!validUrl(url)) {
    return res.status(400).json({ error: 'Informe uma URL válida (com http:// ou https://)' });
  }

  const links = await getLinks();

  let code;
  if (customCode) {
    if (!validCode(customCode)) {
      return res.status(400).json({ error: 'Código inválido. Use de 2 a 30 letras, números, hífen ou _' });
    }
    if (RESERVED.includes(customCode.toLowerCase())) {
      return res.status(400).json({ error: 'Esse código é reservado. Escolha outro.' });
    }
    if (links[customCode]) {
      return res.status(409).json({ error: 'Esse código já está em uso. Escolha outro.' });
    }
    code = customCode;
  } else {
    do {
      code = generateCode();
    } while (links[code]);
  }

  await setLink(code, { url, clicks: 0, createdAt: new Date().toISOString() });

  const base = `${req.protocol}://${req.get('host')}`;
  res.json({ shortUrl: `${base}/${code}`, code });
});

app.post('/api/admin/login', (req, res) => {
  const password = (req.body.password || '').trim();
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Senha incorreta.' });
  }
  const token = createToken();
  res.setHeader('Set-Cookie', `admin_token=${token}; HttpOnly; Path=/; Max-Age=${7 * 24 * 3600}; SameSite=Lax`);
  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'admin_token=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/admin/links', requireAuth, async (req, res) => {
  const links = await getLinks();
  const list = Object.entries(links).map(([code, data]) => ({ code, ...data }));
  list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

app.patch('/api/admin/links/:code', requireAuth, async (req, res) => {
  const links = await getLinks();
  const link = links[req.params.code];

  if (!link) {
    return res.status(404).json({ error: 'Link não encontrado' });
  }

  const newCode = (req.body.code || '').trim();
  const newUrl = (req.body.url || '').trim();

  if (newUrl && !validUrl(newUrl)) {
    return res.status(400).json({ error: 'Informe uma URL válida (com http:// ou https://)' });
  }
  if (newCode && !validCode(newCode)) {
    return res.status(400).json({ error: 'Código inválido. Use de 2 a 30 letras, números, hífen ou _' });
  }
  if (newCode && RESERVED.includes(newCode.toLowerCase())) {
    return res.status(400).json({ error: 'Esse código é reservado. Escolha outro.' });
  }
  if (newCode && newCode !== req.params.code && links[newCode]) {
    return res.status(409).json({ error: 'Esse código já está em uso. Escolha outro.' });
  }

  const updated = { ...link };
  if (newUrl) updated.url = newUrl;
  await deleteLink(req.params.code);
  await setLink(newCode || req.params.code, updated);

  const base = `${req.protocol}://${req.get('host')}`;
  res.json({ shortUrl: `${base}/${newCode || req.params.code}`, code: newCode || req.params.code });
});

app.delete('/api/admin/links/:code', requireAuth, async (req, res) => {
  const links = await getLinks();
  if (!links[req.params.code]) {
    return res.status(404).json({ error: 'Link não encontrado' });
  }
  await deleteLink(req.params.code);
  res.json({ ok: true });
});

function vercelApi(path, options = {}) {
  const url = 'https://api.vercel.com' + path;
  const teamQuery = VERCEL_TEAM_ID ? (url.includes('?') ? '&' : '?') + 'teamId=' + VERCEL_TEAM_ID : '';
  return fetch(url + teamQuery, {
    ...options,
    headers: {
      Authorization: 'Bearer ' + VERCEL_TOKEN,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
}

app.get('/api/admin/site-status', requireAuth, async (req, res) => {
  if (!VERCEL_TOKEN || !VERCEL_PROJECT_ID) {
    return res.json({ configured: false, domain: req.get('host') });
  }
  try {
    const proj = await vercelApi('/v9/projects/' + VERCEL_PROJECT_ID);
    const pj = await proj.json();
    const doms = await vercelApi('/v9/projects/' + VERCEL_PROJECT_ID + '/domains');
    const dj = await doms.json();
    const vercelDomain = (dj.domains || []).map((d) => d.name).find((n) => n.endsWith('.vercel.app')) || '';
    const lastDeploy = (pj.latestDeployments || []).find((d) => d.target === 'production');
    res.json({
      configured: true,
      projectName: pj.name,
      domain: vercelDomain || req.get('host'),
      deployStatus: lastDeploy ? lastDeploy.readyState : 'unknown'
    });
  } catch (e) {
    res.json({ configured: true, domain: req.get('host'), projectName: '', deployStatus: 'unknown' });
  }
});

app.post('/api/admin/site-rename', requireAuth, async (req, res) => {
  if (!VERCEL_TOKEN || !VERCEL_PROJECT_ID) {
    return res.status(400).json({ error: 'Chave da Vercel não configurada. Peça ajuda para configurar.' });
  }

  const name = (req.body.name || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{2,40}$/.test(name)) {
    return res.status(400).json({ error: 'Nome inválido. Use de 3 a 40 letras minúsculas, números e hífen.' });
  }

  try {
    await dns.promises.resolve(name + '.vercel.app');
    return res.status(409).json({ error: 'O nome "' + name + '" já está em uso na Vercel. Escolha outro.' });
  } catch (e) {
    if (e.code !== 'ENOTFOUND') {
      return res.status(502).json({ error: 'Erro ao verificar disponibilidade. Tente novamente.' });
    }
  }

  try {
    const current = await vercelApi('/v9/projects/' + VERCEL_PROJECT_ID);
    const cj = await current.json();
    const oldDomain = req.get('host');

    const upd = await vercelApi('/v9/projects/' + VERCEL_PROJECT_ID, {
      method: 'PATCH',
      body: JSON.stringify({ name })
    });
    if (!upd.ok) {
      const err = await upd.json().catch(() => ({}));
      return res.status(upd.status).json({ error: err.error?.message || 'Erro ao renomear o projeto.' });
    }

    if (oldDomain.endsWith('.vercel.app') && oldDomain !== name + '.vercel.app') {
      await vercelApi('/v9/projects/' + VERCEL_PROJECT_ID + '/domains/' + oldDomain, { method: 'DELETE' });
      const add = await vercelApi('/v10/projects/' + VERCEL_PROJECT_ID + '/domains', {
        method: 'POST',
        body: JSON.stringify({ name: name + '.vercel.app' })
      });
      if (!add.ok) {
        const err = await add.json().catch(() => ({}));
        return res.status(add.status).json({ error: 'Renomeado, mas falha ao trocar domínio: ' + (err.error?.message || 'desconhecido') });
      }
    }

    res.json({ newUrl: 'https://' + name + '.vercel.app', name });
  } catch (e) {
    res.status(502).json({ error: 'Erro ao comunicar com a Vercel. Tente novamente.' });
  }
});

app.get('/api/admin/domain-check', requireAuth, async (req, res) => {
  const domain = (req.query.domain || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$/.test(domain)) {
    return res.status(400).json({ error: 'Digite um domínio válido (ex.: resgate.com.br)' });
  }

  const tld = domain.slice(domain.indexOf('.') + 1);
  const rdapServers = {
    'com.br': 'https://rdap.registro.br/domain/',
    'net.br': 'https://rdap.registro.br/domain/',
    'org.br': 'https://rdap.registro.br/domain/',
    'com': 'https://rdap.verisign.com/com/v1/domain/',
    'net': 'https://rdap.verisign.com/net/v1/domain/',
    'org': 'https://rdap.pir.org/domain/'
  };

  const base = rdapServers[tld];
  if (!base) {
    return res.status(400).json({ error: `Não consigo verificar domínios .${tld}. Use .com.br ou .com` });
  }

  try {
    const r = await fetch(base + domain);
    if (r.status === 404) {
      return res.json({ domain, available: true });
    }
    if (r.ok) {
      return res.json({ domain, available: false });
    }
    return res.status(502).json({ error: 'Erro ao consultar o registro. Tente novamente em instantes.' });
  } catch {
    return res.status(502).json({ error: 'Erro ao consultar o registro. Tente novamente em instantes.' });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
  });
}

module.exports = app;
