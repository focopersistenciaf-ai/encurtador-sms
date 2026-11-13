const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const { MongoClient } = require('mongodb');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

const MONGODB_URI = process.env.MONGODB_URI || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');

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

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
  });
}

module.exports = app;
