const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'links.json');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function loadLinks() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function saveLinks(links) {
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

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/shorten', (req, res) => {
  const url = (req.body.url || '').trim();

  if (!validUrl(url)) {
    return res.status(400).json({ error: 'Informe uma URL válida (com http:// ou https://)' });
  }

  const links = loadLinks();
  const code = generateCode();
  links[code] = { url, clicks: 0, createdAt: new Date().toISOString() };
  saveLinks(links);

  const base = `${req.protocol}://${req.get('host')}`;
  res.json({ shortUrl: `${base}/${code}`, code });
});

app.get('/:code', (req, res) => {
  const links = loadLinks();
  const link = links[req.params.code];

  if (!link) {
    return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }

  link.clicks += 1;
  saveLinks(links);

  res.redirect(301, link.url);
});

app.get('/api/stats/:code', (req, res) => {
  const links = loadLinks();
  const link = links[req.params.code];

  if (!link) {
    return res.status(404).json({ error: 'Link não encontrado' });
  }

  res.json({ url: link.url, clicks: link.clicks, createdAt: link.createdAt });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
