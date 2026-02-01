import express from 'express';
import { logSsrfAttempt } from './logger.js';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.get('/', (_req, res) => {
  res.json({ message: 'SSRF demo VULNERABLE server running' });
});

app.get('/aws-metadata/latest/meta-data/iam/security-credentials', (_req, res) => {
  res.json({
    AccessKeyId: 'FAKEACCESSKEY',
    SecretAccessKey: 'FAKESECRET',
    Token: 'FAKETOKEN',
    Expiration: '2026-12-31T23:59:59Z',
  });
});

app.get('/fetch', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    res.status(400).json({ error: 'url query param required' });
    return;
  }

  try {
    const upstream = await fetch(url);
    const body = await upstream.text();
    logSsrfAttempt({ endpoint: '/fetch', url, status: upstream.status });
    res.status(upstream.status).send(body);
  } catch (err) {
    logSsrfAttempt({ endpoint: '/fetch', url, status: 'error', reason: err.message });
    res.status(500).json({ error: 'fetch failed' });
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
