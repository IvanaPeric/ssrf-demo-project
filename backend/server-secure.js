import express from 'express';
import { validateAndFetch, handleValidationError, registerSecureRoute } from './secure_route.js';

const app = express();
const port = process.env.PORT || 4000;

app.use(express.json());

app.get('/', (_req, res) => {
  res.json({ message: 'SSRF demo SECURE server running' });
});

app.get('/aws-metadata/latest/meta-data/iam/security-credentials', (_req, res) => {
  res.json({
    AccessKeyId: 'FAKEACCESSKEY',
    SecretAccessKey: 'FAKESECRET',
    Token: 'FAKETOKEN',
    Expiration: '2026-12-31T23:59:59Z',
  });
});

// Secure GET /fetch endpoint (for comparison with vulnerable version)
app.get('/fetch', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    res.status(400).json({ error: 'url query param required' });
    return;
  }

  try {
    const result = await validateAndFetch(url, '/fetch');
    res.status(result.status).send(result.body);
  } catch (err) {
    handleValidationError(err, res);
  }
});

// Register secure POST /fetch-secure endpoint
registerSecureRoute(app);

app.listen(port, () => {
  console.log(`Secure server listening on port ${port}`);
});
