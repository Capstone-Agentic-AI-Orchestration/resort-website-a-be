import cors from 'cors';
import express from 'express';
import type { Express } from 'express';
import { login, signup } from './auth.js';

export const SERVICE_NAME = 'resort-website-a-be';

/** Origins allowed to call this API, from the comma-separated CORS_ORIGINS. */
function corsOrigins(): string[] {
  return (process.env.CORS_ORIGINS ?? '')
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);
}

export const app: Express = express();

app.use(cors({ origin: corsOrigins() }));
app.use(express.json());

app.post('/api/auth/signup', (req, res, next) => {
  void signup(req, res).catch(next);
});
app.post('/api/auth/login', (req, res, next) => {
  void login(req, res).catch(next);
});

// What Render polls, and how anything else knows the service is up.
app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use((error: unknown, _req: express.Request, res: express.Response, next: express.NextFunction) => {
  void next;
  const status = typeof error === 'object' && error !== null && 'status' in error && error.status === 400
    ? 400
    : 500;
  res.status(status).json({ error: status === 400 ? 'Invalid JSON request body.' : 'Request could not be completed.' });
});
