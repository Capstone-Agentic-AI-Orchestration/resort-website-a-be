import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import type { Request, Response } from 'express';
import { createSession, createUser, findUserByEmail } from './data/accounts.js';

const scrypt = promisify(scryptCallback);
const SESSION_COOKIE = 'session';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const PASSWORD_BYTES = 64;

interface CredentialsBody {
  email: string;
  password: string;
}

interface UntrustedCredentialsBody {
  email?: unknown;
  password?: unknown;
}

function isEmail(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isPassword(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 8 && value.length <= 1024;
}

async function hashPassword(password: string, salt: string): Promise<string> {
  const hash = await scrypt(password, salt, PASSWORD_BYTES) as Buffer;
  return hash.toString('hex');
}

function setSessionCookie(response: Response, token: string): void {
  const options = [
    `${SESSION_COOKIE}=${token}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (process.env.NODE_ENV === 'production') options.push('Secure');
  response.append('Set-Cookie', options.join('; '));
}

function credentials(req: Request, res: Response): CredentialsBody | undefined {
  const body: unknown = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    res.status(400).json({ error: 'Email and password are required.' });
    return undefined;
  }
  const { email, password } = body as UntrustedCredentialsBody;
  if (!isEmail(email) || !isPassword(password)) {
    res.status(400).json({ error: 'Enter a valid email and a password of at least 8 characters.' });
    return undefined;
  }
  return { email: email.trim().toLowerCase(), password };
}

async function issueSession(userId: string, response: Response): Promise<void> {
  const token = randomBytes(32).toString('base64url');
  const tokenHash = createHash('sha256').update(token).digest('hex');
  createSession({
    id: randomUUID(),
    userId,
    tokenHash,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  setSessionCookie(response, token);
}

export async function signup(req: Request, res: Response): Promise<void> {
  const input = credentials(req, res);
  if (!input) return;
  const salt = randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(input.password, salt);
  try {
    const user = createUser({
      id: randomUUID(),
      email: input.email,
      passwordHash,
      passwordSalt: salt,
    });
    await issueSession(user.id, res);
    res.status(201).json({ user: { id: user.id, email: user.email } });
  } catch {
    res.status(409).json({ error: 'An account with that email already exists.' });
  }
}

export async function login(req: Request, res: Response): Promise<void> {
  const input = credentials(req, res);
  if (!input) return;
  const user = findUserByEmail(input.email);
  const salt = user?.passwordSalt ?? randomBytes(16).toString('hex');
  const actual = Buffer.from(await hashPassword(input.password, salt), 'hex');
  const expected = Buffer.from(user?.passwordHash ?? Buffer.alloc(PASSWORD_BYTES).toString('hex'), 'hex');
  const valid = actual.length === expected.length && timingSafeEqual(actual, expected);
  if (!user || !valid) {
    res.status(401).json({ error: 'Invalid email or password.' });
    return;
  }
  await issueSession(user.id, res);
  res.json({ user: { id: user.id, email: user.email } });
}
