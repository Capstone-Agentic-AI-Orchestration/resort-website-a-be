import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { app } from '../../src/app';
import { closeAccountDatabase } from '../../src/data/accounts';

let directory: string;
const originalDatabasePath = process.env.DATABASE_PATH;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'auth-api-'));
  process.env.DATABASE_PATH = join(directory, 'accounts.sqlite');
});

afterEach(() => {
  closeAccountDatabase();
  if (originalDatabasePath === undefined) delete process.env.DATABASE_PATH;
  else process.env.DATABASE_PATH = originalDatabasePath;
  rmSync(directory, { recursive: true, force: true });
});

function expectSessionCookie(response: request.Response): string {
  const cookie = response.headers['set-cookie']?.[0];
  expect(cookie).toContain('session=');
  expect(cookie).toContain('HttpOnly');
  return cookie;
}

describe('account authentication API', () => {
  it('signs up with a persisted user and an HttpOnly session cookie', async () => {
    const response = await request(app).post('/api/auth/signup')
      .send({ email: 'guest@example.com', password: 'correct-horse' });

    expect(response.status).toBe(201);
    expect(response.body.user).toEqual({ id: expect.any(String), email: 'guest@example.com' });
    const cookie = expectSessionCookie(response);
    expect(cookie).not.toContain('password');
  });

  it('logs in with valid credentials and issues a session cookie', async () => {
    await request(app).post('/api/auth/signup')
      .send({ email: 'guest@example.com', password: 'correct-horse' });

    const response = await request(app).post('/api/auth/login')
      .send({ email: 'GUEST@example.com', password: 'correct-horse' });

    expect(response.status).toBe(200);
    expect(response.body.user).toEqual({ id: expect.any(String), email: 'guest@example.com' });
    expectSessionCookie(response);
  });

  it.each([
    [{ email: 'invalid', password: 'correct-horse' }],
    [{ email: 'guest@example.com', password: 'short' }],
    ['null'],
  ])('rejects invalid signup input safely', async body => {
    const response = await request(app).post('/api/auth/signup')
        .set('Content-Type', 'application/json')
        .send(body);
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: expect.any(String) });
    expect(response.headers['set-cookie']).toBeUndefined();
  });

  it('returns a generic error for incorrect credentials', async () => {
    await request(app).post('/api/auth/signup')
      .send({ email: 'guest@example.com', password: 'correct-horse' });

    const response = await request(app).post('/api/auth/login')
      .send({ email: 'guest@example.com', password: 'wrong-password' });

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: 'Invalid email or password.' });
    expect(JSON.stringify(response.body)).not.toContain('wrong-password');
    expect(response.headers['set-cookie']).toBeUndefined();
  });
});
