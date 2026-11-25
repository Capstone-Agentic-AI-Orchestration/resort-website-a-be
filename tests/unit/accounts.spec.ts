import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const originalDatabasePath = process.env.DATABASE_PATH;
let directory: string;
let closeDatabase = (): void => {};

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'accounts-data-'));
  process.env.DATABASE_PATH = join(directory, 'accounts.sqlite');
  jest.resetModules();
});

afterEach(() => {
  closeDatabase();
  closeDatabase = (): void => {};
  jest.resetModules();
  if (originalDatabasePath === undefined) delete process.env.DATABASE_PATH;
  else process.env.DATABASE_PATH = originalDatabasePath;
  rmSync(directory, { recursive: true, force: true });
});

describe('account and session storage', () => {
  it('stores and finds users by case-insensitive email', () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { createUser, findUserByEmail, closeAccountDatabase } = require('../../src/data/accounts') as typeof import('../../src/data/accounts');
    closeDatabase = closeAccountDatabase;
    const user = { id: 'u1', email: 'Guest@example.com', passwordHash: 'hash', passwordSalt: 'salt' };
    expect(createUser(user)).toEqual(user);
    expect(findUserByEmail('guest@EXAMPLE.com')).toEqual(user);
  });

  it('stores, finds, and deletes sessions', () => {
    const { createUser, createSession, findSessionByTokenHash, deleteSession, closeAccountDatabase } =
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      require('../../src/data/accounts') as typeof import('../../src/data/accounts');
    closeDatabase = closeAccountDatabase;
    createUser({ id: 'u1', email: 'guest@example.com', passwordHash: 'hash', passwordSalt: 'salt' });
    const session = { id: 's1', userId: 'u1', tokenHash: 'token-digest', expiresAt: 1_900_000_000 };
    expect(createSession(session)).toEqual(session);
    expect(findSessionByTokenHash('token-digest')).toEqual(session);
    expect(deleteSession('s1')).toBe(true);
    expect(deleteSession('s1')).toBe(false);
    expect(findSessionByTokenHash('token-digest')).toBeUndefined();
  });
});
