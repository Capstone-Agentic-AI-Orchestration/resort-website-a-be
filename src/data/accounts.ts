import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  passwordSalt: string;
}

export interface SessionRecord {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: number;
}

let database: Database.Database | undefined;
let databasePath: string | undefined;

function getDatabase(): Database.Database {
  const configuredPath = process.env.DATABASE_PATH ?? './data/accounts.sqlite';
  const path = configuredPath === ':memory:' ? configuredPath : resolve(configuredPath);
  if (database && databasePath === path) return database;
  if (database) database.close();

  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  database = new Database(path);
  database.pragma('foreign_keys = ON');
  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL COLLATE NOCASE UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
  `);
  databasePath = path;
  return database;
}

export function closeAccountDatabase(): void {
  database?.close();
  database = undefined;
  databasePath = undefined;
}

export function createUser(user: UserRecord): UserRecord {
  getDatabase().prepare(
    'INSERT INTO users (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)',
  ).run(user.id, user.email, user.passwordHash, user.passwordSalt);
  return user;
}

export function findUserByEmail(email: string): UserRecord | undefined {
  return getDatabase().prepare(
    'SELECT id, email, password_hash AS passwordHash, password_salt AS passwordSalt FROM users WHERE email = ?',
  ).get(email) as UserRecord | undefined;
}

export function createSession(session: SessionRecord): SessionRecord {
  getDatabase().prepare(
    'INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)',
  ).run(session.id, session.userId, session.tokenHash, session.expiresAt);
  return session;
}

export function findSessionByTokenHash(tokenHash: string): SessionRecord | undefined {
  return getDatabase().prepare(
    'SELECT id, user_id AS userId, token_hash AS tokenHash, expires_at AS expiresAt FROM sessions WHERE token_hash = ?',
  ).get(tokenHash) as SessionRecord | undefined;
}

export function deleteSession(id: string): boolean {
  return getDatabase().prepare('DELETE FROM sessions WHERE id = ?').run(id).changes > 0;
}
