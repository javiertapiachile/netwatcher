// src/db/database.js — Fase 3: schema completo

const sqlite3 = require('sqlite3').verbose();
const path    = require('path');
const fs      = require('fs');

const DB_PATH = process.env.DB_PATH || './data/netwatch.db';
const dbDir   = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new sqlite3.Database(DB_PATH, err => {
  if (err) { console.error('[DB] Error:', err.message); process.exit(1); }
  console.log(`[DB] SQLite en: ${path.resolve(DB_PATH)}`);
});

db.runAsync = (sql, p=[]) => new Promise((res,rej) => db.run(sql,p,function(e){e?rej(e):res({lastID:this.lastID,changes:this.changes})}));
db.getAsync = (sql, p=[]) => new Promise((res,rej) => db.get(sql,p,(e,r)=>e?rej(e):res(r||null)));
db.allAsync = (sql, p=[]) => new Promise((res,rej) => db.all(sql,p,(e,r)=>e?rej(e):res(r||[])));
db.execAsync = sql        => new Promise((res,rej) => db.exec(sql,e=>e?rej(e):res()));

const initSchema = async () => {
  await db.runAsync('PRAGMA journal_mode = WAL');
  await db.runAsync('PRAGMA foreign_keys = ON');

  await db.execAsync(`
    -- Fase 1
    CREATE TABLE IF NOT EXISTS connections (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      captured_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      protocol     TEXT    NOT NULL,
      local_addr   TEXT    NOT NULL,
      local_port   INTEGER NOT NULL,
      remote_addr  TEXT    NOT NULL,
      remote_port  INTEGER NOT NULL,
      state        TEXT,
      pid          INTEGER,
      process_name TEXT
    );

    CREATE TABLE IF NOT EXISTS dns_cache (
      ip           TEXT PRIMARY KEY,
      fqdn         TEXT,
      resolved_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      ttl_seconds  INTEGER NOT NULL DEFAULT 300,
      is_private   INTEGER NOT NULL DEFAULT 0
    );

    -- Fase 2
    CREATE TABLE IF NOT EXISTS geo_cache (
      ip           TEXT PRIMARY KEY,
      country      TEXT,
      country_code TEXT,
      region       TEXT,
      city         TEXT,
      isp          TEXT,
      org          TEXT,
      as_number    TEXT,
      lat          REAL,
      lon          REAL,
      is_proxy     INTEGER DEFAULT 0,
      is_hosting   INTEGER DEFAULT 0,
      cached_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS reputation_cache (
      ip             TEXT PRIMARY KEY,
      score          TEXT NOT NULL DEFAULT 'CLEAN',
      reasons        TEXT,
      blocklist_hits TEXT,
      service_name   TEXT,
      service_type   TEXT,
      checked_at     TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      ip           TEXT NOT NULL,
      rule         TEXT NOT NULL,
      severity     TEXT NOT NULL DEFAULT 'medium',
      details      TEXT,
      acknowledged INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS blocked_ips (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      ip           TEXT NOT NULL,
      port         INTEGER,
      pid          INTEGER,
      rule_name    TEXT,
      is_system    INTEGER NOT NULL DEFAULT 0,
      blocked_at   TEXT NOT NULL DEFAULT (datetime('now')),
      unblocked_at TEXT,
      status       TEXT NOT NULL DEFAULT 'active',
      notes        TEXT
    );

    -- Fase 3: usuarios
    CREATE TABLE IF NOT EXISTS users (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      username     TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role         TEXT NOT NULL DEFAULT 'viewer',
      is_master    INTEGER NOT NULL DEFAULT 0,
      last_login   TEXT,
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      is_active    INTEGER NOT NULL DEFAULT 1
    );

    -- Fase 3: sesiones activas
    CREATE TABLE IF NOT EXISTS sessions (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      INTEGER NOT NULL,
      token_hash   TEXT NOT NULL UNIQUE,
      ip_addr      TEXT,
      user_agent   TEXT,
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at   TEXT NOT NULL,
      revoked      INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    -- Fase 3: log de auditoría
    CREATE TABLE IF NOT EXISTS audit_log (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      user_id      INTEGER,
      username     TEXT,
      action       TEXT NOT NULL,
      resource     TEXT,
      ip_addr      TEXT,
      success      INTEGER NOT NULL DEFAULT 1,
      details      TEXT
    );

    -- Fase 3: reglas de sistema protegidas
    CREATE TABLE IF NOT EXISTS system_rules (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      rule_name    TEXT NOT NULL UNIQUE,
      description  TEXT,
      port         INTEGER,
      direction    TEXT,
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      is_active    INTEGER NOT NULL DEFAULT 1
    );

    -- Índices
    CREATE INDEX IF NOT EXISTS idx_connections_captured_at ON connections(captured_at DESC);
    CREATE INDEX IF NOT EXISTS idx_connections_remote_addr ON connections(remote_addr);
    CREATE INDEX IF NOT EXISTS idx_alerts_created_at       ON alerts(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_log_created_at    ON audit_log(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sessions_token          ON sessions(token_hash);
    CREATE INDEX IF NOT EXISTS idx_sessions_user           ON sessions(user_id);
  `);
};

const ready = initSchema().catch(err => {
  console.error('[DB] Error inicializando schema:', err.message);
  process.exit(1);
});

module.exports = { db, ready };
