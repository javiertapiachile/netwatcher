// src/db/database.js
// Capa de datos: inicialización SQLite — Fase 1 + Fase 2

const sqlite3 = require('sqlite3').verbose();
const path    = require('path');
const fs      = require('fs');

const DB_PATH = process.env.DB_PATH || './data/netwatch.db';

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) { console.error('[DB] Error:', err.message); process.exit(1); }
  console.log(`[DB] SQLite en: ${path.resolve(DB_PATH)}`);
});

// ── Helpers async ─────────────────────────────────────────────
db.runAsync = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err); else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });

db.getAsync  = (sql, params = []) =>
  new Promise((resolve, reject) =>
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row || null)));

db.allAsync  = (sql, params = []) =>
  new Promise((resolve, reject) =>
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows || [])));

db.execAsync = (sql) =>
  new Promise((resolve, reject) =>
    db.exec(sql, (err) => err ? reject(err) : resolve()));

// ── Schema ────────────────────────────────────────────────────
const initSchema = async () => {
  await db.runAsync('PRAGMA journal_mode = WAL');
  await db.runAsync('PRAGMA foreign_keys = ON');

  await db.execAsync(`
    -- Fase 1: conexiones capturadas
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

    -- Fase 1: caché DNS
    CREATE TABLE IF NOT EXISTS dns_cache (
      ip           TEXT PRIMARY KEY,
      fqdn         TEXT,
      resolved_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      ttl_seconds  INTEGER NOT NULL DEFAULT 300,
      is_private   INTEGER NOT NULL DEFAULT 0
    );

    -- Fase 2: caché de geolocalización
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

    -- Fase 2: caché de reputación
    CREATE TABLE IF NOT EXISTS reputation_cache (
      ip             TEXT PRIMARY KEY,
      score          TEXT NOT NULL DEFAULT 'CLEAN',
      reasons        TEXT,
      blocklist_hits TEXT,
      service_name   TEXT,
      service_type   TEXT,
      checked_at     TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Fase 2: log de alertas
    CREATE TABLE IF NOT EXISTS alerts (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      ip           TEXT NOT NULL,
      rule         TEXT NOT NULL,
      severity     TEXT NOT NULL DEFAULT 'medium',
      details      TEXT,
      acknowledged INTEGER NOT NULL DEFAULT 0
    );

    -- Fase 2: IPs conocidas (whitelist/blacklist manual del usuario)
    CREATE TABLE IF NOT EXISTS ip_notes (
      ip        TEXT PRIMARY KEY,
      label     TEXT,
      list_type TEXT NOT NULL DEFAULT 'whitelist',
      notes     TEXT,
      added_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Índices
    CREATE INDEX IF NOT EXISTS idx_connections_captured_at ON connections(captured_at DESC);
    CREATE INDEX IF NOT EXISTS idx_connections_remote_addr ON connections(remote_addr);
    CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
  `);
};

const ready = initSchema().catch(err => {
  console.error('[DB] Error inicializando schema:', err.message);
  process.exit(1);
});

module.exports = { db, ready };
