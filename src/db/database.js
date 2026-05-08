// src/db/database.js
// Capa de datos: inicialización de SQLite y schema
// Usa sqlite3 (binarios precompilados, sin compilación nativa)

const sqlite3 = require('sqlite3').verbose();
const path    = require('path');
const fs      = require('fs');

const DB_PATH = process.env.DB_PATH || './data/netwatch.db';

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('[DB] Error abriendo base de datos:', err.message);
    process.exit(1);
  }
  console.log(`[DB] SQLite inicializado en: ${path.resolve(DB_PATH)}`);
});

// Helpers para promisificar sqlite3 (que es callback-based)
db.runAsync = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });

db.getAsync = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row || null);
    });
  });

db.allAsync = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });

db.execAsync = (sql) =>
  new Promise((resolve, reject) => {
    db.exec(sql, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });

// Inicializar schema
const initSchema = async () => {
  // WAL mode: mejor performance en lecturas/escrituras concurrentes
  await db.runAsync('PRAGMA journal_mode = WAL');
  await db.runAsync('PRAGMA foreign_keys = ON');

  await db.execAsync(`
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

    CREATE INDEX IF NOT EXISTS idx_connections_captured_at
      ON connections(captured_at DESC);

    CREATE INDEX IF NOT EXISTS idx_connections_remote_addr
      ON connections(remote_addr);
  `);
};

// Exportar db + promesa de inicialización
const ready = initSchema().catch(err => {
  console.error('[DB] Error inicializando schema:', err.message);
  process.exit(1);
});

module.exports = { db, ready };
