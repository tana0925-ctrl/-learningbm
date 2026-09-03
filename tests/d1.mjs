// node:sqlite で Cloudflare D1 の最小互換シムを作る。
// 本番DBには一切触らない。テストは毎回メモリ上の新しいDBで走る。
import { DatabaseSync } from 'node:sqlite'

class Stmt {
  constructor(db, sql, counter) { this.db = db; this.sql = sql; this.args = []; this.counter = counter }
  bind(...args) { this.args = args.map(normalize); return this }
  _prep() { return this.db.prepare(this.sql) }
  async first(col) {
    this.counter.reads++
    const r = this._prep().get(...this.args)
    if (r === undefined) return null
    return col ? r[col] : r
  }
  async all() {
    this.counter.reads++
    return { results: this._prep().all(...this.args), success: true, meta: {} }
  }
  async run() {
    this.counter.writes++
    const info = this._prep().run(...this.args)
    return { success: true, meta: { last_row_id: Number(info.lastInsertRowid), changes: Number(info.changes) } }
  }
  async raw() { this.counter.reads++; return this._prep().all(...this.args).map((r) => Object.values(r)) }
}

function normalize(v) {
  if (v === undefined || v === null) return null
  if (typeof v === 'boolean') return v ? 1 : 0
  if (typeof v === 'number') return Number.isInteger(v) ? v : v
  return v
}

export class FakeD1 {
  constructor() {
    this.db = new DatabaseSync(':memory:')
    this.counter = { reads: 0, writes: 0 }
  }
  prepare(sql) { return new Stmt(this.db, sql, this.counter) }
  async exec(sql) { this.db.exec(sql); return { count: 1, duration: 0 } }
  async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out }
  // テスト用のヘルパ（D1のAPIではない）
  _run(sql, ...args) { return this.db.prepare(sql).run(...args.map(normalize)) }
  _get(sql, ...args) { const r = this.db.prepare(sql).get(...args.map(normalize)); return r === undefined ? null : r }
  _all(sql, ...args) { return this.db.prepare(sql).all(...args.map(normalize)) }
}

// テストに必要な最小スキーマ。本番の migrations と同じ列名にそろえてある。
export const SCHEMA = `
CREATE TABLE users (
  id TEXT PRIMARY KEY, role TEXT NOT NULL, login_id TEXT UNIQUE, password_hash TEXT,
  password_salt TEXT, name TEXT, grade INTEGER, class_name TEXT, is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')), roster_no INTEGER
);
CREATE TABLE teacher_accounts (
  id TEXT PRIMARY KEY, login_id TEXT UNIQUE, password_hash TEXT, password_salt TEXT,
  name TEXT, school TEXT, is_active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE progress (
  user_id TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at TEXT
);
CREATE TABLE classes (
  id TEXT PRIMARY KEY, teacher_id TEXT NOT NULL, name TEXT, join_code TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE class_members (
  class_id TEXT NOT NULL, user_id TEXT NOT NULL, joined_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (class_id, user_id)
);
CREATE TABLE homework_submissions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, class_id TEXT, title TEXT, body TEXT,
  photo_key TEXT, work_photo_key TEXT DEFAULT '', teacher_id TEXT, teacher_comment TEXT,
  has_physical INTEGER DEFAULT 0, returned_at INTEGER, created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE contact_notes (
  id TEXT PRIMARY KEY, class_id TEXT, day_key TEXT, body TEXT,
  reward_deadline TEXT, reward_coins INTEGER, created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE contact_note_reads (
  user_id TEXT NOT NULL, note_id TEXT NOT NULL, reward_claimed INTEGER DEFAULT 0,
  read_at TEXT DEFAULT (datetime('now')), PRIMARY KEY (user_id, note_id)
);
CREATE TABLE trade_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, give_uid TEXT,
  recv_monster_json TEXT, status TEXT DEFAULT 'pending', delivered_at INTEGER
);
CREATE TABLE learning_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, answered_at TEXT
);
`

