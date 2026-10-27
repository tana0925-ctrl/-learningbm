-- migrations_pf/0001_pf_blobs.sql  （写真専用の D1：learningbm-portfolio／バインディング PFDB）
-- PORTFOLIO_V1 R2 が使えるようになるまでの写真の置き場。本体のDBの容量を食わないよう、別のデータベースにする。
--   1行 = 写真1まい（D1 の1行の上限 2MB より小さくなるよう、先生の端末で長辺1600pxのJPEGに縮めてから入れる）
-- ※ リクエスト経路では DDL を実行しない。
CREATE TABLE IF NOT EXISTS pf_blobs (
  k          TEXT PRIMARY KEY,
  mime       TEXT NOT NULL DEFAULT 'image/jpeg',
  bytes      BLOB NOT NULL,
  byte_size  INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
