-- HS_PHOTO_MULTI_V1 (2026-09-24)
-- 家庭学習の成果物写真を、1人1日あたり複数まい（最大5まい）もてるようにする。
--
-- 既存の homework_photos は PRIMARY KEY(user_id, day_key) で1まいしか持てない。
-- SQLite は主キーを変えられないため本来は「新テーブルへ全部コピー」だが、
-- 本番の写真は59まいで31MBあり、D1で一度にコピーするのは危険
-- （大きな移行は分割せよ、と Cloudflare が明記している）。そこで
--   ・新しい写真は homework_photos2 に入れる
--   ・読むときは homework_photos2 → 無ければ homework_photos の順に見る
--   ・旧テーブルは既存の180日そうじで自然に空になる
-- という形にして、既存データには一切触らない。

CREATE TABLE IF NOT EXISTS homework_photos2 (
  user_id    TEXT    NOT NULL,
  day_key    TEXT    NOT NULL,
  idx        INTEGER NOT NULL DEFAULT 0,   -- 0..4（出した順。0が1まい目）
  mime_type  TEXT    NOT NULL DEFAULT 'image/jpeg',
  bytes      BLOB    NOT NULL,
  byte_size  INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, day_key, idx),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_homework_photos2_user ON homework_photos2(user_id);
CREATE INDEX IF NOT EXISTS idx_homework_photos2_created ON homework_photos2(created_at);

-- ※ 枚数の列は作らない。先生の画面は 5まいぶんの <img> を出しておいて、
--    無いまいは onerror で消える作りにしたので、列も追加クエリも要らない。
