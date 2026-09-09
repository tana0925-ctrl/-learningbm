-- ドリルパーク（外部ドリル教材）の実施ログ
--
-- 1行 = エクセル1行 = 「1回のドリル実施」。
-- 1問ごとの正誤は answers に丸ごと持つ:
--   '1' = 正答 / '0' = 誤答 / '-' = 未出題（間に飛びがある場合のみ。末尾の未出題は切り落とす）
--   例) '1111110' = 7問出て6問正解、7問目だけ誤答
-- 設問ごとに1行ずつ持つ設計もあり得るが、1週間で 3万行を超える書き込みになるため
-- （22人 × 約360実施 × 最大99問）、D1の書き込みを増やさない方を採った。
-- answers は欠損なしなので、必要な集計は取り出したあとJS側でできる。
--
-- row_key = SHA-256( 実施日|開始時刻|クラス|出席番号|氏名|教科|ドリル番号|教材名 )
--   ＝「エクセルの行そのもの」の指紋。どの児童に割り当てたかには依存させない。
--   これに UNIQUE をかけることで、同じファイルを何度取り込んでも、
--   週の範囲が重なっているファイルを取り込んでも、構造的に二重登録されない。

CREATE TABLE IF NOT EXISTS drill_sessions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  row_key      TEXT    NOT NULL,
  user_id      TEXT    NOT NULL,
  class_id     TEXT,
  source       TEXT    NOT NULL DEFAULT 'drillpark',
  done_on      TEXT    NOT NULL,
  started_at   TEXT,
  subject      TEXT,
  drill_no     TEXT,
  material     TEXT,
  use_type     TEXT,
  drill_kind   TEXT,
  answer_sec   INTEGER,
  total_q      INTEGER NOT NULL DEFAULT 0,
  correct_q    INTEGER NOT NULL DEFAULT 0,
  rate_pct     INTEGER,
  answers      TEXT    NOT NULL DEFAULT '',
  import_batch TEXT,
  imported_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  imported_by  TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 二重取り込みを防ぐ本体
CREATE UNIQUE INDEX IF NOT EXISTS uq_drill_sessions_row_key ON drill_sessions(row_key);

-- カルテ／おすすめの材料を引くときの経路
CREATE INDEX IF NOT EXISTS idx_drill_sessions_user_done ON drill_sessions(user_id, done_on);
CREATE INDEX IF NOT EXISTS idx_drill_sessions_class_done ON drill_sessions(class_id, done_on);

-- 取り違えて保存したときに「その取り込みぶんだけ」消せるようにする。
-- 同じ行は同じ row_key になり入れ直しても上書きされないので、
-- 一度消してから入れ直す、という直し方になる。
CREATE INDEX IF NOT EXISTS idx_drill_sessions_batch ON drill_sessions(import_batch);
