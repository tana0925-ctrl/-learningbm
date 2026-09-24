-- 0039_qr_hunt.sql
-- QRHUNT_V1  校内QRさがし（既存「ひみつのQR」の作り替え）
--
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと（2026-09-03 の障害）。
--   src/index.tsx の ensureHomeworkClaimTable() のような
--   「リクエストの中で CREATE TABLE」は、ここでは真似しない。
--
-- 二重付与の防ぎかたは homework_claims / karte_material_uses に合わせる。
--   INSERT OR IGNORE は使わない（通ったのか無視されたのか分からないため）。
--   素の INSERT を try し、成功したときだけ ごほうびを返す。
--
-- ※ 2026-09-25 に本番へ適用ずみ（d1_migrations は 0005 までしか記録が無く、
--    0006 以降は直接SQLで当てる運用なので、それに合わせた）。

-- ── イベント本体（先生が1つ作る）──
CREATE TABLE IF NOT EXISTS qr_hunts (
  id          TEXT PRIMARY KEY,
  class_id    TEXT NOT NULL,
  title       TEXT NOT NULL DEFAULT 'ひみつのQR',
  start_at    TEXT NOT NULL,            -- 'YYYY-MM-DD HH:MM:SS'（素の文字列比較で使う。関数をかけない）
  end_at      TEXT NOT NULL,
  open_from   TEXT,                     -- 'HH:MM' 読み取れる時間帯（任意）。NULL なら終日
  open_to     TEXT,
  created_by  TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_qr_hunts_class ON qr_hunts(class_id, end_at);

-- ── QR 1枚ぶん ──
-- token が そのまま URL に入る： https://learning-bm.pages.dev/q/<token>
-- ランダム8文字。まぎらわしい字（0 O 1 l I）は使わない。
-- 連番や合言葉にしないのは、1枚見つけた子が残りを推測できないようにするため。
-- 子どもが教え合えるのは「場所」だけになる。
CREATE TABLE IF NOT EXISTS qr_spots (
  token             TEXT PRIMARY KEY,
  hunt_id           TEXT NOT NULL,
  label             TEXT NOT NULL DEFAULT '',      -- 先生の手元メモ。印刷面にも児童画面にも出さない
  sort_no           INTEGER NOT NULL DEFAULT 0,    -- 印刷の 1 2 3 … の順
  reward_kind       TEXT NOT NULL DEFAULT 'word',  -- 'word' | 'monster' | 'coin'
  reward_text       TEXT,                          -- ひとこと（空欄でよい。空なら「みつけた！」だけ出る）
  reward_monster_id INTEGER,                       -- public/index.html の MONSTERS の id
  reward_coins      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_qr_spots_hunt ON qr_spots(hunt_id, sort_no);

-- ── 見つけた台帳（1人1枚1回）──
-- PRIMARY KEY (token, user_id) が二重付与を止める。
-- applied_at … キャラ／コインを player に反映した時刻。
--   このアプリは player を stateJson のブロブで持っているため、
--   実際の加算は児童の端末側で行われる。台帳を先に通し、
--   反映が終わってから applied_at を入れる（homework_claims と同じ「予約→確定」）。
--   reward_kind='word' は反映するものが無いので、最初から確定させる。
CREATE TABLE IF NOT EXISTS qr_finds (
  token      TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  hunt_id    TEXT NOT NULL,
  found_at   TEXT NOT NULL DEFAULT (datetime('now')),
  applied_at TEXT,
  PRIMARY KEY (token, user_id)
);

-- 「いま何枚見つけたか」を、その子のぶんだけ数えるための索引。
-- WHERE hunt_id=? AND user_id=? で、読むのは最大でも枚数ぶんの行だけ。
-- 全件を数え直す作りにはしないこと。
CREATE INDEX IF NOT EXISTS idx_qr_finds_user ON qr_finds(hunt_id, user_id);
