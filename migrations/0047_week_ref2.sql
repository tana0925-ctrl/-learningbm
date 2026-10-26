-- 0047_week_ref2.sql  WEEKREF2_V1（2026-10-26）週の振り返りを充実させる
--
-- week_ref2 … 週の振り返りに足した欄（1人1週1行・上書き）。コインは付けない（コインは既存の week_ref_rewards 台帳のまま）。
--   promise_text   … 先週の自分が決めたこと（先週の「次どうする？」と「来週やってみたいこと」）を、出したときに写しておく
--   promise_result … その結果（本人の見立て）'done'=できた／'some'=ちょっと／'not'=できなかった／''（答えていない）
--   promise_reason … わけ 'time'=時間がなかった／'forgot'=わすれた／'way'=やり方が合わなかった／'other'=その他／''
--   promise_note   … 一言（60字まで）
--   q_id / q_choice / q_text … 週ごとにかわる「考える問い」と答え（任意。q_choice は選択肢の番号の文字・q_text は80字まで）
--   school_subj / school_theme / school_learned / school_more … 🏫学校での学び（教科・単元やテーマ・わかったこと・もっと知りたいこと）
--   facts_json     … 出したときに子どもに見せた「今週の自分の記録」（事実だけ。比較・順位なし）。サーバーで数えたもの
-- 文章は structured_reflections.free_text にも いつもの文として入る（既存の一覧・返却・ひと往復がそのまま読める）。
--
-- teacher_class_notes … ⑥授業メモ（以前リクエストの途中で作っていた表。ここでは索引だけ足す。表が無ければ作る）
--
-- ※ リクエスト経路では実行しない。本番には先に流す（2026-09-03 の障害）。
CREATE TABLE IF NOT EXISTS week_ref2 (
  user_id        TEXT NOT NULL,
  week_key       TEXT NOT NULL,
  promise_text   TEXT NOT NULL DEFAULT '',
  promise_result TEXT NOT NULL DEFAULT '',
  promise_reason TEXT NOT NULL DEFAULT '',
  promise_note   TEXT NOT NULL DEFAULT '',
  q_id           TEXT NOT NULL DEFAULT '',
  q_choice       TEXT NOT NULL DEFAULT '',
  q_text         TEXT NOT NULL DEFAULT '',
  school_subj    TEXT NOT NULL DEFAULT '',
  school_theme   TEXT NOT NULL DEFAULT '',
  school_learned TEXT NOT NULL DEFAULT '',
  school_more    TEXT NOT NULL DEFAULT '',
  facts_json     TEXT NOT NULL DEFAULT '',
  updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, week_key)
);
CREATE TABLE IF NOT EXISTS teacher_class_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, class_id TEXT NOT NULL, day_key TEXT, body TEXT, created_by TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS idx_teacher_class_notes_class_day ON teacher_class_notes (class_id, day_key);
