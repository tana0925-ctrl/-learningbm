-- 0048_class_now_units.sql
-- NOWUNIT_V1 クラスごと・教科ごとの「いまの単元」（先生が手で選んだものだけを保存する）。
--   ・選ばなくてもよい。選んだら次に変えるまで有効。空にすると行を消し、自動（授業メモ→クラスの記録→標準の進み方）にもどる。
--   ・カルテの「えらべる3つの道」🅰🅱 は、この単元を中心に作る。
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと。
CREATE TABLE IF NOT EXISTS class_now_units (
  class_id   TEXT NOT NULL,
  subj       TEXT NOT NULL,
  unit       TEXT NOT NULL,
  set_by     TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (class_id, subj)
);
