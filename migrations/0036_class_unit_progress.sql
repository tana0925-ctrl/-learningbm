-- 0036_class_unit_progress.sql
-- WARMIX_V1 攻略モードの「習ったところまで」をクラスごとに持つ列。
--   NULL … まだ設定していない。児童側は war-mix.js の仮の草案を使う。
--   JSON … {"units":{"<単元ID>":false, ...},"updatedAt":"..."}
--          false を書いた単元だけ「未習」＝攻略モードに出さない。
-- 既存の ranking_enabled / def_prog_maxlv とまったく同じ流儀（列を1本足すだけ）。
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと。

ALTER TABLE classes ADD COLUMN unit_progress TEXT;
