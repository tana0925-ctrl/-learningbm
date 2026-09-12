-- test line
SELECT 1;
-- DEF2_CLASSCAP_V1
-- 防衛戦の プログラムづくりで、クラスごとの「ここまで」（レベル上限）を もつ列。
--   0 … せいげんなし（既定。これまでどおり 子どもが じぶんで ひろげられる）
--   1 / 2 / 3 … そのレベルまで
-- 既存の行は すべて 0 になる。つまり この列を 足しただけでは 何も かわらない。
-- 児童のデータには いっさい ふれない（classes に列を 1本 足すだけ）。
ALTER TABLE classes ADD COLUMN def_prog_maxlv INTEGER NOT NULL DEFAULT 0;
