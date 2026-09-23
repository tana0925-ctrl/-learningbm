-- 0038_karte_material_backfill.sql
-- KARTE_MATERIAL_V1 これまでに渡したぶんを「使用済み」として台帳に入れる（1回だけ）。
--
-- なぜ要るか：台帳は今日から空なので、何もしないと過去にほめた材料が
--             もう一度だけ出てきてしまう。先生の実感（＝もう言った）に合わせる。
--             ついでに、まとまりの文字数も下がる（未使用が 平均4.2件 → 1.2件）。
--
-- 対象：2026-09-18 に公開したカルテ 23人ぶんのうち、学習の記録を持つ 21人。
--       そのとき渡っていた上位3件 ＝ 59行。
--       （student_records は 2026-07-29 を最後に追加が無いので、
--         当時の選ばれ方を今そのまま再現できる。並び順は“直す前”の式を使う）
--
-- 授業の観察メモ（teacher_student_notes・全14件）は入れない。
--   件数が少なく、9月のメモはまだ新しい材料として一度使わせたいため。
--
-- ⚠ 書き込むのは karte_material_uses と student_ai_comments の週の列だけ。
--   児童の学習記録（progress / homework_submissions / learning_results /
--   student_records 本体）には一切さわらない。
--
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと。

INSERT OR IGNORE INTO karte_material_uses
  (user_id, source, source_id, class_id, reserved_at, used_at)
SELECT r.user_id, 'record', CAST(r.id AS TEXT), r.class_id,
       '2026-09-18 08:56:00', '2026-09-18 08:56:00'
FROM (
  SELECT id, user_id, class_id,
         ROW_NUMBER() OVER (
           PARTITION BY user_id
           ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC
         ) AS rn
  FROM student_records
) r
WHERE r.rn <= 3
  AND r.user_id IN (SELECT user_id FROM student_ai_comments WHERE updated_at >= '2026-09-01');

-- ── 既にあるカルテ本文に「どの週のことか」を入れる（推定） ──
--
-- 23件はすべて 2026-09-18（金）に公開されている。
-- 直す前の lastWeekDaysJst() は、その週のどの日に作っても 9月7日〜11日 を返す。
-- 本文の裏取りもできている（ある文の「水曜の振り返り」が day_key 2026-09-09 と一致）。
-- それでも「いつコピーしたか」は記録が無いので、week_guessed=1（推定）にしておく。
UPDATE student_ai_comments
   SET week_start = '2026-09-07',
       week_end   = '2026-09-11',
       week_guessed = 1
 WHERE updated_at >= '2026-09-01'
   AND (week_start IS NULL OR week_start = '');
