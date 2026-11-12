-- MINNA_REASON_V1（2026-11-12）みんなのふりかえりに「先生が えらんだ わけ」を のせる（子どもたちにも 見える）
ALTER TABLE minna_posts ADD COLUMN reason TEXT NOT NULL DEFAULT '';
