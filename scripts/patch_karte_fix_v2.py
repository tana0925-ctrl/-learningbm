# -*- coding: utf-8 -*-
# KARTE_FIX_V2 （2026-09-24 の緊急直し）
#   ① 公開（/api/teacher/student-ai-comments）の D1 呼び出しをバッチにまとめる。
#      23人で47回・実測8.7秒かかっていた。先生が毎週押すボタンとしては遅すぎる。
#   ② /teacher-ai.js?v=7 -> v=8（先生のブラウザが古いJSを掴む余地を消す）
#   ※ 週ズレの直しは public/teacher-ai.js 側（lastWeekDaysJst を元の式へ戻す）。
#   児童の画面（配信チェーン）は1件も増やさない。
import json
import os
import sys

SRC = 'src/index.tsx'


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if not raw.isdigit():
    print('NG: CHAIN_BEFORE が数字でない（渡された値: %r）' % raw)
    sys.exit(1)
CHAIN_BEFORE = int(raw)

src = open(SRC, encoding='utf-8').read()
before = chain_count(src)
print('チェーン = %d' % before)
if before != CHAIN_BEFORE:
    print('NG: チェーンが %d 件。実測した %d と合わないので止めます。' % (before, CHAIN_BEFORE))
    sys.exit(1)

for marker in ['KARTE_FIX_V2', '_stInsert', 'teacher-ai.js?v=8']:
    if marker in src:
        print('NG: すでに適用済みのようです（%s）' % marker)
        sys.exit(1)

EDITS = json.loads(r"""[{"tag": "F1_publish_batch", "old": "  let saved = 0\n  for (const it of body.comments) {\n    const sid = String((it && it.studentId) || '')\n    if (!sid) continue\n    if (allowed && !allowed.has(sid)) continue\n    // ══════ KARTE_MATERIAL_V1 ここが「公開」＝台帳の確定点 ══════\n    //  (1) どの週について書いたカルテかを、本文と一緒に残す。\n    //      印刷日から逆算していたころは、金曜に作って月曜に配ると\n    //      見出し(9/14〜18)と本文(9/7〜11)が一週ズレた。\n    //      週を保存して見出しもこれを使えば、いつ作っていつ印刷しても一致する。\n    //  (2) まとまりに入れて渡した材料を「使った」にする。\n    //      予約のうち7日以内のものだけ。作っただけで公開しなかったぶんは\n    //      予約のまま自然に戻る（makeup_grants と同じ流儀）。\n    const _kmW = _karteWeekOf(String((body && (body as any).weekStart) || ''), String((body && (body as any).weekEnd) || ''))\n    try {\n      await c.env.DB.prepare(`INSERT INTO student_ai_comments (user_id, comment, updated_at, week_start, week_end, week_guessed) VALUES (?, ?, datetime('now'), ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET comment=excluded.comment, updated_at=datetime('now'), week_start=excluded.week_start, week_end=excluded.week_end, week_guessed=excluded.week_guessed`).bind(sid, String(it.comment || ''), _kmW.start, _kmW.end, _kmW.guessed).run()\n    } catch (e) {\n      console.error('student-ai-comments: 週の列が無いので本文だけ保存します', e)\n      await c.env.DB.prepare(`INSERT INTO student_ai_comments (user_id, comment, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(user_id) DO UPDATE SET comment=excluded.comment, updated_at=datetime('now')`).bind(sid, String(it.comment || '')).run()\n    }\n    try { await c.env.DB.prepare(\"UPDATE karte_material_uses SET used_at=datetime('now') WHERE user_id=? AND used_at IS NULL AND reserved_at >= datetime('now','-7 days')\").bind(sid).run() } catch {}\n    saved++\n  }\n", "new": "  // ══════ KARTE_FIX_V2 (2026-09-24) 公開を1回のバッチにまとめる ══════\n  //  もとは児童1人につき D1 を2回（本文の保存＋台帳の確定）呼んでいた。\n  //  23人で47回・実測8.7秒。先生が毎週押すボタンとしては遅すぎるので、\n  //  prepare した文を bind して並べ、batch() で一度に流す（2回ぶん）。\n  //  週（week_start / week_end）はリクエスト全体で同じなので1回だけ決める。\n  let saved = 0\n  const _kmW = _karteWeekOf(String((body && (body as any).weekStart) || ''), String((body && (body as any).weekEnd) || ''))\n  const _stInsert = c.env.DB.prepare(`INSERT INTO student_ai_comments (user_id, comment, updated_at, week_start, week_end, week_guessed) VALUES (?, ?, datetime('now'), ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET comment=excluded.comment, updated_at=datetime('now'), week_start=excluded.week_start, week_end=excluded.week_end, week_guessed=excluded.week_guessed`)\n  const _stUse = c.env.DB.prepare(\"UPDATE karte_material_uses SET used_at=datetime('now') WHERE user_id=? AND used_at IS NULL AND reserved_at >= datetime('now','-7 days')\")\n  const _targets: string[] = []\n  const _batch: any[] = []\n  for (const it of body.comments) {\n    const sid = String((it && it.studentId) || '')\n    if (!sid) continue\n    if (allowed && !allowed.has(sid)) continue\n    _targets.push(sid)\n    _batch.push(_stInsert.bind(sid, String((it && it.comment) || ''), _kmW.start, _kmW.end, _kmW.guessed))\n    _batch.push(_stUse.bind(sid))\n    saved++\n  }\n  if (_batch.length) {\n    try {\n      await c.env.DB.batch(_batch)\n    } catch (e) {\n      // 週の列が無い等で落ちたときは、本文だけの古い形でもう一度だけ試す。\n      // ここまで失敗したら 500 を返す（画面に「公開できませんでした」と出る）。\n      console.error('student-ai-comments: まとめて保存できませんでした。本文だけで入れ直します', e)\n      const _stOld = c.env.DB.prepare(`INSERT INTO student_ai_comments (user_id, comment, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(user_id) DO UPDATE SET comment=excluded.comment, updated_at=datetime('now')`)\n      const _retry: any[] = []\n      for (const it of body.comments) {\n        const sid = String((it && it.studentId) || '')\n        if (_targets.indexOf(sid) < 0) continue\n        _retry.push(_stOld.bind(sid, String((it && it.comment) || '')))\n      }\n      try { await c.env.DB.batch(_retry) } catch (e2) {\n        console.error('student-ai-comments: 本文だけの保存も失敗しました', e2)\n        return jsonError(c, 500, 'save_failed')\n      }\n    }\n  }\n"}, {"tag": "F3_cachebust", "old": "teacher-ai.js?v=7", "new": "teacher-ai.js?v=8"}]""")

bad = False
for e in EDITS:
    n = src.count(e['old'])
    print('%-20s アンカー %d 件' % (e['tag'], n))
    if n != 1:
        print('NG: %s のアンカーが %d か所' % (e['tag'], n))
        bad = True
if bad:
    sys.exit(1)

out = src
for e in EDITS:
    out = out.replace(e['old'], e['new'], 1)

after = chain_count(out)
print('適用後のチェーン = %d' % after)
if after != CHAIN_BEFORE:
    print('NG: チェーンが変わりました（%d -> %d）' % (before, after))
    sys.exit(1)

need = {
    'KARTE_FIX_V2': 1,
    '_stInsert': 2,
    '_stUse': 2,
    'c.env.DB.batch(_batch)': 1,
    'teacher-ai.js?v=8': 1,
    'teacher-ai.js?v=7': 0,
    '_karteWeekOf': 2,
    'karte_material_uses': 8,
}
for k, want in need.items():
    got = out.count(k)
    print('適用後 %-28s %d 件（期待 %d）' % (k, got, want))
    if got != want:
        bad = True

for k in ['cannot_trade_special', 'genElectric6', 'if (m.uncapturable) continue;', '__WORLD_V3__', 'WARMIX', '_hash']:
    if out.count(k) < 1:
        print('NG: 安全マーカー %r が消えました' % k)
        bad = True
if bad:
    sys.exit(1)

open(SRC, 'w', encoding='utf-8', newline='').write(out)
print('OK: %d -> %d バイト（%+d）' % (len(src), len(out), len(out) - len(src)))
