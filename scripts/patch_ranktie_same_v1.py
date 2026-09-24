# -*- coding: utf-8 -*-
# RANKTIE_SAME_V1 / RANKBEST_V1 (2026-09-25)
#   ① 同じ点なら同じ順位・同じかけら（運動会と同じ数えかた：1位が2人なら次は3位）。
#      もとは内部の並び順しだいで 2位/3位/なし に割れていた。
#      2026-09-14 の週に、ずかんが同じ10個の子が3人いて実際に起きた。
#      0点は今までどおり対象外なので、誰も取っていない部門では誰にも配らない。
#   ② 週の成績を「最後に保存した時点の値」ではなく「その週のいちばん良かった記録」にする。
#      タイプシュートの点も やせいバトルの連勝も積み上がる数ではないので、
#      途中で良い記録を出しても下がると 0 になっていた。
#      正解ポイントとずかんは積み上がる数なので結果は変わらない（下がるのを防ぐだけ）。
#   既にもらっている子から取り上げることはしない（上書きは MAX のみ、順位は同点を引き上げるだけ）。
#   児童の画面（配信チェーン）は増減しない。DDL なし。public/index.html は触らない。
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

for marker in ['RANKTIE_SAME_V1', 'RANKBEST_V1']:
    if marker in src:
        print('NG: すでに適用済みのようです（%s）' % marker)
        sys.exit(1)

EDITS = json.loads(r"""[{"tag": "E1_tie_same_rank", "old": "  for (const td of typeDefs) {\n    const sorted = list.filter((r) => td.get(r) > 0).sort((a, b) => td.get(b) - td.get(a))\n    for (let i = 0; i < Math.min(3, sorted.length); i++) {\n      const uid = String(sorted[i].uid)\n      const rank = i + 1\n      if (!awards[uid]) awards[uid] = []\n      awards[uid].push({ type: td.type, rank, shards: SHARDS[rank] })\n    }\n  }\n", "new": "  for (const td of typeDefs) {\n    const sorted = list.filter((r) => td.get(r) > 0).sort((a, b) => td.get(b) - td.get(a))\n    // ══════ RANKTIE_SAME_V1 (2026-09-25) 同じ点なら同じ順位・同じかけら ══════\n    //  もとは並べた順に1位2位3位を付けていたので、まったく同じ点でも\n    //  内部の並び順しだいで 6かけら / 3かけら / なし に割れていた。\n    //  2026-09-14 の週に、ずかんが同じ10個の子が3人いて実際に起きた。\n    //  数えかたは運動会と同じ（標準競技順位）：1位が2人いたら次の子は3位。\n    //  0点の子は今までどおり対象外なので、誰も取っていない部門では誰にも配らない。\n    let rank = 0\n    for (let i = 0; i < sorted.length; i++) {\n      if (!(i > 0 && td.get(sorted[i]) === td.get(sorted[i - 1]))) rank = i + 1\n      if (rank > 3) break\n      const uid = String(sorted[i].uid)\n      if (!awards[uid]) awards[uid] = []\n      awards[uid].push({ type: td.type, rank, shards: SHARDS[rank] })\n    }\n  }\n"}, {"tag": "E2_weekly_best", "old": "      await env.DB.prepare(\"INSERT INTO ranking_weekly_scores (user_id, week_key, correct_pt, pokedex, typeshoot, wild, updated_at) VALUES (?,?,?,?,?,?,datetime('now')) ON CONFLICT(user_id, week_key) DO UPDATE SET correct_pt=excluded.correct_pt, pokedex=excluded.pokedex, typeshoot=excluded.typeshoot, wild=excluded.wild, updated_at=datetime('now')\").bind(userId, info.curOpenWeek, cPt, cDex, cTs, cWild).run()\n", "new": "      // ══════ RANKBEST_V1 (2026-09-25) その週の「いちばん良かった記録」で競う ══════\n      //  もとは保存のたびに上書きしていたので、週の途中で良い記録を出しても\n      //  そのあと下がると 0 になっていた。タイプシュートの点も やせいバトルの連勝も\n      //  積み上がる数ではないので、最後に保存した時点の値で競うのは説明できない。\n      //  MAX にすれば「その週のいちばん良かったところ」で競える。\n      //  正解ポイントとずかんは積み上がる数なので MAX でも今までと同じ結果になり、\n      //  古い端末の上書きで下がったときだけ、下がらないように守られる。\n      await env.DB.prepare(\"INSERT INTO ranking_weekly_scores (user_id, week_key, correct_pt, pokedex, typeshoot, wild, updated_at) VALUES (?,?,?,?,?,?,datetime('now')) ON CONFLICT(user_id, week_key) DO UPDATE SET correct_pt=MAX(excluded.correct_pt, COALESCE(correct_pt,0)), pokedex=MAX(excluded.pokedex, COALESCE(pokedex,0)), typeshoot=MAX(excluded.typeshoot, COALESCE(typeshoot,0)), wild=MAX(excluded.wild, COALESCE(wild,0)), updated_at=datetime('now')\").bind(userId, info.curOpenWeek, cPt, cDex, cTs, cWild).run()\n"}]""")

bad = False
for e in EDITS:
    n = src.count(e['old'])
    print('%-20s アンカー %d 件' % (e['tag'], n))
    if n != 1:
        print('NG: %s のアンカーが %d か所（1件でないので止めます）' % (e['tag'], n))
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

need = json.loads(r"""{"RANKTIE_SAME_V1": 1, "RANKBEST_V1": 1, "Math.min(3, sorted.length)": 0, "if (rank > 3) break": 1, "MAX(excluded.typeshoot": 1, "MAX(excluded.correct_pt": 1, "ranking_weekly_scores": 3, "RANKSETTLE_RETRY_V1": 1, "SHARDS[rank]": 1, "_rankShardsApplied": 5}""")
for k in sorted(need):
    want = need[k]
    got = out.count(k)
    print('適用後 %-42s %d 件（期待 %d）' % (k, got, want))
    if got != want:
        print('NG: %r の件数が期待と違います' % k)
        bad = True

# 危険な作り込みが紛れていないこと
for k in ['ALTER TABLE', 'DROP TABLE', 'DELETE FROM progress', 'DELETE FROM users']:
    if out.count(k) != src.count(k):
        print('NG: %r の件数が変わりました（%d -> %d）' % (k, src.count(k), out.count(k)))
        bad = True

for k in ['cannot_trade_special', 'genElectric6', 'if (m.uncapturable) continue;', '__WORLD_V3__', 'WARMIX', '_hash']:
    if out.count(k) < 1:
        print('NG: 安全マーカー %r が消えました' % k)
        bad = True
if bad:
    sys.exit(1)

open(SRC, 'w', encoding='utf-8', newline='').write(out)
print('OK: %d -> %d バイト（%+d）' % (len(src), len(out), len(out) - len(src)))
