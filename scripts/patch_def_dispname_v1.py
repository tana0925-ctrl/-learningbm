# -*- coding: utf-8 -*-
# DEF_DISPNAME_V1 防衛戦に出す名前を ログインIDから はなす。
#   なぜ: 防衛戦の ベスト3・MVP・貢献ゲージ・エントリー一覧に
#         users.name が出ていた。先生が「名簿の匿名化」を押したことで
#         users.name が login_id と同じ値になっており、結果として
#         クラス23人の画面に 他の子のログイン名が出ていた。
#   なにを: 児童側の3本のSQLだけを ゲーム内の名前に差しかえる。
#         ①/api/defense/status の entries
#         ②/api/defense/resolve の照合（ここを直さないと 名前が食い違って
#           retry が返り続け、クラスに結果が出なくなる）
#         ③def_resolve.ts の defServerResolve（entrants/mvp/awards/contrib の親）
#   さわらないもの: /api/teacher/defense/dry-run（教師認証の内側。
#         先生が 誰のことか 分からないと意味がないので login_id のまま）。
#         public/defense2.js も 1文字も さわらない（枠の修正は 別便）。
#   ならび: ①ゲーム内の名前 → ②出席番号 → ③ななし。login_id は 返さない。
import io, json, sys

E = json.loads(r'''{"src/def_resolve.ts":[["export async function defServerResolve(env, st, classId, enemies) {","/* __DEF_DISPNAME_V1__ 防衛戦に出す名前。\n   この欄は クラス全員の画面に出る。だから ログインIDは ぜったいに 返さない。\n   ①ゲーム内の名前（ranking_stats.display_name）→ ②出席番号 → ③ななし の順。\n   ①が ログインIDと同じときだけ 使わない（自分で ログインIDを 名前にした子のため）。\n   12文字で丸めるときは 絵文字を 半分に割らない。 */\nexport function defDisplayName(r: any): string {\n  const lid = String((r && r.lid) || '')\n  const dn = String((r && r.dn) || '').trim()\n  if (dn && dn !== lid) {\n    const cp = Array.from(dn)\n    return cp.length > 12 ? cp.slice(0, 12).join('') : dn\n  }\n  const rno = Number(r && r.rno)\n  if (Number.isFinite(rno) && rno > 0) return String(rno) + '番'\n  return 'ななし'\n}\nexport async function defServerResolve(env, st, classId, enemies) {"],["\"SELECT de.monster_json AS mj, de.strategy AS sg, u.name AS nm, de.user_id AS uid FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC LIMIT 200\"","\"SELECT de.monster_json AS mj, de.strategy AS sg, u.name AS nm, u.login_id AS lid, u.roster_no AS rno, rs.display_name AS dn, de.user_id AS uid FROM defense_entries de JOIN users u ON u.id=de.user_id LEFT JOIN ranking_stats rs ON rs.user_id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC LIMIT 200\""],["nm: String(r.nm || '')","nm: defDisplayName(r)"]],"src/index.tsx":[["import { defServerResolve, defEntryOk, defLogFit } from './def_resolve'","import { defServerResolve, defEntryOk, defLogFit, defDisplayName } from './def_resolve'"],["de.user_id as uid, u.name as nm FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=?","de.user_id as uid, u.name as nm, u.login_id as lid, u.roster_no as rno, rs.display_name as dn FROM defense_entries de JOIN users u ON u.id=de.user_id LEFT JOIN ranking_stats rs ON rs.user_id=de.user_id WHERE de.event_key=? AND de.class_id=?"],["return { user_id: r.uid, name: r.nm, monster: m, strategy: r.strat }","return { name: defDisplayName(r), monster: m, strategy: r.strat }"],["\"SELECT de.monster_json as mj, u.name as nm FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC\"","\"SELECT de.monster_json as mj, u.name as nm, u.login_id as lid, u.roster_no as rno, rs.display_name as dn FROM defense_entries de JOIN users u ON u.id=de.user_id LEFT JOIN ranking_stats rs ON rs.user_id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC\""],["_dvWant.push(String(_r.nm))","_dvWant.push(defDisplayName(_r))"]]}''')


def apply_one(path, mark):
    s = io.open(path, encoding='utf-8').read()
    if mark in s:
        print('すでに適用済み: ' + path)
        return 0
    for pair in E[path]:
        old, new = pair[0], pair[1]
        n = s.count(old)
        if n != 1:
            print('NG: %s のアンカーが %d 件（1件でないと流さない）' % (path, n))
            print('    先頭40字: ' + old[:40])
            sys.exit(1)
        s = s.replace(old, new, 1)
    if mark not in s:
        print('NG: %s に目印が入らなかった' % path)
        sys.exit(1)
    io.open(path, 'w', encoding='utf-8').write(s)
    return len(E[path])


a = apply_one('src/def_resolve.ts', '__DEF_DISPNAME_V1__')
b = apply_one('src/index.tsx', 'defDisplayName(r)')
print('def_resolve.ts %d 箇所 / index.tsx %d 箇所 を書きかえた' % (a, b))
