# PLANSUPPORT_V1 (2026-10-02) 第4便
#
# 先生のことば:「計画、サポーターからのコメントもみたい！」
#
# いまは、計画を見る場所（タブのいちばん上の計画の箱）と、
# サポーターからのことばが出る場所（毎日の振り返りの日ごとのカードの中の
# ピンクの箱）が別で、一人の子について両方読むには行ったり来たりが要る。
#
# この便ですること:
#   計画の箱の、その子のカードの中に、その週に届いた
#   「🏠 サポーターからのことば」を全部ならべる。
#
# ⚠ いちばん大事なところ:
#   既存の日ごとのカードでは、サポーターのことばは高さ15remで切られて
#   「…もっと見る」の中に隠れる作りになっている。2026-09 に3行へ詰めたせいで、
#   先生がいちばん見たかったサポーターのことばが65枚全部で隠れた。
#   ここでは 切らない・畳まない・高さの上限をつけない。
#   23人ぶん縦に長くなるが、読めることを優先する。
#
# D1 のこと:
#   homework_submissions には (user_id, day_key) の索引がある。
#   その週の月〜日 と クラスの子 にしぼって読むので、全件スキャンにはならない。
#   既存の submission-dashboard とまったく同じ読み方にそろえてある。
#
# しないこと:
#   ・既存の日ごとのカード（hw-ctx の 15rem）は触らない。壊すと返却作業が崩れる
#   ・提出率の数字は触らない
#   ・app.get('/') の .replace( チェーンは 1件も増減しない
import sys, io

PATH = 'src/index.tsx'
src = io.open(PATH, encoding='utf-8').read()

if 'PLANSUPPORT_V1' in src:
    print('すでに適用ずみ — 何もしません'); sys.exit(0)

def chain_count(s):
    a = s.index("app.get('/'"); b = s.index("app.get('/logout'")
    return s[a:b].count('.replace(')

CHAIN_BEFORE = 158
n = chain_count(src)
if n != CHAIN_BEFORE:
    print('NG: チェーンが %d 件（期待 %d）。ほかの便と重なっています。中止します。' % (n, CHAIN_BEFORE)); sys.exit(1)
print('チェーン実測: %d 件（期待どおり）' % n)

HWCTX_BEFORE = src.count('#hwList .hw-ctx { max-height: 15rem; overflow: hidden; }')

def swap(old, new, label):
    global src
    c = src.count(old)
    if c != 1:
        print('NG: %s の目印が %d 個（1個のはず）。中止します。' % (label, c)); sys.exit(1)
    src = src.replace(old, new, 1)
    print('  置きかえ OK:', label)

# ------------------------------- ① サーバ: その週のサポーターのことばも返す
swap(
"  const res = await c.env.DB.prepare(sql).bind(...binds).all<any>()\n"
"  return c.json({ ok: true, plans: res.results, weekKey })\n",
"  const res = await c.env.DB.prepare(sql).bind(...binds).all<any>()\n"
"\n"
"  // 2026-10-02 PLANSUPPORT_V1: 先生「計画、サポーターからのコメントもみたい！」\n"
"  //   その週に届いたサポーターのことばを、計画と同じ返事で返す。\n"
"  //   (user_id, day_key) の索引が効く読み方。全件スキャンにはならない。\n"
"  let parentComments: any[] = []\n"
"  try {\n"
"    const _mon = getMondayFromWeekKey(weekKey)\n"
"    const _sun = new Date(_mon)\n"
"    _sun.setUTCDate(_mon.getUTCDate() + 6)\n"
"    const _monStr = _mon.toISOString().split('T')[0]\n"
"    const _sunStr = _sun.toISOString().split('T')[0]\n"
"    let psql = `\n"
"      SELECT hs.user_id as userId, hs.day_key as dayKey, hs.parent_comment as parentComment\n"
"      FROM homework_submissions hs\n"
"      JOIN class_members cm ON cm.user_id = hs.user_id\n"
"      JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?\n"
"      WHERE hs.day_key >= ? AND hs.day_key <= ? AND hs.parent_comment IS NOT NULL AND hs.parent_comment <> ''\n"
"    `\n"
"    const pbinds: any[] = [u.id, _monStr, _sunStr]\n"
"    if (classId) { psql += ` AND cl.id = ?`; pbinds.push(classId) }\n"
"    psql += ` ORDER BY hs.day_key`\n"
"    const pres = await c.env.DB.prepare(psql).bind(...pbinds).all<any>()\n"
"    parentComments = (pres && pres.results) || []\n"
"  } catch (_e) { parentComments = [] }\n"
"\n"
"  return c.json({ ok: true, plans: res.results, weekKey, parentComments })\n",
'サーバ: その週のサポーターのことばを返す')

# ------------------------------------------- ② 画面: 受け取って子ごとに分ける
swap(
"          const data = await api('/api/teacher/weekly-plans'+qs);\n"
"          const plans = data.plans || [];\n",
"          const data = await api('/api/teacher/weekly-plans'+qs);\n"
"          const plans = data.plans || [];\n"
"          /* 2026-10-02 PLANSUPPORT_V1: その週のサポーターのことばを子ごとに分ける。 */\n"
"          var _supByUser = {};\n"
"          try{\n"
"            var _pcs = data.parentComments || [];\n"
"            for(var _pi=0;_pi<_pcs.length;_pi++){\n"
"              var _pc = _pcs[_pi];\n"
"              if(!_pc || !String(_pc.parentComment||'').trim()) continue;\n"
"              if(!_supByUser[_pc.userId]) _supByUser[_pc.userId] = [];\n"
"              _supByUser[_pc.userId].push(_pc);\n"
"            }\n"
"          }catch(_e){ _supByUser = {}; }\n",
'画面: サポーターのことばを子ごとに分ける')

# --------------------------- ③ 画面: その子のカードの中に、切らずに全部ならべる
swap(
"            // 計画承認ボタン（未承認の場合のみ）\n",
"            /* 2026-10-02 PLANSUPPORT_V1: その週のサポーターからのことば。\n"
"               切らない。畭まない。高さの上限をつけない。届いているものは全部出す。\n"
"               （2026-09 に3行へ詰めて 65枚全部で隠れた。同じことをしない） */\n"
"            try{\n"
"              var _sups = _supByUser[p.userId] || [];\n"
"              if(_sups.length){\n"
"                html += '<div class=\"mt-1 p-2 bg-pink-50 rounded border border-pink-200 space-y-1\">'\n"
"                  + '<div class=\"font-bold text-pink-700 text-xs\">\U0001f3e0 サポーターからのことば（この週 '+_sups.length+'件）</div>';\n"
"                for(var _si=0;_si<_sups.length;_si++){\n"
"                  html += '<div class=\"text-xs text-slate-700 break-words\">'\n"
"                    + '<span class=\"text-[10px] text-pink-500 font-bold mr-1\">'+escH(String(_sups[_si].dayKey||'').slice(5))+'</span>'\n"
"                    + escH(_sups[_si].parentComment) + '</div>';\n"
"                }\n"
"                html += '</div>';\n"
"              }\n"
"            }catch(_e){}\n"
"\n"
"            // 計画承認ボタン（未承認の場合のみ）\n",
'画面: カードの中にサポーターのことばをならべる')

# --------------------------------------------------------------- 適用後の確認
ok = True
def chk(name, got, want):
    global ok
    mark = 'OK ' if got == want else 'NG '
    print('  %s %s: %r（期待 %r）' % (mark, name, got, want))
    if got != want: ok = False

chk('チェーン（増減なし）', chain_count(src), CHAIN_BEFORE)
chk('サーバが parentComments を返す', src.count('weekKey, parentComments })'), 1)
chk('サポーターの読み取りは索引が効く形', src.count('WHERE hs.day_key >= ? AND hs.day_key <= ? AND hs.parent_comment'), 1)
chk('画面が子ごとに分けている', src.count('var _supByUser = {};'), 1)
chk('カードの中に出している', src.count('サポーターからのことば（この週'), 1)
chk('既存の日ごとカードの15remは触っていない',
    src.count('#hwList .hw-ctx { max-height: 15rem; overflow: hidden; }'), HWCTX_BEFORE)
chk('目印 PLANSUPPORT_V1', src.count('PLANSUPPORT_V1') >= 3, True)

# 切る指定を新しく入れていないこと（この便が足したサポーターの箱だけを見る）
_i = src.index('bg-pink-50 rounded border border-pink-200 space-y-1')
_box = src[_i - 100 : src.index('// 計画承認ボタン（未承認の場合のみ）', _i)]
for ng in ['max-height', 'max-h-', 'line-clamp', 'truncate', 'overflow-hidden', 'もっと見る']:
    chk('サポーターの箱に %s を入れていない' % ng, ng in _box, False)

# 9/26に2時間止まった事故の形（onclick の中の生クォート）を作っていないこと
chk('サポーターの箱に onclick を足していない', 'onclick' in _box, False)

if not ok:
    print('NG: 確認に失敗。書き込みません。'); sys.exit(1)

io.open(PATH, 'w', encoding='utf-8').write(src)
print('PLANSUPPORT_V1 を適用しました（チェーン %d -> %d）' % (CHAIN_BEFORE, chain_count(src)))
