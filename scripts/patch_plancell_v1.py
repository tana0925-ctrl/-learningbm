# PLANCELL_V1 (2026-10-02) 第2便
#
# 先生が「計画の列はあるのに何も見られない」と感じた場所。
# 「提出状況」の日別マトリックスの「計画」列は、📝 と「修正3回」を出すだけの
# ただの飾りで、押せなかった（<td> に onclick も <button> も無い）。
# 押せそうに見えて押せないのが いちばん たちが悪い。
#
# この便ですること:
#   1) サーバの submission-dashboard が plans_json を返すようにする（いま返していない）
#   2) 「計画」列を押せるボタンにして、押したらその子の計画が すぐ下の行に開く
#      （月〜金／本人からの返事／振り返り。切らない。畳まない）
#
# しないこと:
#   ・提出率の数字は 1つも 触らない（第3便でやる）
#   ・計画の箱（タブのいちばん上）は触らない
#   ・app.get('/') の .replace( チェーンは 1件も増減しない
import sys, io

PATH = 'src/index.tsx'
src = io.open(PATH, encoding='utf-8').read()

if 'PLANCELL_V1' in src:
    print('すでに適用ずみ — 何もしません'); sys.exit(0)

def chain_count(s):
    a = s.index("app.get('/'"); b = s.index("app.get('/logout'")
    return s[a:b].count('.replace(')

CHAIN_BEFORE = 158
n = chain_count(src)
if n != CHAIN_BEFORE:
    print('NG: チェーンが %d 件（期待 %d）。ほかの便と重なっています。中止します。' % (n, CHAIN_BEFORE)); sys.exit(1)
print('チェーン実測: %d 件（期待どおり）' % n)

def swap(old, new, label):
    global src
    c = src.count(old)
    if c != 1:
        print('NG: %s の目印が %d 個（1個のはず）。中止します。' % (label, c)); sys.exit(1)
    src = src.replace(old, new, 1)
    print('  置きかえ OK:', label)

# ---------------------------------------- ① サーバが plans_json を返すようにする
swap(
"      SELECT user_id, revision_count, plan_approved, updated_at\n",
"      SELECT user_id, revision_count, plan_approved, updated_at, plans_json\n",
'サーバ: plans_json を返す（PLANCELL_V1）')

# --------------------------------------------- ② 「計画」列を押せるようにする
OLD_CELL = (
"            var plan = planByUser[m.id];\n"
"            if(plan){\n"
"              var approvedBadge = plan.plan_approved ? '✅' : '\U0001f4dd';\n"
"              var revBadge = plan.revision_count > 0 ? '<div class=\"text-[8px] text-orange-500\">修正'+plan.revision_count+'回</div>' : '';\n"
"              html += '<td class=\"p-1.5 text-center border-b bg-blue-50\">'+approvedBadge+revBadge+'</td>';\n"
"            } else {\n"
)

NEW_CELL = (
"            var plan = planByUser[m.id];\n"
"            var __planRow = '';\n"
"            if(plan){\n"
"              var approvedBadge = plan.plan_approved ? '✅' : '\U0001f4dd';\n"
"              var revBadge = plan.revision_count > 0 ? '<div class=\"text-[8px] text-orange-500\">修正'+plan.revision_count+'回</div>' : '';\n"
"              /* 2026-10-02 PLANCELL_V1: ここは今まで押せない飾りだった。\n"
"                 先生「計画の列はあるのに何も見られない」——押したら下に開くようにする。 */\n"
"              html += '<td class=\"p-1.5 text-center border-b bg-blue-50\">'\n"
"                + '<button type=\"button\" class=\"leading-tight w-full\" onclick=\"dashTogglePlan(&#39;'+escH(m.id)+'&#39;,this)\">'\n"
"                + approvedBadge\n"
"                + '<div class=\"text-[9px] text-indigo-600 underline font-bold\">見る</div>'\n"
"                + revBadge\n"
"                + '</button></td>';\n"
"              var __pj = {}; try{ __pj = JSON.parse(plan.plans_json||'{}'); }catch(_e){ __pj = {}; }\n"
"              var __dl = ['月','火','水','木','金'];\n"
"              var __ks = Object.keys(__pj).filter(function(k){ return k !== '_modified'; });\n"
"              var __body = '', __any = false;\n"
"              for(var __i=0;__i<5;__i++){\n"
"                var __v = __ks[__i] ? __pj[__ks[__i]] : '';\n"
"                var __t = (__v && typeof __v === 'object' && __v) ? (__v.free||'') : (__v||'');\n"
"                var __has = !!String(__t).trim();\n"
"                if(__has) __any = true;\n"
"                __body += '<div class=\"flex gap-2 py-0.5\"><span class=\"font-bold text-slate-500 w-6 shrink-0\">'+__dl[__i]+'</span>'\n"
"                  + '<span class=\"text-slate-700 break-words\">'+(__has ? escH(__t) : '<span class=\"text-slate-300\">—</span>')+'</span></div>';\n"
"              }\n"
"              var __mv = __ks[0] ? __pj[__ks[0]] : '';\n"
"              var __rep = (__mv && typeof __mv === 'object' && __mv) ? (__mv.reply||'') : '';\n"
"              if(String(__rep).trim()) __body += '<div class=\"mt-1 p-1.5 bg-sky-50 rounded border border-sky-200\"><span class=\"font-bold text-sky-700\">✍️ 本人からの返事：</span>'+escH(__rep)+'</div>';\n"
"              var __fv = __ks[4] ? __pj[__ks[4]] : '';\n"
"              var __ref2 = (__fv && typeof __fv === 'object' && __fv) ? (__fv.reflection||'') : '';\n"
"              if(String(__ref2).trim()) __body += '<div class=\"mt-1 p-1.5 bg-orange-50 rounded border border-orange-200\"><span class=\"font-bold text-orange-700\">\U0001f504 振り返り：</span>'+escH(__ref2)+'</div>';\n"
"              if(!__any) __body = '<div class=\"text-slate-400 mb-1\">まだ何も書いていません</div>' + __body;\n"
"              /* 切らない。畭まない。高さの上限をつけない。 */\n"
"              __planRow = '<tr id=\"dashPlanRow_'+escH(m.id)+'\" class=\"hidden\"><td colspan=\"'+(weekDays.length+4)+'\" class=\"p-2 border-b bg-blue-50\">'\n"
"                + '<div class=\"text-xs\">'+__body+'</div></td></tr>';\n"
"            } else {\n"
)
swap(OLD_CELL, NEW_CELL, '計画の列を押せるボタンにする')

# ------------------------------------------- ③ 行のうしろに「開く行」を足す
swap("            html += '</tr>';\n",
     "            html += '</tr>';\n"
     "            html += __planRow; /* PLANCELL_V1: 押したときだけ見える行 */\n",
     '開く行をテーブルに足す')

# ------------------------------------------------------- ④ 開閉する関数を足す
swap("      async function loadSubmissionDashboard(selectedWeek){\n",
     "      /* 2026-10-02 PLANCELL_V1: 「計画」のマスを押したときの開閉。 */\n"
     "      function dashTogglePlan(uid, btn){\n"
     "        var row = document.getElementById('dashPlanRow_'+uid);\n"
     "        if(!row) return;\n"
     "        var nowHidden = row.classList.toggle('hidden');\n"
     "        try{ var lbl = btn.querySelector('div'); if(lbl) lbl.textContent = nowHidden ? '見る' : 'とじる'; }catch(_e){}\n"
     "      }\n\n"
     "      async function loadSubmissionDashboard(selectedWeek){\n",
     '開閉の関数を足す')

# --------------------------------------------------------------- 適用後の確認
ok = True
def chk(name, got, want):
    global ok
    mark = 'OK ' if got == want else 'NG '
    print('  %s %s: %r（期待 %r）' % (mark, name, got, want))
    if got != want: ok = False

chk('チェーン（増減なし）', chain_count(src), CHAIN_BEFORE)
chk('サーバが plans_json を返す', src.count('SELECT user_id, revision_count, plan_approved, updated_at, plans_json'), 1)
chk('押せるボタンになっている', src.count('dashTogglePlan(&#39;'), 1)
chk('開閉の関数がある', src.count('function dashTogglePlan(uid, btn)'), 1)
chk('開く行を足している', src.count('html += __planRow;'), 1)
chk('目印 PLANCELL_V1', src.count('PLANCELL_V1') >= 3, True)
# 9/26に2時間止まった事故の形（onclick の中の生クォート）を作っていないこと
chk("onclick の中で ' を直書きしていない", "onclick=\"dashTogglePlan('" in src, False)
# 高さを詰める指定を入れていないこと
for ng in ['max-h-', 'line-clamp', 'truncate']:
    chk('開く行に %s を入れていない' % ng, ng in NEW_CELL, False)

if not ok:
    print('NG: 確認に失敗。書き込みません。'); sys.exit(1)

io.open(PATH, 'w', encoding='utf-8').write(src)
print('PLANCELL_V1 を適用しました（チェーン %d -> %d）' % (CHAIN_BEFORE, chain_count(src)))
