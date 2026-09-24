# -*- coding: utf-8 -*-
"""
patch_plan_loop_v2.py — 計画の輪 その2
2026-09-25  PLAN_LOOP_V2

(5) 報酬の向き
    いままで「読むものが無い承認のハンコ」に 300コイン+5かけら、
    「読むものがある計画へのひとこと」には何も無い、という逆転があった。
    ⚠ 承認のごほうびは据え置く（減らさない・条件も足さない）。
      先生が忙しくて承認だけ押した週に、子どもが損をする形にはしない。
    ⚠ 振り返りの返却は、もともと 300+5 が付いているのでそのまま。
    足りていなかった「計画へのひとこと」にだけ、承認より小さいごほうびを付ける。
      → 100コイン + 2かけら（承認 300+5 より小さい。
         「文章をもらうほうが得」にして、先生に書かせる圧力を作らないため）
    ⚠ すでに受け取った子のぶんには一切触れない（既存の受け取り記録はそのまま）。

(4後半) 子どもからの返事
    先生のおへんじ／阪神マンのおすすめに、その場で一言返せるようにする。
    ⚠ 新しいテーブルも列も作らない。
      ⚠ plans_json のトップレベルに新しいキー（_reply など）を足すのは危険。
        キーを順番に数えて「5番目＝金曜」としている場所が6か所あり、
        1つでも直し漏らすと金曜の振り返りが取れなくなる。
      → 月曜の日オブジェクトの中（{free, reflection} と同じ並び）に reply を入れる。
        トップレベルのキーは1つも増えないので、数えている6か所は無傷。
    ⚠ ごほうびは付けない（ごほうび目当ての返事は材料として値打ちがない）。
"""
import io
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'


def apply_html(s):
    # --- (5) 計画へのひとことに、小さなごほうび ---
    old = "        if(st.planAiComment){ html += '<div class=\"bg-violet-50 border-2 border-violet-300 rounded-xl p-3 space-y-1\"><div class=\"font-bold text-violet-700 text-sm\">\\uD83D\\uDCCB 先生からの計画アドバイス</div><div class=\"text-xs text-slate-700 whitespace-pre-wrap\">'+escapeHtml(st.planAiComment)+'</div></div>'; }"
    assert s.count(old) == 1, 'H1: %d' % s.count(old)
    new = ("        // \U0001F4CC 2026-09-25 PLAN_LOOP_V2: 文章のコメントにも小さなごほうびを付ける。\n"
           "        //   承認（読むものが無いハンコ）に300+5、文章に0、という逆転を解く。\n"
           "        //   金額は承認より小さい100+2。「文章をもらうほうが得」にしないため。\n"
           "        //   \u26A0 受け取りは今週のぶんだけ（過去の週はもらい直せてしまうので文章だけ）。\n"
           "        if(st.planAiComment){\n"
           "          html += '<div class=\"bg-violet-50 border-2 border-violet-300 rounded-xl p-3 space-y-1\">'\n"
           "            + '<div class=\"font-bold text-violet-700 text-sm\">\\uD83D\\uDCCB 先生からの計画アドバイス</div>'\n"
           "            + '<div class=\"text-xs text-slate-700 whitespace-pre-wrap\">'+escapeHtml(st.planAiComment)+'</div>'\n"
           "            + ((!isPastWeek && !localStorage.getItem('hwPlanCmtReward_'+weekKey))\n"
           "                ? '<div class=\"text-xs font-bold text-orange-600\">ごほうび: コイン100枚 ＋ かけら2個</div>'\n"
           "                  + '<button onclick=\"hwClaimPlanCmtReward(\\'' + weekKey + '\\')\" class=\"mt-1 px-3 py-1 bg-violet-600 text-white rounded-lg text-xs font-bold hover:opacity-90\">受け取る！</button>'\n"
           "                : '')\n"
           "            + '</div>';\n"
           "        }")
    s = s.replace(old, new)

    # 受け取り関数
    old = """function hwClaimRefReward(weekKey){"""
    new = ("// \U0001F4CC 2026-09-25 PLAN_LOOP_V2: 計画へのひとことのごほうび（承認より小さい）\n"
           "function hwClaimPlanCmtReward(weekKey){\n"
           "  try{\n"
           "    hsGrantRewards({ kind:'coin', coins:100, shards:2 }, { coins:0, shards:0 });\n"
           "    localStorage.setItem('hwPlanCmtReward_'+weekKey, '1');\n"
           "    alert('\\uD83C\\uDF81 先生からのアドバイスを受け取りました！\\nコイン100枚 ＋ かけら2個');\n"
           "    hwRenderWeekView();\n"
           "  }catch(e){ console.warn('hwClaimPlanCmtReward error:', e); }\n"
           "}\n"
           "\n"
           "function hwClaimRefReward(weekKey){")
    assert s.count(old) == 1, 'H2: %d' % s.count(old)
    s = s.replace(old, new)

    # --- (4後半) おへんじ枠に「返事」欄を足す ---
    old = """          _ph += '<div class="text-[10px] text-sky-600">読んでから、今週の計画を書いてみよう。</div></div>';"""
    new = ("""          _ph += '<div class="text-[10px] text-sky-600">読んでから、今週の計画を書いてみよう。</div>';\n"""
           "          // \U0001F4CC 2026-09-25 PLAN_LOOP_V2: その場で一言返せるようにする。\n"
           "          //   \u26A0 新しいテーブルも列も作らない。月曜の日オブジェクトの中に入れるので、\n"
           "          //     plans_json のトップレベルのキーは1つも増えない（金曜の取り違えが起きない）。\n"
           "          //   \u26A0 ごほうびは付けない（ごほうび目当ての返事は材料として値打ちがないため）。\n"
           "          var _rp = '';\n"
           "          try{\n"
           "            var _pl0 = hwGetPlanForWeek(weekKey) || {};\n"
           "            var _mv0 = _pl0[_hwDayKeys830[0]];\n"
           "            _rp = (_mv0 && typeof _mv0 === 'object') ? (_mv0.reply || '') : '';\n"
           "          }catch(_e){}\n"
           "          _ph += '<div class=\"mt-1 pt-1 border-t border-sky-200 space-y-1\">'\n"
           "            + '<div class=\"text-[11px] font-bold text-sky-800\">\\u270D\\uFE0F 先生・阪神マンへ、ひとこと返す（にんい）</div>'\n"
           "            + '<textarea id=\"hwReplyInput\" rows=\"2\" class=\"w-full border border-sky-300 rounded-lg p-1.5 text-xs\" placeholder=\"れい：先週は algebra がむずかしかったので、今週は先に計算をやります\">'+escapeHtml(_rp)+'</textarea>'\n"
           "            + '<button onclick=\"hwSaveReply()\" class=\"px-3 py-1 bg-sky-600 text-white rounded-lg text-xs font-bold hover:opacity-90\">送る</button>'\n"
           "            + '<span id=\"hwReplyMsg\" class=\"ml-2 text-[11px] text-sky-700\"></span>'\n"
           "            + '</div>';\n"
           """          _ph += '</div>';""")
    assert s.count(old) == 1, 'H3: %d' % s.count(old)
    s = s.replace(old, new)

    # 返事を保存する関数（既存の週間計画の保存APIをそのまま使う）
    old = """function hwClaimPlanReward(weekKey){"""
    new = ("// \U0001F4CC 2026-09-25 PLAN_LOOP_V2: 先生・阪神マンへの返事を保存する。\n"
           "//   保存先は plans_json の月曜の中（{free, reflection, reply}）。\n"
           "//   既存の /api/student/weekly-plan をそのまま使うので、新しいAPIは無い。\n"
           "function hwSaveReply(){\n"
           "  try{\n"
           "    var ta = document.getElementById('hwReplyInput');\n"
           "    if(!ta) return;\n"
           "    var txt = String(ta.value||'').trim().slice(0, 500);\n"
           "    var todayKey = hsGetDayKey830(new Date());\n"
           "    var weekKey = hsGetWeekKey(todayKey);\n"
           "    var plan = hwGetPlanForWeek(weekKey) || {};\n"
           "    var monKey = _hwDayKeys830[0];\n"
           "    var cur = plan[monKey];\n"
           "    if(cur && typeof cur === 'object'){ cur.reply = txt; plan[monKey] = cur; }\n"
           "    else { plan[monKey] = { free: (cur || ''), reply: txt }; }\n"
           "    hwSavePlanForWeek(weekKey, plan);\n"
           "    var msg = document.getElementById('hwReplyMsg');\n"
           "    fetch('/api/student/weekly-plan', { method:'POST', headers:{'content-type':'application/json'},\n"
           "      body: JSON.stringify({ weekKey: weekKey, plans: plan }) })\n"
           "      .then(function(r){ if(msg) msg.textContent = r.ok ? '\\u2705 おくったよ！' : '\\u26A0\\uFE0F 保存できませんでした'; setTimeout(function(){ if(msg) msg.textContent=''; }, 3000); })\n"
           "      .catch(function(){ if(msg){ msg.textContent = '\\u26A0\\uFE0F つうしんエラー'; setTimeout(function(){ msg.textContent=''; }, 3000); } });\n"
           "  }catch(e){ console.warn('hwSaveReply error:', e); }\n"
           "}\n"
           "\n"
           "function hwClaimPlanReward(weekKey){")
    assert s.count(old) == 1, 'H4: %d' % s.count(old)
    s = s.replace(old, new)

    return s


def apply_tsx(s):
    # --- 先生の計画カードに「本人からの返事」を出す ---
    old = """            // 📌 2026-09-25 PLAN_LOOP_V1: 計画に一言返す欄。"""
    new = ("""            // 📌 2026-09-25 PLAN_LOOP_V2: 子どもからの返事（月曜の中に入っている）\n"""
           """            try{\n"""
           """              var _mk = keys[0] || '';\n"""
           """              var _mv = _mk ? parsed[_mk] : '';\n"""
           """              var _rep = (_mv && typeof _mv === 'object') ? (_mv.reply || '') : '';\n"""
           """              if(_rep && String(_rep).trim()){\n"""
           """                html += '<div class="text-xs mt-1 p-1.5 bg-sky-50 rounded border border-sky-200">'\n"""
           """                  + '<span class="font-bold text-sky-700">✍️ 本人からの返事：</span>'+escH(_rep)+'</div>';\n"""
           """              }\n"""
           """            }catch(_e){}\n"""
           """\n"""
           """            // 📌 2026-09-25 PLAN_LOOP_V1: 計画に一言返す欄。""")
    assert s.count(old) == 1, 'T1: %d' % s.count(old)
    s = s.replace(old, new)
    return s


def main():
    a = io.open(TSX, encoding='utf-8').read()
    b = apply_tsx(a)
    h1 = io.open(HTML, encoding='utf-8').read()
    h2 = apply_html(h1)
    if b == a or h2 == h1:
        print('NO CHANGE'); sys.exit(1)
    io.open(TSX, 'w', encoding='utf-8').write(b)
    io.open(HTML, 'w', encoding='utf-8').write(h2)
    print('src/index.tsx     %d -> %d' % (len(a), len(b)))
    print('public/index.html %d -> %d' % (len(h1), len(h2)))


if __name__ == '__main__':
    main()
