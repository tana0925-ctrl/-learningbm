import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip'); continue
        if old not in data:
            print('ANCHOR NOT FOUND',repr(old[:60])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old)); sys.exit(1)
        data=data.replace(old,new); print('ok',repr(old[:30]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ('          <!-- AIクラス分析 -->',
     '          <!-- 🤖 AI分析（まとめて）＋常時表示 -->\n          <div class="bg-gradient-to-br from-sky-50 to-indigo-50 border border-sky-200 rounded-xl p-4 space-y-2">\n            <div class="flex items-center justify-between flex-wrap gap-2">\n              <div class="font-bold text-sm text-sky-800">🤖 最新のAI分析（保存済み・いつでも表示）</div>\n              <button onclick="loadAiSummary()" class="bg-sky-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-sky-700">🔄 更新</button>\n            </div>\n            <div id="aiSummaryBox" class="text-sm text-slate-600"><p class="text-xs text-slate-400">クラスを選ぶと、保存済みのAI分析がここに表示されます</p></div>\n          </div>\n          <div class="bg-gradient-to-br from-violet-50 to-fuchsia-50 border border-violet-300 rounded-xl p-4 space-y-2">\n            <div class="font-bold text-sm text-violet-800">🤖 AI分析（まとめて）— ワンストップ</div>\n            <p class="text-xs text-violet-600">①「まとめてコピー」→ ChatGPT/Gemini等に貼り付け → ②AIの結果を下に貼って「保存」。クラス全体の所見と各児童の個人カルテコメントを一度にまとめて反映＆常時表示します。</p>\n            <div class="flex flex-wrap gap-2 items-center">\n              <button onclick="copyUnifiedAi()" class="bg-emerald-600 text-white rounded-lg px-3 py-2 text-xs font-bold hover:bg-emerald-700">📋 まとめてコピー（クラス＋全児童）</button>\n              <span id="unifiedAiStatus" class="text-xs text-violet-700 font-bold"></span>\n            </div>\n            <textarea id="unifiedAiPaste" rows="5" placeholder="ここにAIの出力を全部貼り付け（=== [CLASS] クラス全体 === / === [児童ID] 名前 === の目印ごとに自動でふり分けます）" class="w-full text-xs border border-violet-300 rounded-lg p-2"></textarea>\n            <div><button onclick="saveUnifiedAi()" class="bg-violet-600 text-white rounded-lg px-3 py-2 text-xs font-bold hover:bg-violet-700">💾 まとめて保存（クラス所見＋個人コメント）</button></div>\n          </div>\n          <!-- AIクラス分析 -->'),
    ("        if(sub==='notes' && typeof initNotesTab==='function') initNotesTab();",
     "        if(sub==='notes' && typeof initNotesTab==='function') initNotesTab();\n        if(sub==='ai' && typeof loadAiSummary==='function'){ try{ loadAiSummary(); }catch(_e){} }"),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE RB')
