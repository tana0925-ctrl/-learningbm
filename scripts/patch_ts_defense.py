import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip:',repr(old[:40])); continue
        if old not in data:
            print('ANCHOR NOT FOUND',path,repr(old[:70])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old),repr(old[:70])); sys.exit(1)
        data=data.replace(old,new); print('ok',path,repr(old[:40]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ('          </div>\n        </div>\n\n        <!-- サブタブ⑥: 授業メモ -->',
     '          </div>\n          <div class="bg-white rounded-xl shadow p-4">\n            <div class="font-bold text-slate-700 mb-1">📚 記録の取り込み（まとめ・振り返り・その他）</div>\n            <div class="text-xs text-slate-500 mb-2">ロイロ等の「調べたこと・レポート・振り返り」を外部AIに決まった形式で書き出させ、ここに貼り付けて児童ごとに保存します。保存先は上の「クラス」で選んだクラスです。</div>\n            <div class="flex items-center gap-2 flex-wrap mb-2">\n              <span class="text-xs font-bold text-slate-600">種類:</span>\n              <select id="recType" class="border p-1.5 rounded text-xs bg-white">\n                <option value="report">まとめ・レポート（調べたこと）</option>\n                <option value="reflect">振り返り</option>\n                <option value="other">その他</option>\n              </select>\n              <button onclick="copyRecordPrompt()" class="bg-emerald-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-emerald-700">📋 AI用プロンプトをコピー</button>\n              <span id="recPromptStatus" class="text-xs text-emerald-600 font-bold"></span>\n            </div>\n            <textarea id="recPaste" rows="8" class="w-full border rounded-lg p-2 text-xs" placeholder="AIが書き出した結果をここに貼り付け（=== [児童ID] 名前 === / タイトル: / 日付: / 教科: / 単元: / 本文: …）"></textarea>\n            <div class="flex items-center gap-2 mt-2">\n              <button onclick="parseRecords()" class="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:opacity-90">🔍 読み取り</button>\n              <span id="recParseStatus" class="text-xs text-slate-500"></span>\n            </div>\n            <div id="recPreview" class="mt-3"></div>\n          </div>\n        </div>\n\n        <!-- サブタブ⑥: 授業メモ -->'),
    ('H.push(\'<div style="margin-bottom:8px"><div style="font-weight:800;color:#16a34a;font-size:13px">💬 おうちでの声かけ例（努力・やり方をほめる）</div><ul style="margin:4px 0;padding-left:20px;color:#334155">\'); for(var v=0;v<voices.length;v++){ H.push(\'<li style="margin:3px 0">\'+esc(voices[v])+\'</li>\'); } H.push(\'</ul></div>\'); ',
     ''),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE P4_card_koe')
