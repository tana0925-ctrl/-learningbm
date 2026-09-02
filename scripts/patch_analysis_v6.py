#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_analysis_v6.py --- 個人カルテ（印刷）を「その週中心」にし、レビューを通していない
                          自動コメントを外す

  K1 (B-d) カルテの先頭に「📅 今週のようす（月〜金）」を追加し、
           今年度ぶんの集計は「今年度の積み上げ」という位置づけに下げる
  K2 (B-d) 「学習の見える化」の見出しを「今年度の学習の見える化」に
  K3 (B-c) 提出率パネルから、先生のレビューを通していない自動の声かけ文を削除。
           数字は残すが、赤字の警告色をやめ、先生が手書きできる欄を置く。

テストの点数は引き続きカルテに載せません（v3で対応ずみ）。
public/index.html は触りません。
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

src = io.open(TSX, encoding='utf-8').read()
orig = src
changes = []

def fail(msg):
    print('❌ 中止: ' + msg); sys.exit(1)

def rep(old, new, tag, sentinel=None):
    global src
    if sentinel is not None and sentinel in src:
        print('⏭  %s は適用済み（スキップ）' % tag); return
    n = src.count(old)
    if n == 0:
        if new in src:
            print('⏭  %s は適用済み（スキップ）' % tag); return
        fail('%s のアンカーが見つかりません' % tag)
    if n != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, n))
    src = src.replace(old, new, 1)
    changes.append(tag)

# ---------------- K1: 「今週のようす」を先頭に ----------------
K1_OLD = """H.push('<div class="sec"><h2>🌟 がんばりの記録</h2><div class="chips">');"""

WEEK = (
    "/* 📅 2026-09 方針: 個人カルテは「その週」を主役にする（先生の指示）。"
    "テストの点数は載せない。 */ "
    "var _kJst=function(){ var n=new Date(); return new Date(n.getTime()+n.getTimezoneOffset()*60000+9*3600000); }; "
    "var _kFmt=function(dt){ var p=function(x){return (x<10?'0':'')+x;}; "
    "return dt.getFullYear()+'-'+p(dt.getMonth()+1)+'-'+p(dt.getDate()); }; "
    "var _kNow=_kJst(); var _kWd=(_kNow.getDay()+6)%7; var _kMon=new Date(_kNow.getTime()-_kWd*86400000); "
    "var _kDays=[]; for(var kd=0;kd<5;kd++){ _kDays.push(_kFmt(new Date(_kMon.getTime()+kd*86400000))); } "
    "var _kSub={}; (d.recentSubmissions||[]).forEach(function(s){ if(s&&s.day_key) _kSub[s.day_key]=s; }); "
    "var _kDone=0,_kMin=0,_kCells='',_kVoice=[]; var _kDn=['月','火','水','木','金']; "
    "for(var kd2=0;kd2<5;kd2++){ var _kk=_kDays[kd2]; var _ks=_kSub[_kk]; "
    "var _kw=_ks?((_ks.end_weather==='sun')?'☀️':(_ks.end_weather==='cloud')?'☁️':"
    "(_ks.end_weather==='rain')?'🌧️':'⭕'):'・'; "
    "if(_ks){ _kDone++; _kMin+=(_ks.minutes||0); "
    "if(_ks.weather_reason) _kVoice.push(_kDn[kd2]+' '+_ks.weather_reason); } "
    "_kCells+='<div style=\"text-align:center;flex:1;min-width:44px\">"
    "<div style=\"font-size:11px;color:#64748b;font-weight:700\">'+_kDn[kd2]+'</div>"
    "<div style=\"font-size:24px;line-height:1.2\">'+_kw+'</div></div>'; } "
    "var _kMonU=(function(){ var n2=new Date(); var dd=n2.getUTCDay(); var df=(dd===0?6:dd-1); "
    "return new Date(n2.getTime()-df*86400000).toISOString().slice(0,10); })(); "
    "var _kRef=null; (d.reflections||[]).forEach(function(r){ "
    "if(r&&(r.weekKey===_kDays[0]||r.weekKey===_kMonU)) _kRef=r; }); "
    "var _kH='<div class=\"sec\" style=\"border-color:#fcd34d;background:#fffbeb\">"
    "<h2>📅 今週のようす（'+_kDays[0]+' 〜 '+_kDays[4]+'）</h2>'; "
    "_kH+='<div style=\"display:flex;gap:6px;align-items:flex-end;margin-bottom:6px\">'+_kCells+'</div>'; "
    "_kH+='<div style=\"font-size:12px;color:#92400e;font-weight:700\">今週は 5日のうち '+_kDone+'日 "
    "とりくめました（合計 '+_kMin+'分）</div>'; "
    "if(_kVoice.length){ _kH+='<div style=\"margin-top:8px\">"
    "<div style=\"font-size:11px;font-weight:800;color:#b45309\">🗣 自分のことば</div><ul class=\"refl\">'; "
    "for(var kv=0;kv<_kVoice.length;kv++){ _kH+='<li>'+esc(_kVoice[kv])+'</li>'; } _kH+='</ul></div>'; } "
    "if(_kRef){ _kH+='<div style=\"margin-top:6px;font-size:12px;color:#475569\">"
    "<div style=\"font-size:11px;font-weight:800;color:#b45309\">📝 今週のふりかえり</div>'; "
    "if(_kRef.goodPoint) _kH+='<div>よかったこと … '+esc(_kRef.goodPoint)+'</div>'; "
    "if(_kRef.improvePoint) _kH+='<div>もうすこしなこと … '+esc(_kRef.improvePoint)+'</div>'; "
    "if(_kRef.nextAction) _kH+='<div>つぎにやること … '+esc(_kRef.nextAction)+'</div>'; _kH+='</div>'; } "
    "_kH+='<div style=\"margin-top:8px;border:2px dashed #fcd34d;border-radius:10px;min-height:54px;padding:8px\">"
    "<div style=\"font-size:10px;color:#b45309;font-weight:700\">✏️ 先生から</div></div>'; "
    "_kH+='</div>'; H.push(_kH); "
)

K1_NEW = WEEK + """H.push('<div class="sec"><h2>🌟 今年度の積み上げ</h2><div class="chips">');"""
rep(K1_OLD, K1_NEW, 'K1 カルテの先頭に「今週のようす」を追加', sentinel='今週のようす（')

# ---------------- K2: 見出しを今年度に ----------------
rep('<h2>📊 学習の見える化</h2>', '<h2>📊 今年度の学習の見える化</h2>',
    'K2 「学習の見える化」を「今年度の学習の見える化」に')

# ---------------- K3: レビューを通していない自動コメントを外す ----------------
SRX_OLD = (
    "var _srx=(ov.submissionRate||{}); if(_srx.show){ "
    "var _trTxt=_srx.trend==='down'?'↓ さいきん下がってきています':_srx.trend==='up'?'↑ さいきん上がってきています':'→ ほぼ横ばい'; "
    "var _trCol=_srx.trend==='down'?'#dc2626':_srx.trend==='up'?'#16a34a':'#64748b'; "
    "var _low=(_srx.overall!=null&&_srx.overall<60)||_srx.trend==='down'; "
    "var _box='<div class=\"sec\" style=\"border-color:'+(_low?'#fca5a5':'#bbf7d0')+';background:'+(_low?'#fef2f2':'#f0fdf4')+'\"><h2>📊 家庭学習の提出率</h2>'; "
    "_box+='<div style=\"display:flex;gap:14px;flex-wrap:wrap;align-items:center\">"
    "<div style=\"font-size:30px;font-weight:900;color:'+(_low?'#dc2626':'#16a34a')+'\">'+(_srx.overall!=null?_srx.overall+'%':'-')+'</div>"
    "<div style=\"font-size:12px;color:'+_trCol+';font-weight:700\">'+_trTxt+'"
    "<div style=\"font-size:10px;color:#94a3b8;font-weight:400\">直近約4週 '+(_srx.recent!=null?_srx.recent+'%':'-')+' / その前 '+(_srx.prev!=null?_srx.prev+'%':'-')+'</div></div></div>'; "
    "if(_low){ var _goal=(_srx.recent!=null&&_srx.recent<40)?'まずは週2回':'まずは週3〜4回'; "
    "_box+='<div style=\"margin-top:8px;background:#fff;border-radius:10px;padding:9px 12px;color:#7f1d1d;font-weight:700\">"
    "📣 正直に伝えると、いま提出が'+(_srx.trend==='down'?'下がってきている':'少なめ')+'よ。でも、ここからがチャンス！　"
    "👉 次の一歩：'+_goal+'の提出を目標にしよう。出した日はカレンダーに○をつけると続けやすいよ。</div>'; } "
    "else { _box+='<div style=\"margin-top:8px;background:#fff;border-radius:10px;padding:9px 12px;color:#166534;font-weight:700\">"
    "🎉 よく続けられているね！この提出ペースは大きな力になっているよ。この調子！</div>'; } "
    "_box+='</div>'; H.push(_box); } "
)

SRX_NEW = (
    "/* 📌 2026-09 方針: ここには以前、先生のレビューを通さない自動の声かけ文が入っていた。 */ "
    "/*   低いと赤字で『正直に伝えると…』という文が、子どもに直接わたる形になっていた。 */ "
    "/*  → 数字だけ残し、かける言葉は先生がレビューして公開したコメント（🐯の欄）か手書きに任せる。 */ "
    "var _srx=(ov.submissionRate||{}); if(_srx.show){ "
    "var _trTxt=_srx.trend==='down'?'→ さいきんは すこし へっています':_srx.trend==='up'?'→ さいきんは ふえています':'→ ほぼ おなじくらいです'; "
    "var _box='<div class=\"sec\"><h2>📊 家庭学習の提出（今年度）</h2>'; "
    "_box+='<div style=\"display:flex;gap:14px;flex-wrap:wrap;align-items:center\">"
    "<div style=\"font-size:30px;font-weight:900;color:#475569\">'+(_srx.overall!=null?_srx.overall+'%':'-')+'</div>"
    "<div style=\"font-size:12px;color:#64748b;font-weight:700\">'+_trTxt+'"
    "<div style=\"font-size:10px;color:#94a3b8;font-weight:400\">直近約4週 '+(_srx.recent!=null?_srx.recent+'%':'-')+' / その前 '+(_srx.prev!=null?_srx.prev+'%':'-')+'</div></div></div>'; "
    "if(!d.aiComment){ _box+='<div style=\"margin-top:8px;border:2px dashed #cbd5e1;border-radius:10px;min-height:46px;padding:8px\">"
    "<div style=\"font-size:10px;color:#94a3b8;font-weight:700\">✏️ 先生から</div></div>'; } "
    "_box+='</div>'; H.push(_box); } "
)
rep(SRX_OLD, SRX_NEW, 'K3 レビューを通していない自動の声かけ文を削除', sentinel='先生のレビューを通さない自動の声かけ文')

# ---------------- 検証 ----------------
def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

if root_replace_count(orig) != root_replace_count(src):
    fail('本番HTMLの置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

for must in ['function _buildKarteHtml', 'function downloadAllKartes', 'function downloadKartePdf',
             '📅 今週のようす（', '<h2>🌟 今年度の積み上げ</h2>', '<h2>📊 今年度の学習の見える化</h2>',
             '📊 家庭学習の提出（今年度）', '🐯 阪神マンからのアドバイス',
             '子どもに渡すカルテにはテストの点数']:
    if must not in src: fail('必須の要素が失われました: %s' % must)

# 責める文言・自動の声かけが残っていないこと
for bad in ['正直に伝えると、いま提出が', 'よく続けられているね！この提出ペースは',
            '次の一歩：', '<h2>📊 家庭学習の提出率</h2>']:
    if bad in src: fail('外したはずの自動コメントが残っています: %s' % bad)

# テストの点数がカルテに戻っていないこと
i = src.index('function _buildKarteHtml')
j = src.index('function downloadKartePdf')
karte = src[i:j]
karte_nc = karte.replace('子どもに渡すカルテにはテストの点数・得点率を載せない（先生の指示）', '')
for bad in ['テストの記録', '得点率', 'testScores', 'd.tests']:
    if bad in karte_nc: fail('カルテ内にテストの点数が入っています: %s' % bad)
print('🔎 カルテ内にテストの点数は入っていません')

for pat, want in [('📅 今週のようす（', 1), ('✏️ 先生から', 2), ('_kDays[0]', 2)]:
    if src.count(pat) != want:
        fail('検訽失敗: %r が %d 箇所（%d のはず）' % (pat, src.count(pat), want))

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました')
else:
    print('… 変更なし')
print('---- 適用した項目 ----')
for c in changes: print(' ・' + c)
if not changes: print(' （なし）')
