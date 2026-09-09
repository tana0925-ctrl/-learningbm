#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_karte_v2.py --- 家庭学習カルテ 2026-09 仕上げ

V1 見出し「🎯 今週のおすすめ（先生が確認したもの）」から括弧書きを外す。
   子どもが受け取る紙に、大人の運用の都合を書かない（先生の指示）。
V2 同じ理由で「🔁 復習する単元とやり方（分散学習）」からも括弧書きを外す。
   学習科学の用語は子ども向けの紙には要らない（先生の判断）。
V3-V6 A4裏表を構造的に守るための上限。
   実測でストレス時 1.91 ページ（余白 95px）しかなく、
   「自分のことば」「先生からの記録」「今週のおすすめ」は
   長さ・件数に上限がなく、放っておくと3ページ目に落ちる。
   文字は小さくしない。あふれる分を出さないだけ。
   ・自分のことば   … 1件 50字まで
   ・先生からの記録 … 最大3件、1件 50字まで
   ・今週のおすすめ … 220字まで

public/index.html は触りません。
"""
import io, os, sys

STEPS = [
 {
  "tag": "V1 見出しから「（先生が確認したもの）」を外す",
  "sen": "'🎯 今週のおすすめ':",
  "old": "🎯 今週のおすすめ（先生が確認したもの）",
  "new": "🎯 今週のおすすめ"
 },
 {
  "tag": "V2 見出しから「（分散学習）」を外す",
  "sen": "復習する単元とやり方</div>",
  "old": "🔁 復習する単元とやり方（分散学習）",
  "new": "🔁 復習する単元とやり方"
 },
 {
  "tag": "V3 「自分のことば」1件あたりの長さに上限",
  "sen": "var _vt=String(_ks.weather_reason)",
  "old": "if(_ks.weather_reason) _kVoice.push(_kDn[kd2]+' '+_ks.weather_reason);",
  "new": "if(_ks.weather_reason){ var _vt=String(_ks.weather_reason); if(_vt.length>50) _vt=_vt.slice(0,49)+'…'; _kVoice.push(_kDn[kd2]+' '+_vt); }"
 },
 {
  "tag": "V4 「先生からの記録」は最大3件",
  "sen": "String(''+(n.body||'')).trim();}).slice(0,3)",
  "old": "var _tn=(d.teacherNotes||[]).filter(function(n){return n.showInKarte&&String(''+(n.body||'')).trim();});",
  "new": "var _tn=(d.teacherNotes||[]).filter(function(n){return n.showInKarte&&String(''+(n.body||'')).trim();}).slice(0,3);"
 },
 {
  "tag": "V5 「先生からの記録」1件あたりの長さに上限",
  "sen": "var _nb=String(nn.body||'')",
  "old": "H.push('<li>'+esc(nn.dayKey||'')+' '+esc(nn.body||'')+'</li>');",
  "new": "var _nb=String(nn.body||''); if(_nb.length>50) _nb=_nb.slice(0,49)+'…'; H.push('<li>'+esc(nn.dayKey||'')+' '+esc(_nb)+'</li>');"
 },
 {
  "tag": "V6 「今週のおすすめ」の長さに上限",
  "sen": "if(_ps.length>220)",
  "old": "var _psB=_ps?esc(_ps).split(String.fromCharCode(10)).join('<br>'):one;",
  "new": "if(_ps.length>220) _ps=_ps.slice(0,219)+'…'; var _psB=_ps?esc(_ps).split(String.fromCharCode(10)).join('<br>'):one;"
 }
]

MUST = [
 "function _buildKarteHtml(",
 "function _kHowToLearn(",
 "function downloadAllKartes(",
 "@page{size:A4",
 "📒 家庭学習カルテ",
 "🌟 今年度の積み上げ",
 "📊 今年度の学習の見える化",
 "🐯 阪神マンからのアドバイス",
 "📝 先生からの記録",
 "✏️ 先生から",
 "app.get('/api/student/my-karte'",
 "app.get('/api/teacher/student-full-analysis'",
 "planSuggestion",
 "/teacher-ai.js?v=7",
 "カルテは月曜に印刷して配るため",
 "🎯 今週のおすすめ",
 "🔁 復習する単元とやり方"
]

BAD = [
 "（先生が確認したもの）",
 "（分散学習）"
]


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tsx = os.path.join(root, 'src', 'index.tsx')
    src = io.open(tsx, encoding='utf-8').read()
    orig = src
    changes = []

    def fail(msg):
        print('\u274c 中止: ' + msg)
        sys.exit(1)

    for st in STEPS:
        if st['sen'] in src:
            print('\u23ed %s は適用済み（スキップ）' % st['tag']); continue
        n = src.count(st['old'])
        if n == 0: fail('%s のアンカーが見つかりません' % st['tag'])
        if n != 1: fail('%s のアンカーが %d 箇所（1箇所のはず）' % (st['tag'], n))
        src = src.replace(st['old'], st['new'], 1)
        changes.append(st['tag'])

    def root_replace_count(text):
        a = text.index("app.get('/', async (c) => {")
        b = text.index("app.get('/logout'", a)
        return text[a:b].count('.replace(')

    if root_replace_count(orig) != root_replace_count(src):
        fail('本番HTMLの置換チェーンの数が変わりました（%d -> %d）'
             % (root_replace_count(orig), root_replace_count(src)))
    print('\U0001f50e 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

    for m in MUST:
        if m not in src: fail('必須の要素が失われました: %s' % m)
    for x in BAD:
        if x in src: fail('外したはずの但し書きが残っています: %s' % x)

    if src != orig:
        io.open(tsx, 'w', encoding='utf-8', newline='').write(src)
        print('\u2705 src/index.tsx を更新しました')
    else:
        print('… 変更なし')
    print('---- 適用した項目 ----')
    for c in changes: print(' \u30fb' + c)
    if not changes: print(' （なし）')


if __name__ == '__main__':
    main()
