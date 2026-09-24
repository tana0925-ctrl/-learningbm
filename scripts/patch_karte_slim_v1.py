# -*- coding: utf-8 -*-
# KARTE_SLIM_V1 (2026-09-25)
#   ・📊見える化の横棒グラフ（💪とくい／🌱のばす／🔁復習）を外す。
#     実測で、並ぶ単元が 📚メニュー と完全一致していた（3人で確認）。同じことを紙の3か所で言っていた。
#   ・グラフ3つ（レーダー／月別棒／ドーナツ）は残し、高さだけ詰める（先生の「見た目も大切」）。
#   ・横棒から消える「💪とくい」は、💪とくいなところ の欄に文字で残す。
#   ・「出会ったばかり」の一文が3単元とも同じになっていたのを、単元の位置でも変える。
#   ⚠ これでも A4 1枚には収まらない（実測 440->390mm / 使える高さ273mm）。
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
    print('NG: CHAIN_BEFORE が数字でない（%r）' % raw); sys.exit(1)
CHAIN_BEFORE = int(raw)

src = open(SRC, encoding='utf-8').read()
before = chain_count(src)
print('チェーン = %d' % before)
if before != CHAIN_BEFORE:
    print('NG: チェーンが %d 件。実測した %d と合わないので止めます。' % (before, CHAIN_BEFORE)); sys.exit(1)

if 'KARTE_SLIM_V1' in src:
    print('NG: すでに適用済みのようです'); sys.exit(1)

EDITS = json.loads(r"""[{"tag": "H1_drop_mixbars", "old": "var _mix=[]; for(var gi=0;gi<good.length&&_mix.length<2;gi++){ _mix.push({label:_unitJa(good[gi].unit),rate:good[gi].rate,total:good[gi].total,color:'#22c55e'}); } for(var wi=0;wi<grow.length&&_mix.length<5;wi++){ _mix.push({label:_unitJa(grow[wi].unit),rate:grow[wi].rate,total:grow[wi].total,color:'#f97316'}); } for(var ri=0;ri<reviewWeak.length&&_mix.length<6;ri++){ var _rgn=_unitGrade(reviewWeak[ri].unit); _mix.push({label:(_rgn?_rgn+'年 ':'')+_unitJa(reviewWeak[ri].unit),rate:reviewWeak[ri].rate,total:reviewWeak[ri].total,color:'#3b82f6'}); } if(_mix.length){ var _mw=520,_mlw=150,_mbx=_mlw+6,_mbw=_mw-_mbx-92,_mrh=24,_mh=_mix.length*_mrh+4; var _ms='<svg width=\"'+_mw+'\" height=\"'+_mh+'\" viewBox=\"0 0 '+_mw+' '+_mh+'\" xmlns=\"http://www.w3.org/2000/svg\" style=\"max-width:100%\">'; for(var mi=0;mi<_mix.length;mi++){ var _mit=_mix[mi]; var _mr=Math.max(0,Math.min(100,_mit.rate||0)); var _my=mi*_mrh+_mrh/2; var _mbv=Math.max(_mbw*_mr/100,2); var _mlb=String(_mit.label||''); if(_mlb.length>12) _mlb=_mlb.slice(0,11)+'…'; _ms+='<text x=\"'+_mlw+'\" y=\"'+(_my+4)+'\" font-size=\"11\" font-weight=\"700\" fill=\"#334155\" text-anchor=\"end\">'+_mlb+'</text>'; _ms+='<rect x=\"'+_mbx+'\" y=\"'+(_my-8)+'\" width=\"'+_mbw+'\" height=\"16\" rx=\"8\" fill=\"#f1f5f9\"/>'; _ms+='<rect x=\"'+_mbx+'\" y=\"'+(_my-8)+'\" width=\"'+_mbv.toFixed(1)+'\" height=\"16\" rx=\"8\" fill=\"'+_mit.color+'\"/>'; _ms+='<text x=\"'+(_mbx+_mbw+5)+'\" y=\"'+(_my+4)+'\" font-size=\"10\" font-weight=\"700\" fill=\"'+_mit.color+'\" text-anchor=\"start\">'+_mr+'%（'+(_mit.total||0)+'問）</text>'; } _ms+='</svg>'; H.push('<div style=\"margin-top:8px;border-top:1px dashed #e2e8f0;padding-top:7px\"><div style=\"font-size:12px;font-weight:800;margin-bottom:3px\"><span style=\"color:#16a34a\">💪 とくい</span> ／ <span style=\"color:#ea580c\">🌱 のばす</span> ／ <span style=\"color:#0369a1\">🔁 下の学年の復習</span></div>'+_ms+'</div>'); } H.push('</div>');", "new": "/* 📊 KARTE_SLIM_V1 (2026-09-25) 横棒グラフ（💪とくい／🌱のばす／🔁復習）を外した。\n   実測で、ここに並ぶ単元が 📚メニュー の単元と完全に一致していた（3人で確認）。\n   「のばす」「復習」は 📚メニュー に正答率・問題の種類・1問あたりの回数つきで出ており、\n   「とくい」は 💪とくいなところ に文字で出る。同じことを紙の3か所で言っていた。\n   （9/9 の改修で1本に統合したはずが、メニューを詳しくしたぶん また重複していた） */\n        H.push('</div>');"}, {"tag": "H2_shrink_graphs", "old": "H.push('<div class=\"sec\"><h2>📊 今年度の学習の見える化</h2><div style=\"display:flex;flex-wrap:wrap;gap:8px;align-items:flex-start;justify-content:space-around\">');", "new": "H.push('<div class=\"sec\"><h2>📊 今年度の学習の見える化</h2><div style=\"zoom:0.82;display:flex;flex-wrap:wrap;gap:8px;align-items:flex-start;justify-content:space-around\">');   /* KARTE_SLIM_V1 グラフは残す。高さだけ詰める（先生の「見た目も大切」） */"}, {"tag": "H3_good_text", "old": "var _extra=[]; if(reviewGood.length){", "new": "var _extra=[];\n        /* KARTE_SLIM_V1 横棒から消えた「💪とくい」を、ここに文字で残す。 */\n        if(good.length){ var _gd=[]; for(var _gi=0;_gi<good.length&&_gi<3;_gi++){ _gd.push(esc(_unitJa(good[_gi].unit))+'('+good[_gi].rate+'%)'); } _extra.push('<div style=\"font-size:12px;color:#16a34a;font-weight:700\">💪 いまの学年でよくできている … '+_gd.join('、')+'</div>'); }\n        if(reviewGood.length){"}, {"tag": "H4_style_vary", "old": "        var styleFor=function(p){\n          var r=Number(p.repeatPer);\n          if(r&&r>=5) return '同じ問題をなん回も解いとる単元やから、答えを覚えてるだけかもしれん。新しい問題のほうに行ってみよう';\n          if(r&&r>0&&r<2) return 'まだ1問を1回ずつ。出会ったばかりやから、まちがえた問題をその場でもう一度だけ解き直すところから';\n          return 'まちがえた問題に印をつけて、次の日にもう一度だけ解き直す';\n        };", "new": "        /* KARTE_SLIM_V1 反復回数が3単元とも同じ帯に入ると、この一文まで同じになっていた。\n           単元の位置（1番目＝いま効く／2番目＝つぎ／3番目＝ならし）でも言い方を変える。 */\n        var styleFor=function(p, i){\n          var r=Number(p.repeatPer);\n          if(r&&r>=5){\n            if(i===0) return '同じ問題をなん回も解いとるな。答えを覚えてるだけかもしれんから、新しい問題に当たってみよう';\n            if(i===1) return 'ここも回数が多い。数をこなすより、1問をていねいに見るほうが効くと思うで';\n            return '回数は十分。たまに別の問題で試して、ほんまに分かってるか確かめてみ';\n          }\n          if(r&&r>0&&r<2){\n            if(i===0) return 'まだ1問を1回ずつ。出会ったばかりやから、まちがえた1問をその場で解き直すところから';\n            if(i===1) return 'ここも始めたばかり。答えを見てからでええから、もう一度自分で書いてみよう';\n            return 'まだ数が少ない単元。今週は1問でも当たれたら上出来や';\n          }\n          if(i===0) return 'まちがえた問題に印をつけて、次の日にもう一度だけ解き直す';\n          if(i===1) return '前にまちがえた問題だけ、さっと見直す';\n          return '思い出せるかどうかだけ、ためしてみる';\n        };"}, {"tag": "H5_style_call", "old": "+ '<span style=\"font-size:11px;color:#475569\">'+esc(styleFor(p))+'</span></li>');", "new": "+ '<span style=\"font-size:11px;color:#475569\">'+esc(styleFor(p, i))+'</span></li>');"}]""")
bad = False
for e in EDITS:
    n = src.count(e['old'])
    print('%-18s アンカー %d 件' % (e['tag'], n))
    if n != 1:
        print('NG: %s のアンカーが %d か所' % (e['tag'], n)); bad = True
if bad: sys.exit(1)

out = src
for e in EDITS:
    out = out.replace(e['old'], e['new'], 1)

after = chain_count(out)
print('適用後のチェーン = %d' % after)
if after != CHAIN_BEFORE:
    print('NG: チェーンが変わりました（%d -> %d）' % (before, after)); sys.exit(1)

need = {'KARTE_SLIM_V1': 4, '_mix': 0, 'styleFor(p, i)': 1, 'zoom:0.82': 1,
        '_kRadar': 2, '_kBars': 2, '_kDonut': 2, 'いまの学年でよくできている': 1}
for k, want in need.items():
    got = out.count(k)
    print('適用後 %-28s %d 件（期待 %d）' % (k, got, want))
    if got != want: bad = True

for k in ['cannot_trade_special', 'genElectric6', '__WORLD_V3__', 'WARMIX', '_hash',
          'karte_material_uses', '_karteWeekOf', 'KARTE_MENU_V1', 'KARTE_FRESH_V1', '__DEFMOP_V1__']:
    if out.count(k) < 1:
        print('NG: 安全マーカー %r が消えました' % k); bad = True
if bad: sys.exit(1)

open(SRC, 'w', encoding='utf-8', newline='').write(out)
print('OK: %d -> %d バイト（%+d）' % (len(src), len(out), len(out) - len(src)))
