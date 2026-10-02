# PLANRATE_V1 (2026-10-02) 第3便
#
# 「📋 今週の計画提出率 100% 23/23人」は嘘の数字だった。
# 行があるかどうかだけで数えていて、中身が空っぽの子（月〜金ぜんぶ空）も
# 「提出」に入っていた。2026-W40 の実際は 23人中15人。
# 同じ画面の計画の箱は「15人が提出」と出しているので、先生がどちらを
# 信じればよいか分からない状態だった。学級の状態を判断する数字なので直す。
#
# この便ですること:
#   計画提出率・計画未提出者を「中身が書いてあるか」で数えなおす。
#
# 前提:
#   第2便（PLANCELL_V1）でサーバが plans_json を返すようになっていること。
#   返っていなければ数えられないので、この便は第2便のあとに流す。
#
# しないこと:
#   ・週の振り返り提出率は触らない（原因が分かるまで触らない）
#   ・表示の文言も、ほかの3つの数字も触らない
#   ・app.get('/') の .replace( チェーンは 1件も増減しない
import sys, io

PATH = 'src/index.tsx'
src = io.open(PATH, encoding='utf-8').read()

if 'PLANRATE_V1' in src:
    print('すでに適用ずみ — 何もしません'); sys.exit(0)

if 'PLANCELL_V1' not in src:
    print('NG: 第2便（PLANCELL_V1）がまだ入っていません。'
          'サーバが plans_json を返さないと中身で数えられません。中止します。'); sys.exit(1)

def chain_count(s):
    a = s.index("app.get('/'"); b = s.index("app.get('/logout'")
    return s[a:b].count('.replace(')

CHAIN_BEFORE = 158
n = chain_count(src)
if n != CHAIN_BEFORE:
    print('NG: チェーンが %d 件（期待 %d）。ほかの便と重なっています。中止します。' % (n, CHAIN_BEFORE)); sys.exit(1)
print('チェーン実測: %d 件（期待どおり）' % n)

OLD = (
"          const planCount = plans.length;\n"
"          const planRate = members.length > 0 ? Math.round(planCount / members.length * 100) : 0;\n"
"          const planMissing = members.filter(function(m){ return !planByUser[m.id]; });\n"
)

NEW = (
"          /* 2026-10-02 PLANRATE_V1: 「行がある」ではなく「中身が書いてある」で数える。\n"
"             前は空っぽの子も「提出」に数えていて、同じ画面の計画の箱が\n"
"             「15人が提出」と出しているのにここだけ 100% と出ていた。 */\n"
"          function _planHasText(p){\n"
"            if(!p) return false;\n"
"            var o = {}; try{ o = JSON.parse(p.plans_json||'{}'); }catch(_e){ return false; }\n"
"            var ks = Object.keys(o).filter(function(k){ return k !== '_modified'; });\n"
"            for(var i=0;i<ks.length;i++){\n"
"              var v = o[ks[i]];\n"
"              var t = (v && typeof v === 'object') ? (v.free||'') : (v||'');\n"
"              if(String(t).trim()) return true;\n"
"            }\n"
"            return false;\n"
"          }\n"
"          const planCount = plans.filter(_planHasText).length;\n"
"          const planRate = members.length > 0 ? Math.round(planCount / members.length * 100) : 0;\n"
"          const planMissing = members.filter(function(m){ return !_planHasText(planByUser[m.id]); });\n"
)

REF_BEFORE = src.count('const refCount = reflections.length;')

if src.count(OLD) != 1:
    print('NG: 計画提出率の目印が %d 個（1個のはず）。中止します。' % src.count(OLD)); sys.exit(1)
src = src.replace(OLD, NEW, 1)

ok = True
def chk(name, got, want):
    global ok
    mark = 'OK ' if got == want else 'NG '
    print('  %s %s: %r（期待 %r）' % (mark, name, got, want))
    if got != want: ok = False

chk('チェーン（増減なし）', chain_count(src), CHAIN_BEFORE)
chk('中身で数える関数がある', src.count('function _planHasText(p)'), 1)
chk('提出数を中身で数えている', src.count('plans.filter(_planHasText).length'), 1)
chk('未提出者も中身で数えている', src.count('!_planHasText(planByUser[m.id])'), 1)
chk('古い数え方は残っていない', src.count('const planCount = plans.length;'), 1)  # 13237行目の別物は残す
chk('週の振り返りの数え方は触っていない', src.count('const refCount = reflections.length;'), REF_BEFORE)
chk('目印 PLANRATE_V1', src.count('PLANRATE_V1') >= 1, True)

if not ok:
    print('NG: 確認に失敗。書き込みません。'); sys.exit(1)

io.open(PATH, 'w', encoding='utf-8').write(src)
print('PLANRATE_V1 を適用しました（チェーン %d -> %d）' % (CHAIN_BEFORE, chain_count(src)))
