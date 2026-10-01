# HWPLAN_TOP_V1 (2026-10-01)
#
# 先生のことば:「家庭学習の計画とか子供のやつみえない！家庭学習は別格で大切」
#
# 調べたこと:
#   子どもの週の計画は D1 に入っている（2026-W40 は 23人中15人が記入ずみ）。
#   画面も壊れていない。ただし置き場所が
#       ① 家庭学習 → ② 毎日の振り返り → 約1000px スクロール → 閉じた折りたたみ
#   の奥にあり、開いた直後の画面には影も形も出ていなかった。
#   9月の承認は3週で1件だけ。6〜7月は「書いた人数＝承認した人数」だった。
#   先生が使うのをやめたのではなく、見つからなくなっていた。
#
# この便ですること（1つだけ）:
#   「📝 生徒の今週の計画」を、家庭学習タブを開いた直後の いちばん上に、
#   最初から開いた状態で出す。折りたたみ(<details>)をやめる。
#
# しないこと:
#   ・中身の作り方（loadStudentPlans）は 1文字も変えない
#   ・高さを詰めない。畳まない。23人ぶん縦に長くなるのは承知のうえ
#     （2026-09 に「3行に詰めたせいでサポーターからのことばが65枚全部で隠れた」
#       という失敗をしている。同じことをしない）
#   ・src/index.tsx の app.get('/') の .replace( チェーンは 1件も増減しない
#
# 合わなければ 何も書かずに 落ちる（fail-closed）。
import sys, io

PATH = 'src/index.tsx'
src = io.open(PATH, encoding='utf-8').read()
orig = src

if 'HWPLAN_TOP_V1' in src:
    print('すでに適用ずみ — 何もしません')
    sys.exit(0)

# ---------------------------------------------------------------- 事前の実測
def chain_count(s):
    a = s.index("app.get('/'")
    b = s.index("app.get('/logout'")
    return s[a:b].count('.replace(')

CHAIN_BEFORE = 158
n = chain_count(src)
if n != CHAIN_BEFORE:
    print('NG: チェーンが %d 件（期待 %d）。ほかの便と重なっています。中止します。' % (n, CHAIN_BEFORE))
    sys.exit(1)
print('チェーン実測: %d 件（期待どおり）' % n)

# ------------------------------------------------- ① 古い折りたたみを取り除く
OLD = (
'          <!-- \U0001f4cc 2026-09 整理: 「2 今週の計画」をここへ畳んだ。\n'
'               開いたときに自動で読み込むので、毎回ボタンを押さなくてよい。 -->\n'
'          <details id="hwPlanBox" class="bg-blue-50 border border-blue-200 rounded-xl p-3 mb-3" ontoggle="if(this.open) hwPlanOpened();">\n'
'            <summary class="cursor-pointer font-bold text-sm text-blue-800 select-none">\U0001f4dd 生徒の今週の計画 <span id="hwPlanCount" class="ml-1 text-[11px] font-normal text-slate-500"></span></summary>\n'
'            <!-- 2026-09-29 整理(A-6): 「\U0001f504 読み込み直す」を撤去。開いたときに毎回いちばん新しいものを読む。 -->\n'
'            <div id="studentPlansList" class="space-y-2 text-sm text-slate-700 mt-2">\n'
'              <p class="text-xs text-slate-400">開くと読み込みます</p>\n'
'            </div>\n'
'          </details>\n'
)

NEW_POINTER = (
'          <!-- \U0001f4cc 2026-10-01 HWPLAN_TOP_V1: 計画はこのタブのいちばん上へ移した。 -->\n'
'          <p class="text-xs text-slate-500 mb-3">\U0001f4dd 生徒の今週の計画は、<b>このタブのいちばん上</b>に出ています。</p>\n'
)

if src.count(OLD) != 1:
    print('NG: 古い hwPlanBox の折りたたみが %d 個（1個のはず）。中止します。' % src.count(OLD))
    sys.exit(1)
src = src.replace(OLD, NEW_POINTER, 1)

# --------------------------------------- ② タブのいちばん上に、開いた状態で置く
ANCHOR = '        <!-- サブタブ: 提出状況ダッシュボード -->\n'
if src.count(ANCHOR) != 1:
    print('NG: 置き場所の目印が %d 個（1個のはず）。中止します。' % src.count(ANCHOR))
    sys.exit(1)

TOP_BLOCK = (
'        <!-- \U0001f4cc 2026-10-01 HWPLAN_TOP_V1\n'
'             家庭学習でいちばん大切な「子どもが立てた週の計画」を、\n'
'             タブを開いた直後のいちばん上に、最初から開いた状態で出す。\n'
'             前は「毎日の振り返り」の奥の折りたたみの中にあり、\n'
'             3回クリックとスクロールがいった（→先生の目に入っていなかった）。\n'
'             高さは詰めない。畭まない。縦に長くなってよい。 -->\n'
'        <div id="hwPlanBox" class="bg-blue-50 border-2 border-blue-300 rounded-xl p-3 shadow-sm">\n'
'          <div class="font-bold text-sm text-blue-800">\U0001f4dd 生徒の今週の計画 <span id="hwPlanCount" class="ml-1 text-[11px] font-normal text-slate-500"></span></div>\n'
'          <div id="studentPlansList" class="space-y-2 text-sm text-slate-700 mt-2">\n'
'            <p class="text-xs text-slate-400">読み込み中...</p>\n'
'          </div>\n'
'        </div>\n'
'\n'
)
src = src.replace(ANCHOR, TOP_BLOCK + ANCHOR, 1)

# ------------------------------------- ③ 家庭学習タブを開いたときに読み込ませる
SW_OLD = "        if(tab === 'homework') { loadWeeklyMenu(); switchHomeworkSubTab('menu'); }\n"
SW_NEW = ("        /* 2026-10-01 HWPLAN_TOP_V1: 計画は折りたたみをやめたので、\n"
          "           タブを開いたときに読み込む（renderClasses はこの前に終わっている）。 */\n"
          "        if(tab === 'homework') { loadWeeklyMenu(); switchHomeworkSubTab('menu'); try{ loadStudentPlans(); }catch(_e){} }\n")
if src.count(SW_OLD) != 1:
    print('NG: switchTab の目印が %d 個（1個のはず）。中止します。' % src.count(SW_OLD))
    sys.exit(1)
src = src.replace(SW_OLD, SW_NEW, 1)

# --------------------------------------------------------------- 適用後の確認
ok = True
def chk(name, got, want):
    global ok
    mark = 'OK ' if got == want else 'NG '
    print('  %s %s: %r（期待 %r）' % (mark, name, got, want))
    if got != want: ok = False

after = chain_count(src)
chk('チェーン（増減なし）', after, CHAIN_BEFORE)
chk('hwPlanBox は1つだけ', src.count('id="hwPlanBox"'), 1)
chk('studentPlansList は1つだけ', src.count('id="studentPlansList"'), 1)
chk('hwPlanCount は1つだけ', src.count('id="hwPlanCount"'), 1)
chk('<details id="hwPlanBox" は残っていない', src.count('<details id="hwPlanBox"'), 0)
chk('ontoggle の折りたたみは残っていない', src.count('hwPlanOpened();"'), 0)
chk('タブを開いたときに読み込む', src.count('try{ loadStudentPlans(); }catch(_e){}'), 1)
chk('目印 HWPLAN_TOP_V1', src.count('HWPLAN_TOP_V1') >= 3, True)

# 置き場所が本当に hwPane_daily の外に出たか（= タブ直下にあるか）を位置で確かめる
i_nav  = src.index('id="hwSubTab_dashboard"')
i_box  = src.index('id="hwPlanBox"')
i_dash = src.index('id="hwPane_dashboard"')
i_menu = src.index('id="hwPane_menu"')
i_daily= src.index('id="hwPane_daily"')
chk('計画の箱はサブタブの並びより下', i_nav < i_box, True)
chk('計画の箱は「提出状況」の中身より上', i_box < i_dash, True)
chk('計画の箱は「先生メニュー」より上', i_box < i_menu, True)
chk('計画の箱は「毎日の振り返り」より上', i_box < i_daily, True)

# 9/26に2時間止まった事故の形を作っていないこと
bad = src.count("onclick=\"") and False
chk('生のクォートを含む onclick を増やしていない', "('" in TOP_BLOCK or "(\\'" in TOP_BLOCK, False)

if not ok:
    print('NG: 確認に失敗。書き込みません。')
    sys.exit(1)

io.open(PATH, 'w', encoding='utf-8').write(src)
print('HWPLAN_TOP_V1 を適用しました（チェーン %d -> %d）' % (CHAIN_BEFORE, after))
