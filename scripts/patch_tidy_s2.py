#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_tidy_s2.py --- 家庭学習タブの整理 段階2（消さずに、畳む・置き場所を正す）

  ★ この段階でも機能を1つも消しません。場所を変えるだけです。

  U1 「2 今週の計画」を ③ の折りたたみへ
     ボタン1個ぶんの中身しかないサブタブを1枚使っていた。
     ③（見て返す作業をしている画面）の中に <details> で置く。
     ・開いたときに自動で読み込む（毎回「読み込む」を押さなくてよくなる）
     ・「🔄 読み込み直す」ボタンも残す
     ・studentPlansList の id はそのまま＝ loadStudentPlans() は無改造で動く

  U2 名簿管理（プライバシー保護）を 📚クラス管理タブへ移設
     「今週の課題を出す」作業（毎週）と「名簿とプライバシー」（年度はじめ）は
     目的も頻度も違うのに同じタブに縦に並んでいた。
     クラスと名簿は同じ話なので、クラス管理タブに置くのが自然。
     ・CSV方式・画面方式とも、そのまま移す（どちらも残す）
     ・番号が ①③④ と飛んでいたのを ①②③ に振り直す（説明文と一致させる）
     ・普段は閉じておく（<details>）。年度はじめにしか使わないため

  U3 サブタブの番号を振り直す（「2 今週の計画」が無くなるため 1, 2, 📊）

  ★ 消していないもの
     生徒の今週の計画、名簿CSVダウンロード／アップロード、クラウド名の匿名化、
     名簿リセット、表示名の画面編集、今週の課題、提出状況、写真ギャラリー
"""
import io, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
src = io.open(TSX, encoding='utf-8').read()
orig = src
done = []

def fail(m):
    print('❌ 中止: ' + m); sys.exit(1)

def sub(tag, old, new, sentinel):
    global src
    if sentinel in src:
        print('⏭  %s は適用ずみ（スキップ）' % tag); return
    if src.count(old) != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, src.count(old)))
    src = src.replace(old, new, 1)
    done.append(tag)

def cut(tag, old):
    """消すだけの手順。消す対象が「もう無い」なら適用ずみ扱い"""
    global src
    if old not in src:
        print('⏭  %s は適用ずみ（スキップ）' % tag); return
    if src.count(old) != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, src.count(old)))
    src = src.replace(old, '', 1)
    done.append(tag)

def block_at(text, start, opener=r'<div\b', closer='</div>'):
    """start から始まる要素の範囲（閉じタグの次）を、開き／閉じを数えて返す"""
    d = 0
    for m in re.finditer(r'(' + opener + r')|(' + re.escape(closer) + r')', text[start:]):
        if m.group(1): d += 1
        else:
            d -= 1
            if d == 0: return start + m.end()
    return -1

# ══════════════════════════════════════════════════════════
# U2-a 名簿管理ブロックを切り出す（あとでクラス管理タブへ入れる）
# ══════════════════════════════════════════════════════════
ROSTER_MARK = '<!-- 名簿管理（プライバシー保護） -->'
roster_html = None
# ⚠ 移設ずみの判定は「移設先ができているか」で行う。
#   目印のコメントは移設後もブロックの中に残るので、それを合図にすると
#   2回目に「クラス管理タブから切り取って、どこにも入れない」＝機能消失になる。
#   （実際に2回目でそうなり、下の機能チェックが止めてくれた）
if 'id="rosterAdminBox"' in src:
    print('⏭  U2a 名簿管理の取り外し は適用ずみ（スキップ）')
elif ROSTER_MARK in src:
    if src.count(ROSTER_MARK) != 1: fail('名簿管理の目印が %d 個' % src.count(ROSTER_MARK))
    a = src.index(ROSTER_MARK)
    b = block_at(src, src.index('<div', a))
    if b < 0: fail('名簿管理ブロックの閉じタグが見つかりません')
    roster_html = src[a:b]
    # 範囲の妥当性（機能を巻き込まない／取りこぼさない）
    for need in ['downloadStudentCSV()', 'uploadStudentCSV(event)', 'anonymizeCloudNames()',
                 'clearStudentCSV()', 'loadNameEditor()', 'id="nameEditList"', 'id="csvStatusMsg"']:
        if need not in roster_html: fail('名簿管理の範囲に %s が入っていません（狭すぎ）' % need)
    for bad in ['saveWeeklyMenu()', 'id="menuKanjiPage"', 'id="hwPane_', '<script']:
        if bad in roster_html: fail('名簿管理の範囲に %s が入っています（広すぎ）' % bad)
    if len(roster_html) > 2600: fail('名簿管理の範囲が %d 字（広すぎ）' % len(roster_html))
    src = src[:a] + src[b:]
    done.append('U2a 名簿管理ブロックを先生メニューから取り外す（%d字）' % len(roster_html))
else:
    print('⏭  U2a 名簿管理の取り外し は適用ずみ（スキップ）')

# ══════════════════════════════════════════════════════════
# U2-b 📚クラス管理タブに置く（普段は閉じておく）
# ══════════════════════════════════════════════════════════
CLS_OLD = """<div id="tabPaneClasses" class="space-y-4">
        <div id="classList" class="space-y-4"></div>
      </div>"""
if 'id="rosterAdminBox"' in src:
    print('⏭  U2b クラス管理タブへの設置 は適用ずみ（スキップ）')
else:
    if roster_html is None:
        fail('名簿管理ブロックを取り出せていないのに設置しようとしています')
    if src.count(CLS_OLD) != 1: fail('クラス管理タブのアンカーが %d 箇所' % src.count(CLS_OLD))
    # 番号の振り直し（①③④ ＋ 番号なし → ①②③ ＋ 番号なし）
    fixed = roster_html
    fixed = fixed.replace('📥 ① 現在の名簿をCSVダウンロード', '📥 ① 名簿をCSVでダウンロード')
    fixed = fixed.replace('📤 ③ 名簿CSVアップロード', '📤 ② 直したCSVをアップロード')
    fixed = fixed.replace('🔒 ④ クラウド側の名前を空にする', '🔒 ③ クラウド側の名前を空にする')
    fixed = fixed.replace(
        '① 「名簿CSVダウンロード」で現在の児童リストを取得 → ②必要なら実名に編集 → ③「名簿CSVアップロード」で先生のブラウザに保存。<br>',
        '① CSVをダウンロード → 表計算ソフトで実名に直す → ② そのCSVをアップロード（先生のブラウザにだけ保存されます）。<br>')
    fixed = fixed.replace('<span class="font-bold">④最後に', '<span class="font-bold">③最後に')
    CLS_NEW = """<div id="tabPaneClasses" class="space-y-4">
        <div id="classList" class="space-y-4"></div>
        <!-- 📌 2026-09 整理: 名簿とプライバシーは「年度はじめの作業」で、
             毎週の家庭学習とは別の話。クラスと名簿は同じ話なのでこちらへ移した。
             機能は1つも減らしていない（CSV方式・画面方式とも そのまま）。
             普段は閉じておき、使うときだけ開く。 -->
        <details id="rosterAdminBox" class="bg-white rounded-xl shadow p-3">
          <summary class="cursor-pointer font-bold text-sm text-rose-800 select-none">🔒 名簿管理（プライバシー保護）</summary>
          <div class="mt-3">
""" + fixed + """
          </div>
        </details>
      </div>"""
    src = src.replace(CLS_OLD, CLS_NEW, 1)
    done.append('U2b 名簿管理をクラス管理タブへ設置（番号を①②③に振り直し）')

# ══════════════════════════════════════════════════════════
# U1 「2 今週の計画」を ③ の折りたたみへ
# ══════════════════════════════════════════════════════════
PLAN_NEW = """<!-- 📌 2026-09 整理: 「2 今週の計画」はボタン1個ぶんの中身しかないサブタブだった。
             返す作業をしている③の中へ、折りたたみとして移した（機能はそのまま）。 -->"""
if 'ボタン1個ぶんの中身しかないサブタブだった' in src:
    print('⏭  U1a 今週の計画のサブタブを取り外す は適用ずみ（スキップ）')
else:
    # 空白の入り方に左右されないよう、開きタグから <div> の対応を数えて切る
    if src.count('<div id="hwPane_plan"') != 1:
        fail('hwPane_plan の開始タグが %d 箇所' % src.count('<div id="hwPane_plan"'))
    _a = src.index('<div id="hwPane_plan"')
    _mark = '<!-- サブタブ②: 今週の計画 -->'
    if _mark in src[max(0, _a-200):_a]:
        _a = src.rindex(_mark, 0, _a)
    _end = block_at(src, src.index('<div id="hwPane_plan"'))
    if _end < 0: fail('hwPane_plan の閉じタグが見つかりません')
    _blk = src[_a:_end]
    for _need in ['id="studentPlansList"', 'loadStudentPlans()']:
        if _need not in _blk: fail('hwPane_plan の範囲に %s が入っていません' % _need)
    for _bad in ['id="hwPane_daily"', 'id="hwList"', '<script', 'id="hwPane_menu"']:
        if _bad in _blk: fail('hwPane_plan の範囲に %s が入っています（広すぎ）' % _bad)
    if len(_blk) > 1200: fail('hwPane_plan の範囲が %d 字（広すぎ）' % len(_blk))
    src = src[:_a] + PLAN_NEW + src[_end:]
    done.append('U1a 今週の計画のサブタブを取り外す（%d字）' % len(_blk))

PLAN_INTO_OLD = """          <div id="hwList" class="space-y-3 text-sm">"""
PLAN_INTO_NEW = """          <!-- 📌 2026-09 整理: 「2 今週の計画」をここへ畳んだ。
               開いたときに自動で読み込むので、毎回ボタンを押さなくてよい。 -->
          <details id="hwPlanBox" class="bg-blue-50 border border-blue-200 rounded-xl p-3 mb-3" ontoggle="if(this.open) hwPlanOpened();">
            <summary class="cursor-pointer font-bold text-sm text-blue-800 select-none">📝 生徒の今週の計画</summary>
            <div class="mt-2 flex justify-end">
              <button onclick="loadStudentPlans()" class="bg-blue-600 text-white rounded-lg px-3 py-1 text-xs font-bold shadow hover:opacity-90">🔄 読み込み直す</button>
            </div>
            <div id="studentPlansList" class="space-y-2 text-sm text-slate-700 mt-2">
              <p class="text-xs text-slate-400">開くと読み込みます</p>
            </div>
          </details>
          <div id="hwList" class="space-y-3 text-sm">"""
sub('U1b 今週の計画を③の折りたたみへ', PLAN_INTO_OLD, PLAN_INTO_NEW, 'id="hwPlanBox"')

# 開いたときに1回だけ読み込む
OPEN_OLD = """      // 📌 2026-09 整理: 期間プルダウンの中身を作る（年度はじめ4月〜今月）。"""
OPEN_NEW = """      // 📌 2026-09 整理: 「今週の計画」を開いたら1回だけ読み込む。
      //   毎回「読み込む」を押させないため。閉じて開き直しても読み直さない
      //   （読み直したいときは中の「🔄 読み込み直す」を押す）。
      window._hwPlanLoaded = false;
      function hwPlanOpened(){
        if(window._hwPlanLoaded) return;
        window._hwPlanLoaded = true;
        try{ loadStudentPlans(); }catch(e){}
      }

      // 📌 2026-09 整理: 期間プルダウンの中身を作る（年度はじめ4月〜今月）。"""
sub('U1c 開いたら1回だけ読み込む', OPEN_OLD, OPEN_NEW, 'function hwPlanOpened()')

# ナビのボタンを外す
NAV_OLD = """          <button id="hwSubTab_plan" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchHomeworkSubTab('plan')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">2</span> 今週の計画
          </button>
"""
cut('U1d ナビから「2 今週の計画」を外す', NAV_OLD)

# 切り替え関数から plan を外す
SW_OLD = """        const tabs = ['dashboard','menu','plan','daily'];
        const colors = {dashboard:'indigo',menu:'green',plan:'blue',daily:'emerald'};"""
SW_NEW = """        const tabs = ['dashboard','menu','daily'];
        const colors = {dashboard:'indigo',menu:'green',daily:'emerald'};"""
sub('U1e 切り替え関数から plan を外す', SW_OLD, SW_NEW, "const tabs = ['dashboard','menu','daily'];")

SW2_OLD = """        if(sub === 'plan') loadStudentPlans();
"""
cut('U1f 切り替え時の plan 分岐を外す', SW2_OLD)

# ══════════════════════════════════════════════════════════
# U3 番号の振り直し（3 毎日の振り返り → 2）
# ══════════════════════════════════════════════════════════
NUM_OLD = """            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">3</span> 毎日の振り返り"""
NUM_NEW = """            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">2</span> 毎日の振り返り"""
sub('U3 「毎日の振り返り」の番号を 3 → 2', NUM_OLD, NUM_NEW, 'font-black">2</span> 毎日の振り返り')

# ══════════════════════════════════════════════════════════
# 検証 ── 合言葉とは別に「結果そのもの」を見る
# ══════════════════════════════════════════════════════════
i = src.index('id="tabPaneHomework"'); j = src.index('id="tabPaneMissions"', i)
hw = src[i:j]
i2 = src.index('id="tabPaneClasses"'); j2 = src.index('id="tabPaneAnalytics"', i2)
cls = src[i2:j2]

# ★1 機能がどこにも消えていないこと（ページ全体で存在を見る）
for must in ['downloadStudentCSV()', 'uploadStudentCSV(event)', 'anonymizeCloudNames()',
             'clearStudentCSV()', 'loadNameEditor()', 'id="nameEditList"', 'id="csvStatusMsg"',
             'loadStudentPlans()', 'id="studentPlansList"',
             'saveWeeklyMenu()', 'id="menuKanjiPage"', 'id="menuDayMon"',
             'loadSubmissionDashboard()', 'loadPhotoGallery()', 'dashWeekPrev()',
             'id="hwClassFilter"', 'id="hwStatusFilter"', 'id="hwMonthFilter"',
             'bulkReturnNoComment()', 'id="hwList"', 'id="hwSummaryBar"', 'id="hwDateTabs"']:
    if must not in src: fail('★機能が失われました: %s' % must)
print('🔎 名簿CSV・画面編集・今週の計画・今週の課題・提出状況・写真・返却まわりはすべて残っています')

# ★2 置き場所が正しく変わったこと
if 'downloadStudentCSV()' in hw: fail('名簿管理がまだ家庭学習タブに残っています')
if 'downloadStudentCSV()' not in cls: fail('名簿管理がクラス管理タブに入っていません')
if 'id="rosterAdminBox"' not in cls: fail('名簿管理の折りたたみがクラス管理タブにありません')
print('🔎 名簿管理は 家庭学習タブ → クラス管理タブ へ移りました（折りたたみの中）')

if 'id="hwPane_plan"' in src or 'id="hwSubTab_plan"' in src:
    fail('「2 今週の計画」のサブタブが残っています')
if 'id="hwPlanBox"' not in hw: fail('今週の計画の折りたたみが③にありません')
if 'id="studentPlansList"' not in hw: fail('今週の計画の中身が③にありません')
print('🔎 「今週の計画」は サブタブ → ③の折りたたみ へ移りました')

# ★3 番号の飛び・重複がないこと
nums = re.findall(r'font-black">([0-9📊])</span>', hw)
if nums != ['1','2','📊']:
    fail('サブタブの番号が %s になっています（1,2,📊 のはず）' % nums)
print('🔎 サブタブの番号: 1, 2, 📊（飛びなし・重複なし）')

# ★4 名簿の番号が ①②③ に揃っていること
for want in ['📥 ① 名簿をCSVでダウンロード', '📤 ② 直したCSVをアップロード', '🔒 ③ クラウド側の名前を空にする']:
    if want not in cls: fail('名簿の番号が振り直されていません: %s' % want)
for bad in ['📤 ③ 名簿CSVアップロード', '🔒 ④ クラウド側の名前を空にする']:
    if bad in src: fail('古い番号が残っています: %s' % bad)
print('🔎 名簿の手順は ①②③（もとは ①③④ で②が飛んでいた）')

# ★5 切り替え関数に plan が残っていないこと
sw = src[src.index('function switchHomeworkSubTab'):src.index('function switchHomeworkSubTab')+1500]
if "'plan'" in sw: fail('切り替え関数に plan が残っています')
print('🔎 切り替え関数から plan が消えています')

# ★6 いつもの安全確認
def rc(t):
    a = t.index("app.get('/', async (c) => {"); b = t.index("app.get('/logout'", a)
    return t[a:b].count('.replace(')
if rc(src) != rc(orig): fail('置換チェーンの数が変わりました（%d → %d）' % (rc(orig), rc(src)))
print('🔎 置換チェーン: %d 件（パッチ前と同じ）' % rc(src))

bal  = len(re.findall(r'<div\b', src))  - len(re.findall(r'</div>', src))
bal0 = len(re.findall(r'<div\b', orig)) - len(re.findall(r'</div>', orig))
if bal != bal0: fail('<div> の釣り合いが変わりました（%d → %d）' % (bal0, bal))
det  = len(re.findall(r'<details\b', src))  - len(re.findall(r'</details>', src))
det0 = len(re.findall(r'<details\b', orig)) - len(re.findall(r'</details>', orig))
if det != det0: fail('<details> の釣り合いが変わりました（%d → %d）' % (det0, det))
print('🔎 <div> と <details> の釣り合い: 変化なし')

n_state = src.count('state_json')
if n_state != orig.count('state_json'): fail('state_json を触る箇所が変わりました')
print('🔎 state_json を触る箇所: %d（変化なし）' % n_state)

g0 = src.index('let _adminChecked = false'); g1 = src.index('// -------------------- DB migration', g0)
for l in src[g0:g1].split('\n'):
    if 'CREATE INDEX' in l and not l.strip().startswith('//'):
        fail('起動時ミドルウェアに CREATE INDEX が復活しています')
print('🔎 起動時ミドルウェアに DDL はありません')

import hashlib
def area(t, s0, s1):
    a = t.index(s0); b = t.index(s1, a); return hashlib.md5(t[a:b].encode('utf-8')).hexdigest()
for name, s0, s1 in [('防衛戦', 'async function ensureDefenseTables', "app.post('/api/defense/reward-claim'"),
                     ('カルテ', 'function _buildKarteHtml', 'function downloadKartePdf'),
                     ('シール券', "app.post('/api/shop/sticker/buy'", "app.post('/api/shop/sticker/redeem'")]:
    if area(src, s0, s1) != area(orig, s0, s1):
        fail('%s のコードが変わっています（このパッチでは触らない）' % name)
print('🔎 防衛戦・カルテ・シール券のコードには触れていません（md5 一致）')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
print('---- 入れたもの ----')
for t in done: print(' ・' + t)
if not done: print(' （なし）')
