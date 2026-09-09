#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_tidy_s1.py --- 家庭学習タブの整理 段階1（消さずに、まとめる・畳む・置き場所を正す）

  先生「機能は充実させてほしい。でも整理はしてほしい」

  ★ この段階では機能を1つも消しません。まとめるだけです。

  T1 ③のフィルタ行を 8 → 5 にまとめる
     ・「絞り込み」と「更新」は中身が1文字も違わない（どちらも loadHomework()）→ 1つに
     ・「未返却」（状態プルダウン）と「🔴 未返却をぜんぶ表示」は同じことを言っている
       → 表示プルダウン1つに統合。「未返却だけ」を選ぶと、
         画面のしぼりこみ（従来）とサーバ側の未返却モード（unreturned=1）の両方が効く
     ・期間は <input type="month"> の数字入力をやめ、
       「すべての期間 / 2026年4月 …」のプルダウンに（年度はじめ〜今月を自動で並べる）
       これで「絞り込みを解除」ボタンが要らなくなる（＝先頭の「すべての期間」を選ぶだけ）
     ・クラス・表示・期間は「選んだら即反映」。押す手間をなくす

  T2 中身が空のサブタブ「4 今週の振り返り」を削除
     案内文だけのタブ。機能ではないので消してよい、と確認ずみ。
     案内は③の下に1行として残す（＝情報は失わない）

  T3 サブタブの番号を振り直す（4が消えるため）

  ★ 消していないもの（全部そのまま動きます）
     すべて／未返却／返却済みの3通りの表示、月しぼりこみ、未返却をぜんぶ表示、
     まとめて返却、日付タブ、サマリーバー、未提出者リスト、
     ①先生メニュー、②今週の計画、📊提出状況、名簿管理（CSV方式・画面方式とも）
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
    """sentinel が「もうある」なら適用ずみ扱い（追加・置換むけ）"""
    global src
    if sentinel in src:
        print('⏭  %s は適用ずみ（スキップ）' % tag); return
    if src.count(old) != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, src.count(old)))
    src = src.replace(old, new, 1)
    done.append(tag)

def cut(tag, old):
    """消すだけの手順。消す対象が「もう無い」なら適用ずみ扱い。
       （追加むけの sub() と同じ合言葉の考え方を使うと、消す前の状態を
         『適用ずみ』と誤判定してしまう。9/8に同じ型の失敗をしたので分けた）"""
    global src
    if old not in src:
        print('⏭  %s は適用ずみ（スキップ）' % tag); return
    if src.count(old) != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, src.count(old)))
    src = src.replace(old, '', 1)
    done.append(tag)

# ══════════════════════════════════════════════════════════
# T1 ③のフィルタ行
# ══════════════════════════════════════════════════════════
T1_OLD = """            <select id="hwClassFilter" class="border p-2 rounded text-sm bg-white"></select>
            <select id="hwStatusFilter" class="border p-2 rounded text-sm bg-white">
              <option value="">すべて</option>
              <option value="unreturned">未返却</option>
              <option value="returned">返却済み</option>
            </select>
            <button onclick="loadHomework()" class="bg-emerald-600 text-white rounded px-3 py-1 text-sm font-bold">絞り込み</button>
            <button onclick="loadHomework()" class="bg-slate-200 rounded px-3 py-1 text-sm">更新</button>
            <!-- 📌 2026-09: 一覧は新しい100件で打ち切られるため、古い提出に辿り着けなかった。
                 「未返却をぜんぶ」と「月しぼりこみ」を足して、7月ぶんにも届くようにする。 -->
            <button onclick="hwShowAllUnreturned()" id="hwAllUnreturnedBtn" class="bg-red-500 text-white rounded px-3 py-1 text-sm font-bold">🔴 未返却をぜんぶ表示</button>
            <input type="month" id="hwMonthFilter" class="border p-1 rounded text-sm bg-white" onchange="loadHomework()" title="この月の提出だけを表示します"/>
            <button onclick="hwClearFilters()" class="bg-slate-100 rounded px-2 py-1 text-xs">絞り込みを解除</button>
            <button onclick="bulkReturnNoComment()" class="ml-auto bg-blue-500 text-white rounded-lg px-4 py-1.5 text-sm font-bold shadow hover:opacity-90">✅ 未返却をまとめて返却（コメントなし）</button>"""
T1_NEW = """            <!-- 📌 2026-09 整理: ここは操作が8つ並んでいて、しかも
                   ・「絞り込み」と「更新」が同じ関数（loadHomework）
                   ・状態の「未返却」と「🔴 未返却をぜんぶ表示」が同じことを言っている
                 という重複があった。機能は1つも減らさず、5つにまとめている。 -->
            <label class="text-xs text-slate-500">クラス</label>
            <select id="hwClassFilter" class="border p-2 rounded text-sm bg-white" onchange="loadHomework()"></select>
            <label class="text-xs text-slate-500">表示</label>
            <select id="hwStatusFilter" class="border p-2 rounded text-sm bg-white" onchange="loadHomework()">
              <option value="">すべて</option>
              <option value="unreturned">未返却だけ（月をまたいで全部）</option>
              <option value="returned">返却済みだけ</option>
            </select>
            <label class="text-xs text-slate-500">期間</label>
            <select id="hwMonthFilter" class="border p-2 rounded text-sm bg-white" onchange="loadHomework()" title="この月の提出だけを表示します">
              <option value="">すべての期間</option>
            </select>
            <button onclick="loadHomework()" class="bg-slate-200 rounded px-3 py-1 text-sm" title="いまの条件でもう一度読み込みます">🔄 更新</button>
            <button onclick="bulkReturnNoComment()" class="ml-auto bg-blue-500 text-white rounded-lg px-4 py-1.5 text-sm font-bold shadow hover:opacity-90">✅ 未返却をまとめて返却（コメントなし）</button>"""
sub('T1 ③のフィルタ行を8→5にまとめる', T1_OLD, T1_NEW, '未返却だけ（月をまたいで全部）')

# ---- 期間プルダウンの中身を作る＋状態と未返却モードを連動させる ----
T1B_OLD = """      // 📌 2026-09: 「🔴 未返却をぜんぶ表示」の ON/OFF
      window._hwOnlyUnreturned = false;
      function hwShowAllUnreturned(){"""
T1B_NEW = """      // 📌 2026-09 整理: 期間プルダウンの中身を作る（年度はじめ4月〜今月）。
      //   <input type="month"> の数字入力より、並んでいる中から選ぶほうが速い。
      //   先頭の「すべての期間」を選べば解除になるので、解除ボタンが要らない。
      function hwFillMonthOptions(){
        var sel = document.getElementById('hwMonthFilter');
        if(!sel || sel.dataset.filled === '1') return;
        var now = new Date();
        var y = now.getFullYear(), m = now.getMonth() + 1;
        var fyStartY = (m >= 4) ? y : y - 1;   // 年度は4月はじまり
        var opts = [];
        var cy = fyStartY, cm = 4;
        while (cy < y || (cy === y && cm <= m)) {
          opts.push({ v: cy + '-' + String(cm).padStart(2,'0'), t: cy + '年' + cm + '月' });
          cm++; if(cm > 12){ cm = 1; cy++; }
        }
        opts.reverse();  // 新しい月を上に
        opts.forEach(function(o){
          var el = document.createElement('option');
          el.value = o.v; el.textContent = o.t;
          sel.appendChild(el);
        });
        sel.dataset.filled = '1';
      }

      // 📌 2026-09 整理: 「未返却だけ」を選んだら、画面のしぼりこみ（従来）と
      //   サーバ側の未返却モード（unreturned=1／月をまたいで最大500件）の両方を効かせる。
      //   もとは同じ意味の操作が2つ（状態プルダウンと 🔴 ボタン）に分かれていた。
      window._hwOnlyUnreturned = false;
      function hwSyncUnreturnedMode(){
        var st = document.getElementById('hwStatusFilter');
        window._hwOnlyUnreturned = !!(st && st.value === 'unreturned');
      }

      function hwShowAllUnreturned(){"""
sub('T1b 期間プルダウンと未返却モードの連動', T1B_OLD, T1B_NEW, 'function hwFillMonthOptions()')

# ---- loadHomework の先頭で毎回同期する ----
T1C_OLD = """      async function loadHomework(){
        const wrap = document.getElementById('hwList');
        wrap.innerHTML='<p class="text-slate-400">読み込み中...</p>';"""
T1C_NEW = """      async function loadHomework(){
        hwFillMonthOptions();
        hwSyncUnreturnedMode();
        const wrap = document.getElementById('hwList');
        wrap.innerHTML='<p class="text-slate-400">読み込み中...</p>';"""
sub('T1c 読み込みのたびに期間と表示を同期', T1C_OLD, T1C_NEW, 'hwSyncUnreturnedMode();\n        const wrap')

# ══════════════════════════════════════════════════════════
# T2 空のサブタブ「4 今週の振り返り」を消し、案内を③の末尾へ移す
# ══════════════════════════════════════════════════════════
T2_NEW = """<!-- 📌 2026-09 整理: 「4 今週の振り返り」は案内文だけのサブタブだったので、
             タブごと畳んで③の下に1行の案内として置いた。機能は元から無い。 -->"""
if '案内文だけのサブタブだったので' in src:
    print('⏭  T2 空のサブタブ「4 今週の振り返り」を畳む は適用ずみ（スキップ）')
else:
    # 空白の入り方に左右されないよう、開きタグから <div> の対応を数えて切る
    if src.count('<div id="hwPane_weekly"') != 1:
        fail('hwPane_weekly の開始タグが %d 箇所' % src.count('<div id="hwPane_weekly"'))
    _a = src.index('<div id="hwPane_weekly"')
    _mark = '<!-- サブタブ④: 今週の振り返り -->'
    if src[max(0, _a-200):_a].find(_mark) >= 0:
        _a = src.rindex(_mark, 0, _a)
    _depth = 0; _end = None
    for _m in re.finditer(r'(<div\b)|(</div>)', src[_a:]):
        if _m.group(1): _depth += 1
        else:
            _depth -= 1
            if _depth == 0: _end = _a + _m.end(); break
    if _end is None: fail('hwPane_weekly の閉じタグが見つかりません')
    _blk = src[_a:_end]
    # 切る範囲の中身が「案内文だけ」であることを確かめる（機能を巻き込まないため）
    if '今週の振り返りへの返却は、分析タブに移りました' not in _blk:
        fail('hwPane_weekly の範囲がおかしいです（案内文が入っていません）')
    for _bad in ['<button', '<select', '<input', '<textarea', '<script', 'id="hwList"', 'id="hwPane_daily"']:
        if _bad in _blk: fail('hwPane_weekly の範囲に %s が入っています（広すぎ）' % _bad)
    if len(_blk) > 900: fail('hwPane_weekly の範囲が %d 字（広すぎ）' % len(_blk))
    src = src[:_a] + T2_NEW + src[_end:]
    done.append('T2 空のサブタブ「4 今週の振り返り」を畳む（%d字）' % len(_blk))

# ナビのボタンを消す
T2C_OLD = """          <button id="hwSubTab_weekly" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchHomeworkSubTab('weekly')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">4</span> 今週の振り返り
          </button>
"""
cut('T2b ナビから「4 今週の振り返り」を外す', T2C_OLD)

# 案内を③の末尾（hwList の直後）に置く
T2D_OLD = """          <div id="hwList" class="space-y-3 text-sm">"""
T2D_NEW = """          <div id="hwList" class="space-y-3 text-sm">
          <!-- 📌 2026-09 整理: 空だった「4 今週の振り返り」タブの案内を、ここに1行で移した -->
          <p class="text-[11px] text-slate-400 mt-2 border-t pt-2">
            週の振り返りへの返却は <b>分析タブ →「📋 今日のひと往復」</b> です。
            「今回ふくめるもの」の<b>週の振り返りの返却</b>にチェックを入れてください（金曜日は自動でON）。
          </p>"""
sub('T2c 案内を③の末尾に移設', T2D_OLD, T2D_NEW, '空だった「4 今週の振り返り」タブの案内を')

# 切り替え関数から weekly を外す
T2E_OLD = """        const tabs = ['dashboard','menu','plan','daily','weekly'];
        const colors = {dashboard:'indigo',menu:'green',plan:'blue',daily:'emerald',weekly:'yellow'};"""
T2E_NEW = """        const tabs = ['dashboard','menu','plan','daily'];
        const colors = {dashboard:'indigo',menu:'green',plan:'blue',daily:'emerald'};"""
sub('T2d 切り替え関数から weekly を外す', T2E_OLD, T2E_NEW, "const tabs = ['dashboard','menu','plan','daily'];")

T2F_OLD = """        if(sub === 'weekly'){ initNewTabFilters(); }
"""
cut('T2e 切り替え時の weekly 分岐を外す', T2F_OLD)

# ══════════════════════════════════════════════════════════
# T3 番号の振り直し（📊提出状況はそのまま）
# ══════════════════════════════════════════════════════════
# 4 が消えたので 1,2,3 のまま。番号の重複や飛びがないことを下で確認する。

# ══════════════════════════════════════════════════════════
# 検証 ── 合言葉とは別に「結果そのもの」を見る
# ══════════════════════════════════════════════════════════
i = src.index('id="tabPaneHomework"')
j = src.index('id="tabPaneMissions"', i)
hw = src[i:j]

# 1) 機能を消していないこと（★いちばん大事）
for must in ['id="hwClassFilter"', 'id="hwStatusFilter"', 'id="hwMonthFilter"',
             'bulkReturnNoComment()', 'id="hwList"', 'id="hwSummaryBar"',
             'id="hwUnsubmittedList"', 'id="hwDateTabs"',
             'id="hwPane_menu"', 'id="hwPane_plan"', 'id="hwPane_daily"', 'id="hwPane_dashboard"',
             'id="hwSubTab_menu"', 'id="hwSubTab_plan"', 'id="hwSubTab_daily"', 'id="hwSubTab_dashboard"',
             'saveWeeklyMenu()', 'downloadStudentCSV()', 'uploadStudentCSV(event)',
             'anonymizeCloudNames()', 'clearStudentCSV()', 'loadNameEditor()',
             'loadStudentPlans()', 'loadSubmissionDashboard()', 'loadPhotoGallery()',
             'dashWeekPrev()', 'dashWeekNext()', 'dashWeekToday()']:
    if must not in hw: fail('★機能が失われました: %s' % must)
print('🔎 家庭学習タブの機能（課題設定・名簿CSV・画面編集・計画・提出状況・写真）はすべて残っています')

for must in ['value="unreturned"', 'value="returned"', 'すべての期間',
             'onclick="returnHomework(', 'hwToggleEdit(', 'hwSaveEdit(']:
    if must not in src: fail('★表示のしかた／返却まわりが失われました: %s' % must)
print('🔎 すべて／未返却／返却済み・月しぼりこみ・返却・再返却はすべて残っています')

# 2) 重複が本当に消えたか（結果そのもの）
n_load = hw.count('onclick="loadHomework()"')
if n_load != 1:
    fail('loadHomework() を呼ぶボタンが %d 個（1個のはず）' % n_load)
print('🔎 loadHomework() を呼ぶボタンは 1 個（もとは「絞り込み」「更新」の2個）')

if 'id="hwAllUnreturnedBtn"' in hw:
    fail('「🔴 未返却をぜんぶ表示」ボタンが残っています（表示プルダウンに統合したはず）')
if '絞り込みを解除' in hw:
    fail('「絞り込みを解除」ボタンが残っています（期間プルダウンの「すべての期間」に統合したはず）')
print('🔎 意味が重なっていたボタン2つは、プルダウンに統合されました')

if 'type="month"' in hw:
    fail('期間がまだ <input type="month"> のままです')
print('🔎 期間は選ぶだけのプルダウンになりました')

# ③の操作の数
row_a = hw.index('id="hwClassFilter"'); row_a = hw.rindex('<div', 0, row_a)
row_b = hw.index('id="hwSummaryBar"', row_a)
row = hw[row_a:row_b]
n_ctrl = len(re.findall(r'<select\b', row)) + len(re.findall(r'<input\b', row)) + len(re.findall(r'<button\b', row))
if n_ctrl != 5:
    fail('③の操作が %d 個です（5個のはず）' % n_ctrl)
print('🔎 ③の操作は 5 個（クラス・表示・期間・更新・まとめて返却）。もとは 8 個')

# 3) 空タブが消え、案内は残っていること
if 'id="hwPane_weekly"' in src or 'id="hwSubTab_weekly"' in src:
    fail('空のサブタブが残っています')
if "'weekly'" in src[src.index('function switchHomeworkSubTab'):src.index('function switchHomeworkSubTab')+1500]:
    fail('切り替え関数に weekly が残っています')
if '週の振り返りへの返却は' not in hw:
    fail('週の振り返りの案内が失われました（③の下に残すはず）')
print('🔎 空のサブタブは消え、その案内は③の下に1行として残っています')

# 4) サブタブの番号に飛び・重複が無いこと
nums = re.findall(r'font-black">([0-9📊])</span>', hw)
if nums != ['1','2','3','📊']:
    fail('サブタブの番号が %s になっています（1,2,3,📊 のはず）' % nums)
print('🔎 サブタブの番号: 1, 2, 3, 📊（飛びなし・重複なし）')

# 5) いつもの安全確認
def rc(t):
    a = t.index("app.get('/', async (c) => {"); b = t.index("app.get('/logout'", a)
    return t[a:b].count('.replace(')
if rc(src) != rc(orig): fail('置換チェーンの数が変わりました（%d → %d）' % (rc(orig), rc(src)))
print('🔎 置換チェーン: %d 件（変化なし）' % rc(src))

bal  = len(re.findall(r'<div\b', src))  - len(re.findall(r'</div>', src))
bal0 = len(re.findall(r'<div\b', orig)) - len(re.findall(r'</div>', orig))
if bal != bal0: fail('<div> の釣り合いが変わりました（%d → %d）' % (bal0, bal))
print('🔎 <div> の釣り合い: 変化なし')

g0 = src.index('let _adminChecked = false'); g1 = src.index('// -------------------- DB migration', g0)
for l in src[g0:g1].split('\n'):
    if 'CREATE INDEX' in l and not l.strip().startswith('//'):
        fail('起動時ミドルウェアに CREATE INDEX が復活しています')
print('🔎 起動時ミドルウェアに DDL はありません')

# 6) 他セッションの担当領域に触れていないこと
import hashlib
def area(t, s0, s1):
    a = t.index(s0); b = t.index(s1, a); return hashlib.md5(t[a:b].encode('utf-8')).hexdigest()
if area(src, 'async function ensureDefenseTables', "app.post('/api/defense/reward-claim'") != \
   area(orig, 'async function ensureDefenseTables', "app.post('/api/defense/reward-claim'"):
    fail('防衛戦のコードが変わっています')
if area(src, 'function _buildKarteHtml', 'function downloadKartePdf') != \
   area(orig, 'function _buildKarteHtml', 'function downloadKartePdf'):
    fail('カルテ（_buildKarteHtml）のコードが変わっています')
print('🔎 防衛戦・カルテのコードには触れていません（md5 一致）')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
print('---- 入れたもの ----')
for t in done: print(' ・' + t)
if not done: print(' （なし）')
