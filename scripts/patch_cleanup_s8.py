# -*- coding: utf-8 -*-
"""
patch_cleanup_s8.py — 教師ダッシュボードの片づけ 第2便(3/3)
2026-09-29  CLEANUP_S5   ※D（タブの並べ替え）だけを入れる別便

D 上のタブ7つを「機能ごと」から「先生の仕事の順番」へ並べ替える。
  前： クラス管理 / 連絡帳 / (おしらせ) / 家庭学習 / 分析 / 質問チャット / ミッション
  後： ① 家庭学習 → ② 質問チャット → ③ 連絡帳 → ④ 分析・カルテ
       → ⑤ ミッション → ⑥ クラス・名簿   （おしらせは今までどおり管理者だけ）

  ・毎日ひらくもの（①②③）を左に、年に1回のもの（⑥）を右にした。
  ・画面をひらいた直後に出るタブも「① 家庭学習」にした（前は「クラス管理」で、
    毎日いちばん使うものが最初に出ていなかった）。
  ・タブの中身・押したときに出るものは1つも変えていない。並び順と名前だけ。
  ・分析タブの中の小さいタブにも「月曜に印刷」「ときどき」の目印を足した。
    ③月曜（カルテ印刷）＝分析の「4」、⑤学期末（通知表）＝分析の「4」の中の
    「通知表（先生用）」にあるため、そこに出る場所を文字で示した。

★配信チェーン（158件）は増減させない。
"""
import io
import sys

TSX = 'src/index.tsx'
ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
CHAIN_WANT = 158

BTN_OFF = u'class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100"'
BTN_ON = u'class="flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white"'


def die(msg):
    sys.stderr.write('NG: ' + msg + '\n')
    sys.exit(1)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def rep(s, old, new, label):
    n = s.count(old)
    if n != 1:
        die(u'あて先 %s が %d 件（1件のはず）' % (label, n))
    return s.replace(old, new)


NAV_OLD = (u'      <!-- タブナビ -->\n'
           u'      <div class="bg-white rounded-xl shadow p-1 flex gap-1">\n'
           u'        <button id="tabClasses" ' + BTN_ON + u" onclick=\"switchTab('classes')\">\U0001f4da クラス管理</button>\n"
           u'        <button id="tabContact" ' + BTN_OFF + u" onclick=\"switchTab('contact')\">\U0001f4d3 連絡帳</button>\n"
           u'        <button id="tabAnnouncements" style="display:none" ' + BTN_OFF + u" onclick=\"switchTab('announcements')\">\U0001f4e2 おしらせ</button>\n"
           u'        <button id="tabHomework" ' + BTN_OFF + u" onclick=\"switchTab('homework')\">\U0001f4ec 家庭学習</button>\n"
           u'        <button id="tabAnalytics" ' + BTN_OFF + u" onclick=\"switchTab('analytics')\">\U0001f4ca 分析</button>\n"
           u'        <button id="tabMail" ' + BTN_OFF + u" onclick=\"switchTab('mail')\">\U0001f4ac 質問チャット</button>\n"
           u'        <button id="tabMissions" ' + BTN_OFF + u" onclick=\"switchTab('missions')\">\U0001f3af ミッション</button>\n"
           u'      </div>\n')

NAV_NEW = (u'      <!-- タブナビ -->\n'
           u'      <!-- 2026-09-29 整理(D): 機能ごとの並びを、先生の仕事の順番に並べ替えた。\n'
           u'           左から「毎日」→「今週・月曜」→「ときどき」→「年度はじめ」。\n'
           u'           タブの中身は1つも動かしていない（並び順と名前だけ）。 -->\n'
           u'      <div class="space-y-1">\n'
           u'        <div class="flex items-center text-[10px] font-bold text-slate-400 px-2">\n'
           u'          <span>← 毎日つかうもの</span>\n'
           u'          <span class="ml-auto">ときどき・年度はじめ →</span>\n'
           u'        </div>\n'
           u'        <div class="bg-white rounded-xl shadow p-1 flex gap-1">\n'
           u'          <button id="tabHomework" ' + BTN_ON + u" onclick=\"switchTab('homework')\">① \U0001f4ec 家庭学習</button>\n"
           u'          <button id="tabMail" ' + BTN_OFF + u" onclick=\"switchTab('mail')\">② \U0001f4ac 質問チャット</button>\n"
           u'          <button id="tabContact" ' + BTN_OFF + u" onclick=\"switchTab('contact')\">③ \U0001f4d3 連絡帳</button>\n"
           u'          <button id="tabAnalytics" ' + BTN_OFF + u" onclick=\"switchTab('analytics')\">④ \U0001f4ca 分析・カルテ</button>\n"
           u'          <button id="tabMissions" ' + BTN_OFF + u" onclick=\"switchTab('missions')\">⑤ \U0001f3af ミッション</button>\n"
           u'          <button id="tabClasses" ' + BTN_OFF + u" onclick=\"switchTab('classes')\">⑥ \U0001f4da クラス・名簿</button>\n"
           u'          <button id="tabAnnouncements" style="display:none" ' + BTN_OFF + u" onclick=\"switchTab('announcements')\">\U0001f4e2 おしらせ</button>\n"
           u'        </div>\n'
           u'      </div>\n')

# 最初に出るタブを「① 家庭学習」にする
BOOT_OLD = u'        await renderClasses();\n      })();\n'
BOOT_NEW = (u'        await renderClasses();\n'
            u'        /* 2026-09-29 整理(D): ひらいた直後に出るタブを「① 家庭学習」にする。\n'
            u'           クラス一覧の読み込みは上で済ませてあるので、あとから見ても中身は入っている。 */\n'
            u"        try{ switchTab('homework'); }catch(_e){}\n"
            u'      })();\n')

# 分析タブの小さいタブに目印を足す
SUB4_OLD = u'</span> AIの結果\n'
SUB4_NEW = u'</span> カルテ・AI<span class="ml-1 text-[9px] font-normal opacity-70">月曜に印刷</span>\n'
SUB5_OLD = u'</span> テスト取り込み\n'
SUB5_NEW = u'</span> 取り込み<span class="ml-1 text-[9px] font-normal opacity-70">ときどき</span>\n'

RC_OLD = u'              <div class="font-bold text-sm text-indigo-800">\U0001f4cb 通知表（先生用・観点別）</div>\n'
RC_NEW = u'              <div class="font-bold text-sm text-indigo-800">\U0001f4cb 通知表（先生用・観点別）<span class="ml-1 text-[10px] font-normal text-indigo-500">学期末に使います</span></div>\n'


def main():
    s = io.open(TSX, encoding='utf-8').read()
    n0 = chain_count(s)
    if n0 != CHAIN_WANT:
        die(u'チェーンが %d 件（%d 件のはず）。止めます。' % (n0, CHAIN_WANT))

    s = rep(s, NAV_OLD, NAV_NEW, 'D タブの並べ替え')
    s = rep(s, BOOT_OLD, BOOT_NEW, 'D 最初に出るタブ')
    s = rep(s, SUB4_OLD, SUB4_NEW, 'D 分析4の目印')
    s = rep(s, SUB5_OLD, SUB5_NEW, 'D 分析5の目印')
    s = rep(s, RC_OLD, RC_NEW, 'D 通知表の目印')

    n1 = chain_count(s)
    if n1 != n0:
        die(u'チェーンが %d 件になった（%d 件のままでないとだめ）' % (n1, n0))
    io.open(TSX, 'w', encoding='utf-8').write(s)
    print('PATCH OK / chain %d -> %d' % (n0, n1))


main()
# -*- coding: utf-8 -*-
"""
patch_cleanup_s5.py — 教師ダッシュボードの片づけ 第2便(3/3)
2026-09-29  CLEANUP_S5   ※D（タブの並べ替え）だけを入れる別便

D 上のタブ7つを「機能ごと」から「先生の仕事の順番」へ並べ替える。
  前： クラス管理 / 連絡帳 / (おしらせ) / 家庭学習 / 分析 / 質問チャット / ミッション
  後： ① 家庭学習 → ② 質問チャット → ③ 連絡帳 → ④ 分析・カルテ
       → ⑤ ミッション → ⑥ クラス・名簿   （おしらせは今までどおり管理者だけ）

  ・毎日ひらくもの（①②③）を左に、年に1回のもの（⑥）を右にした。
  ・画面をひらいた直後に出るタブも「① 家庭学習」にした（前は「クラス管理」で、
    毎日いちばん使うものが最初に出ていなかった）。
  ・タブの中身・押したときに出るものは1つも変えていない。並び順と名前だけ。
  ・分析タブの中の小さいタブにも「月曜に印刷」「ときどき」の目印を足した。
    ③月曜（カルテ印刷）＝分析の「4」、⑤学期末（通知表）＝分析の「4」の中の
    「通知表（先生用）」にあるため、そこに出る場所を文字で示した。

★配信チェーン（158件）は増減させない。
"""
import io
import sys

TSX = 'src/index.tsx'
ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
CHAIN_WANT = 158

BTN_OFF = u'class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100"'
BTN_ON = u'class="flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white"'


def die(msg):
    sys.stderr.write('NG: ' + msg + '\n')
    sys.exit(1)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def rep(s, old, new, label):
    n = s.count(old)
    if n != 1:
        die(u'あて先 %s が %d 件（1件のはず）' % (label, n))
    return s.replace(old, new)


NAV_OLD = (u'      <!-- タブナビ -->\n'
           u'      <div class="bg-white rounded-xl shadow p-1 flex gap-1">\n'
           u'        <button id="tabClasses" ' + BTN_ON + u" onclick=\"switchTab('classes')\">\U0001f4da クラス管理</button>\n"
           u'        <button id="tabContact" ' + BTN_OFF + u" onclick=\"switchTab('contact')\">\U0001f4d3 連絡帳</button>\n"
           u'        <button id="tabAnnouncements" style="display:none" ' + BTN_OFF + u" onclick=\"switchTab('announcements')\">\U0001f4e2 おしらせ</button>\n"
           u'        <button id="tabHomework" ' + BTN_OFF + u" onclick=\"switchTab('homework')\">\U0001f4ec 家庭学習</button>\n"
           u'        <button id="tabAnalytics" ' + BTN_OFF + u" onclick=\"switchTab('analytics')\">\U0001f4ca 分析</button>\n"
           u'        <button id="tabMail" ' + BTN_OFF + u" onclick=\"switchTab('mail')\">\U0001f4ac 質問チャット</button>\n"
           u'        <button id="tabMissions" ' + BTN_OFF + u" onclick=\"switchTab('missions')\">\U0001f3af ミッション</button>\n"
           u'      </div>\n')

NAV_NEW = (u'      <!-- タブナビ -->\n'
           u'      <!-- 2026-09-29 整理(D): 機能ごとの並びを、先生の仕事の順番に並べ替えた。\n'
           u'           左から「毎日」→「今週・月曜」→「ときどき」→「年度はじめ」。\n'
           u'           タブの中身は1つも動かしていない（並び順と名前だけ）。 -->\n'
           u'      <div class="space-y-1">\n'
           u'        <div class="flex items-center text-[10px] font-bold text-slate-400 px-2">\n'
           u'          <span>← 毎日つかうもの</span>\n'
           u'          <span class="ml-auto">ときどき・年度はじめ →</span>\n'
           u'        </div>\n'
           u'        <div class="bg-white rounded-xl shadow p-1 flex gap-1">\n'
           u'          <button id="tabHomework" ' + BTN_ON + u" onclick=\"switchTab('homework')\">① \U0001f4ec 家庭学習</button>\n"
           u'          <button id="tabMail" ' + BTN_OFF + u" onclick=\"switchTab('mail')\">② \U0001f4ac 質問チャット</button>\n"
           u'          <button id="tabContact" ' + BTN_OFF + u" onclick=\"switchTab('contact')\">③ \U0001f4d3 連絡帳</button>\n"
           u'          <button id="tabAnalytics" ' + BTN_OFF + u" onclick=\"switchTab('analytics')\">④ \U0001f4ca 分析・カルテ</button>\n"
           u'          <button id="tabMissions" ' + BTN_OFF + u" onclick=\"switchTab('missions')\">⑤ \U0001f3af ミッション</button>\n"
           u'          <button id="tabClasses" ' + BTN_OFF + u" onclick=\"switchTab('classes')\">⑥ \U0001f4da クラス・名簿</button>\n"
           u'          <button id="tabAnnouncements" style="display:none" ' + BTN_OFF + u" onclick=\"switchTab('announcements')\">\U0001f4e2 おしらせ</button>\n"
           u'        </div>\n'
           u'      </div>\n')

# 最初に出るタブを「① 家庭学習」にする
BOOT_OLD = u'        await renderClasses();\n      })();\n'
BOOT_NEW = (u'        await renderClasses();\n'
            u'        /* 2026-09-29 整理(D): ひらいた直後に出るタブを「① 家庭学習」にする。\n'
            u'           クラス一覧の読み込みは上で済ませてあるので、あとから見ても中身は入っている。 */\n'
            u"        try{ switchTab('homework'); }catch(_e){}\n"
            u'      })();\n')

# 分析タブの小さいタブに目印を足す
SUB4_OLD = u'</span> AIの結果\n'
SUB4_NEW = u'</span> カルテ・AI<span class="ml-1 text-[9px] font-normal opacity-70">月曜に印刷</span>\n'
SUB5_OLD = u'</span> テスト取り込み\n'
SUB5_NEW = u'</span> 取り込み<span class="ml-1 text-[9px] font-normal opacity-70">ときどき</span>\n'

RC_OLD = u'              <div class="font-bold text-sm text-indigo-800">\U0001f4cb 通知表（先生用・観点別）</div>\n'
RC_NEW = u'              <div class="font-bold text-sm text-indigo-800">\U0001f4cb 通知表（先生用・観点別）<span class="ml-1 text-[10px] font-normal text-indigo-500">学期末に使います</span></div>\n'


def main():
    s = io.open(TSX, encoding='utf-8').read()
    n0 = chain_count(s)
    if n0 != CHAIN_WANT:
        die(u'チェーンが %d 件（%d 件のはず）。止めます。' % (n0, CHAIN_WANT))

    s = rep(s, NAV_OLD, NAV_NEW, 'D タブの並べ替え')
    s = rep(s, BOOT_OLD, BOOT_NEW, 'D 最初に出るタブ')
    s = rep(s, SUB4_OLD, SUB4_NEW, 'D 分析4の目印')
    s = rep(s, SUB5_OLD, SUB5_NEW, 'D 分析5の目印')
    s = rep(s, RC_OLD, RC_NEW, 'D 通知表の目印')

    n1 = chain_count(s)
    if n1 != n0:
        die(u'チェーンが %d 件になった（%d 件のままでないとだめ）' % (n1, n0))
    io.open(TSX, 'w', encoding='utf-8').write(s)
    print('PATCH OK / chain %d -> %d' % (n0, n1))


main()
