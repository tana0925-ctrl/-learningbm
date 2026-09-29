import sys

PATH = 'src/index.tsx'
CHAIN_BEFORE = 158

# 連続日数の直し 第3便：祝日表が切れたときに先生が気づけるようにする
#
# 子どもの画面には何も出さない。教師画面だけ。
# 今日（2026年9月）はまだ切れていないので、画面には何も出ない。
# HTMLに増えるのは説明用のHTMLコメント（33文字、57バイト）だけ。
# 数字は1つも変わらない。

FN_ANCHOR = "function hwDayMap(dayKeys: any): any {"

FN = """// 祝日表が切れたことを先生に知らせる。子どもの画面には出さない。
// 表が切れたまま気づかないと、祝日が「学校のある日」として数えられ、
// 家庭学習の連続日数がだまって切れてしまう。それを防ぐための見張り。
// 2028-03-20 の春分の日だけは見込みで入れてある（国立天文台の正式発表は2027年2月）。
// そのため 2027-02-01 からは、確かめてほしいという知らせを出す。
function hwHolidayNotice(): string {
  const today = khtTodayKey(Date.now())
  let s = '<!-- 祝日表は ' + KHT_HOLIDAYS_UNTIL + ' まで入っています -->'
  if (today > KHT_HOLIDAYS_UNTIL) {
    s += '<div class="bg-amber-100 border border-amber-400 text-amber-900 rounded-xl p-3 text-sm">'
      + '<b>祝日表が ' + KHT_HOLIDAYS_UNTIL + ' で切れています。</b>'
      + 'このままでは祝日が「学校のある日」として数えられ、家庭学習の連続日数がだまって切れてしまいます。'
      + '国立天文台の暦要項を見て、次の年度ぶんの祝日を足してください。'
      + '</div>'
  } else if (today >= '2027-02-01') {
    s += '<div class="bg-sky-100 border border-sky-400 text-sky-900 rounded-xl p-3 text-sm">'
      + '2028年3月20日の春分の日は見込みで入れてあります。'
      + '国立天文台の暦要項（2027年2月発表）でお確かめください。ちがっていたら直してください。'
      + '</div>'
  }
  return s
}

"""

TPL_OLD = '    <div class="max-w-4xl mx-auto space-y-4">'
TPL_NEW = '    <div class="max-w-4xl mx-auto space-y-4">' + '$' + '{hwHolidayNotice()}'

NEEDED = ['function khtTodayKey(', 'KHT_HOLIDAYS_UNTIL', 'function hwStreakCurrent(',
          "app.get('/teacher', (c) => {"]
UNTOUCHED = ['KHT_PRICE_STREAK = 500', 'KHT_PRICE_MID = 1500', 'KHT_PRICE_NONE = 3000',
             'KHT_STREAK_NEED = 3', 'function khtStreak(', 'function khtIsRest(',
             'function khtRecent(', 'function khtPriceOf(',
             'function hwStreakCurrent(', 'function hwStreakMax(', 'function hwDayMap(']


def die(msg):
    print('### 中止: ' + msg)
    sys.exit(1)


def chain_count(src):
    a = src.index("app.get('/'")
    b = src.index("app.get('/logout'")
    if b <= a:
        die('チェーンの範囲が取れない')
    return src.count('.replace(', a, b)


def main():
    with open(PATH, encoding='utf-8') as f:
        src = f.read()

    before = chain_count(src)
    print('チェーン数（前）:', before)
    if before != CHAIN_BEFORE:
        die('チェーン数が %d（%d のはず）' % (before, CHAIN_BEFORE))

    for k in NEEDED:
        if k not in src:
            die('前提が足りない（前の便が当たっていない？）: ' + k)

    if 'hwHolidayNotice' in src:
        die('hwHolidayNotice がすでにある（この便はもう当たっている）')

    if src.count(FN_ANCHOR) != 1:
        die('関数のあて先が %d 件（1件のはず）' % src.count(FN_ANCHOR))
    if src.count(TPL_OLD) != 1:
        die('教師画面のあて先が %d 件（1件のはず）' % src.count(TPL_OLD))

    out = src.replace(FN_ANCHOR, FN + FN_ANCHOR, 1)
    out = out.replace(TPL_OLD, TPL_NEW, 1)

    after = chain_count(out)
    print('チェーン数（後）:', after)
    if after != before:
        die('チェーン数が %d -> %d に変わった' % (before, after))

    if out.count('function hwHolidayNotice(): string {') != 1:
        die('関数の定義が1個でない')
    if out.count(TPL_NEW) != 1:
        die('呼び出しが1個でない')
    if out.count('hwHolidayNotice') != 2:
        die('hwHolidayNotice が %d 個（2個のはず）' % out.count('hwHolidayNotice'))

    for k in UNTOUCHED:
        if src.count(k) != out.count(k):
            die('さわってはいけないところが変わった: ' + k)

    grew = len(out) - len(src)
    want = len(FN) + (len(TPL_NEW) - len(TPL_OLD))
    if grew != want:
        die('増えた文字数が %d（%d のはず）' % (grew, want))

    with open(PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(out)

    print('OK: hwHolidayNotice を追加し、教師画面の先頭から呼ぶようにした')
    print('OK: 今日は表示なし。HTMLに増えるのは説明用コメントの57バイトだけ')
    print('OK: 2027-02-01 から春分の日の確認おねがい、2028-04-01 から期限切れの警告')


if __name__ == '__main__':
    main()
