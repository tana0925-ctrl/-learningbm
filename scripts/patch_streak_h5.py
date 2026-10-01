import sys

PATH = 'src/index.tsx'
CHAIN_BEFORE = 158

# 連続日数の直し 第5便：カフート券の数え方を、カルテ・教師一覧とそろえる
#
# いまのカフート券は「今日まだ出していなければ 0」なので、
# 朝8時半をすぎると全員の連続が 0 になり、いちばん続けている子ほど
# 朝いちばんに高い値段を見せられていた（例: 500円 -> 1500円）。
#
# 新しい数え方（hwStreakCurrent）は
#   ・今日はまだ出していなくても切らない
#   ・休みの日に出していたら、その分も数える
# どちらも連続を増やす向きにしか働かない。だから値段は下がるか据え置きだけ。
#
# もどすときは scripts/patch_streak_h5_revert.py

OLD = ("// public/index.html の hsCalcRequiredStreak と同じ数え方。\n"
       "function khtStreak(days: any, todayKey: string, extra: any): number {\n"
       "  let k = todayKey\n"
       "  let s = 0\n"
       "  for (let i = 0; i < 400; i++) {\n"
       "    if (khtIsRest(k, extra)) { k = khtAddDay(k, -1); continue }\n"
       "    if (days[k]) { s++; k = khtAddDay(k, -1); continue }\n"
       "    break\n"
       "  }\n"
       "  return s\n"
       "}\n")

NEW = ("// 2026-10-01: 数え方は hwStreakCurrent ただ1本（カルテ・教師一覧と共通）。\n"
       "//   ・今日はまだ出していなくても切らない\n"
       "//   ・休みの日に出していたら、その分も数える\n"
       "//   どちらも連続を増やす向きにしか働かないので、券の値段が上がることはない。\n"
       "function khtStreak(days: any, todayKey: string, extra: any): number {\n"
       "  return hwStreakCurrent(Object.keys(days || {}), todayKey, extra)\n"
       "}\n")

NEEDED = ['function hwStreakCurrent(', 'function hwStreakMax(', 'function khtTodayKey(',
          'function khtIsRest(', 'function khtRecent(', 'function khtPriceOf(']
UNTOUCHED = ['KHT_PRICE_STREAK = 500', 'KHT_PRICE_MID = 1500', 'KHT_PRICE_NONE = 3000',
             'KHT_STREAK_NEED = 3', 'KHT_RECENT_DAYS = 5', 'KHT_LEGACY_PRICE = 800',
             'function khtRecent(', 'function khtPriceOf(', 'function khtIsRest(',
             'khtStreak(days, todayKey, extra)']


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
            die('前提が足りない: ' + k)

    if NEW in src:
        die('この便はもう当たっている')
    if src.count(OLD) != 1:
        die('あて先が %d 件（1件のはず）' % src.count(OLD))

    out = src.replace(OLD, NEW, 1)

    after = chain_count(out)
    print('チェーン数（後）:', after)
    if after != before:
        die('チェーン数が %d -> %d に変わった' % (before, after))

    if out.count('function khtStreak(') != 1:
        die('khtStreak の定義が1個でない')
    if out.count('return hwStreakCurrent(Object.keys(days || {}), todayKey, extra)') != 1:
        die('差しかえが入っていない')
    if out.count('khtStreak(days, todayKey, extra)') != 3:
        die('khtStreak の呼び出しが %d 件（3件のはず）' % out.count('khtStreak(days, todayKey, extra)'))

    for k in UNTOUCHED:
        if src.count(k) != out.count(k):
            die('さわってはいけないところが変わった: ' + k)

    if out.count('currentStreak = hwStreakCurrent(') != 2 or out.count('f.streak = hwStreakMax(days, {})') != 1:
        die('第4便のぶんが壊れた')

    grew = len(out) - len(src)
    want = len(NEW) - len(OLD)
    if grew != want:
        die('増えた文字数が %d（%d のはず）' % (grew, want))

    with open(PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(out)

    print('OK: カフート券の数え方を hwStreakCurrent にそろえた')
    print('OK: 値段は下がるか据え置きのみ（連続が増える向きの変更だけなので）')


if __name__ == '__main__':
    main()
