# -*- coding: utf-8 -*-
"""
patch_hw_ctx_height_v1.py — 返却カードの3行たたみが高すぎて畳みすぎていたのを直す
2026-09-24  HW_CTX_HEIGHT_V1

2026-09-23 の HW_RETURN_V1 で入れた `#hwList .hw-ctx { max-height: 4.6rem }` が
きつすぎた。先生の実画面で測ったところ：
  ・カードの中身は 138〜234px（中央値170px）あるのに、見えているのは 74px だけ
  ・100枚すべてが畳まれ、
  ・🏠 サポーターからのことばが「65枚すべてで見えない」状態だった
サポーターのことばは、まさに先生が「返すときに一緒に見たい」と言われたもの。
それを隠していたので、上限を 15rem（240px）に上げる。実測の最大が234pxなので
ふつうのカードは畳まれず全部見える。異常に長い子のときだけ「…もっと見る」が出る。
"""
import io
import sys

TSX = 'src/index.tsx'
OLD = '#hwList .hw-ctx { max-height: 4.6rem; overflow: hidden; }'
NEW = '#hwList .hw-ctx { max-height: 15rem; overflow: hidden; }'


def apply(s):
    n = s.count(OLD)
    assert n == 1, 'anchor: %d' % n
    return s.replace(OLD, NEW)


def main():
    src = io.open(TSX, encoding='utf-8').read()
    out = apply(src)
    if out == src:
        print('NO CHANGE'); sys.exit(1)
    io.open(TSX, 'w', encoding='utf-8').write(out)
    print('patched (%d -> %d)' % (len(src), len(out)))


if __name__ == '__main__':
    main()
