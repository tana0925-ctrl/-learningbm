# -*- coding: utf-8 -*-
# DEFLANE_MIX_V1 : 防衛戦だけ、てきのレーンを seed から きめる。
#   いまは てきの ならびが _cj % 3 で かたまっていて、
#   みぎの道には よわい 2体しか 来ない。だから「みぎに よせる」だけで 勝ててしまう。
#   ここを 強い順に 1体ずつ 3つの道へ くばる形（seed で じゅんばんを まぜる）に かえる。
#   - seed が 同じなら 同じ ならび（決定論は こわさない）
#   - サーバ（src/def_engine.ts）と ブラウザ（つなぎで 書きかえる）で 同じ形
#   - ジムチャレンジは foeLaneMix を わたさないので これまでどおり
#
# 1回流しても 2回流しても 同じ形になる（番兵 __DEFLANE_MIX_V1__）。
# 一致しないときは 何も書かずに 失敗で終わる（fail-closed）。

import io
import sys

NL = chr(10)
Q = chr(34)

ENG_PATH = 'src/def_engine.ts'
INDEX_PATH = 'src/index.tsx'
RES_PATH = 'src/def_resolve.ts'
D2_PATH = 'public/defense2.js'
PUB_PATH = 'public/index.html'

SENTINEL = '__DEFLANE_MIX_V1__'

OLD_B = 'for(var _cj=0;_cj<B.length;_cj++){ B[_cj].adv=0; B[_cj].curLn=(B[_cj].lane!=null?B[_cj].lane:(_cj%CLN)); } }'
NEW_B = '/* __DEFLANE_MIX_V1__ 防衛戦だけ: てきのレーンを seed から きめる。強い順に 1体ずつ くばるので 1つの道に かたよらない。 */ var _cLB=null; if(opts.foeLaneMix){ var _cO=[],_cx,_cy,_ct; for(_cx=0;_cx<B.length;_cx++) _cO.push(_cx); _cO.sort(function(x,y){ var sx=(Number(B[x].maxHp)||0)+3*(Number(B[x].atk)||0), sy=(Number(B[y].maxHp)||0)+3*(Number(B[y].atk)||0); return (sy-sx)||(x-y); }); _cLB=new Array(B.length); var _cL2=[]; for(_cx=0;_cx<CLN;_cx++) _cL2.push(_cx); for(var _cr=0;_cr*CLN<B.length;_cr++){ for(_cx=CLN-1;_cx>0;_cx--){ _cy=Math.floor(rng()*(_cx+1)); _ct=_cL2[_cx]; _cL2[_cx]=_cL2[_cy]; _cL2[_cy]=_ct; } for(_cx=0;_cx<CLN&&_cr*CLN+_cx<B.length;_cx++) _cLB[_cO[_cr*CLN+_cx]]=_cL2[_cx]; } } for(var _cj=0;_cj<B.length;_cj++){ B[_cj].adv=0; B[_cj].curLn=(B[_cj].lane!=null?B[_cj].lane:(_cLB?_cLB[_cj]:(_cj%CLN))); } }'

CHAIN_ANCHOR = NL + '    _rootHtmlCache = t' + NL
CHAIN_ADD = (NL + '      // ' + SENTINEL + ' 防衛戦だけ てきのレーンを seed から きめる（ジムチャレンジは foeLaneMix を わたさないので これまでどおり）'
             + NL + '      t = t.replace(' + Q + OLD_B + Q + ', ' + Q + NEW_B + Q + ')')

OLD_V = '/defense2.js?v=19'
NEW_V = '/defense2.js?v=20'

OLD_RES = '      forts: false, tactics: true, contact: true'
NEW_RES = '      forts: false, tactics: true, contact: true, foeLaneMix: true'

OLD_D2A = 'forts:false,tactics:true,contact:true}); });'
NEW_D2A = 'forts:false,tactics:true,contact:true,foeLaneMix:true}); });'

OLD_D2B = 'programsA:pa,programsB:[pb],forts:false,tactics:true,contact:true});'
NEW_D2B = 'programsA:pa,programsB:[pb],forts:false,tactics:true,contact:true,foeLaneMix:true});'


def read(path):
    return io.open(path, encoding='utf-8').read()


def write(path, text):
    io.open(path, 'w', encoding='utf-8', newline='').write(text)


def need_one(text, anchor, label):
    n = text.count(anchor)
    if n != 1:
        print('NG: %s のアンカーが %d 件（1 件でないので中止）' % (label, n))
        sys.exit(1)


def chain_count(text):
    i = text.index("app.get('/', async (c) => {")
    j = text.index("app.get('/logout'", i)
    return text[i:j].count('.replace(')


def main():
    e = read(ENG_PATH)
    s = read(INDEX_PATH)
    v = read(RES_PATH)
    d = read(D2_PATH)
    pub = read(PUB_PATH)

    hits = [SENTINEL in e, SENTINEL in s]
    if all(hits):
        print('すでに入っています（番兵 %s）。何もしません。' % SENTINEL)
        return
    if any(hits):
        print('NG: 片方だけ入っている状態です。手で見てください。')
        sys.exit(1)

    need_one(e, OLD_B, 'エンジンの レーンわり')
    need_one(pub, OLD_B, '本番HTMLの レーンわり')
    need_one(s, CHAIN_ANCHOR, 'つなぎの おわり')
    need_one(s, OLD_V, 'defense2.js のばんごう')
    need_one(v, OLD_RES, 'サーバの opts')
    need_one(d, OLD_D2A, 'ブラウザ本番の opts')
    need_one(d, OLD_D2B, 'ためしバトルの opts')
    if e.count('foeLaneMix') != 0 or v.count('foeLaneMix') != 0 or d.count('foeLaneMix') != 0:
        print('NG: foeLaneMix がすでにある')
        sys.exit(1)

    chain_before = chain_count(s)

    e2 = e.replace(OLD_B, NEW_B)
    s2 = s.replace(CHAIN_ANCHOR, CHAIN_ADD + CHAIN_ANCHOR).replace(OLD_V, NEW_V)
    v2 = v.replace(OLD_RES, NEW_RES)
    d2 = d.replace(OLD_D2A, NEW_D2A).replace(OLD_D2B, NEW_D2B)

    if e2.count(NEW_B) != 1 or e2.count(OLD_B) != 0:
        print('NG: エンジンの入れかえが おかしい')
        sys.exit(1)
    if s2.count(SENTINEL) != 2:
        print('NG: 番兵が 2 件でない（つなぎの見出しと 中身）')
        sys.exit(1)
    if s2.count(NEW_V) != 1 or s2.count(OLD_V) != 0:
        print('NG: ばんごうの更新が おかしい')
        sys.exit(1)
    if v2.count('foeLaneMix') != 1:
        print('NG: サーバの opts が 1 件でない')
        sys.exit(1)
    if d2.count('foeLaneMix') != 2:
        print('NG: ブラウザの opts が 2 件でない')
        sys.exit(1)

    chain_after = chain_count(s2)
    if chain_after != chain_before + 1:
        print('NG: つなぎの数が %d から %d（ふえるのは 1 件だけの予定）' % (chain_before, chain_after))
        sys.exit(1)

    if pub.replace(OLD_B, NEW_B).count(NEW_B) != 1:
        print('NG: 本番HTMLへの あてはめが 1 件でない')
        sys.exit(1)

    write(ENG_PATH, e2)
    write(INDEX_PATH, s2)
    write(RES_PATH, v2)
    write(D2_PATH, d2)
    print('OK: 入れました。つなぎの数は %d から %d。' % (chain_before, chain_after))


main()
