// __DEFMOP_V1__ 防衛戦：全滅で即終了せず、生き残りが基地まで歩く。
//
// いまの症状（実測で確認ずみ）
//  - 両軍は adv 0.56 / 0.38 で おたがいをロックし合う（_cMove の上限が「相手の位置 - CR*0.8」のため）
//  - 基地を殴るには adv >= 1-CR = 0.925 が必要なので、相手が1体でも生きている間は 永久に届かない
//  - 最後の1体が倒れた瞬間に wipe で終了 → 子どもには「基地に着く前に終わった」と見える
//  - D1の実測：直近6回のうち4回が「敵の基地 380/380＝無傷」のまま全滅勝ち
//
// この段でやること
//  - 片方が全滅しても すぐ終わらせず、生き残りが basetまで歩いて実際に殴れるようにする
//  - 基地HPが0になれば reason='base'、歩ききれなければ mopTicks で打ち切って reason='wipe'
//
// ⚠️ 既定では 何も変わらない
//  - opts.mopTicks が 0（既定）なら、従来とまったく同じ動きになる
//  - 有効にするのは src/def_resolve.ts の defAutoBattleRT(...) に mopTicks を渡したときだけ
//  - 友達対戦・ジムチャレンジは この opts を渡さないので 最後まで影響しない
//
// やくそく
//  - public/index.html は手で編集しない。ここの文字列を src/index.tsx のチェーンが当てる
//  - アンカーが見つからないときは throw せず console.error して飛ばす

export type DefMopPatch = { tag: string, a: string, b: string }

// ---- 1) 掃討フェーズの宣言 ------------------------------------------------
const A_DECL = "var winner=null, reason='wipe';"

const B_DECL = `/* __DEFMOP_V1__ 片方が全滅したあとの「掃討」。opts.mopTicks が 0 なら 何も起きない。 */
          var MOP = Math.max(0, Math.floor(Number(opts.mopTicks) || 0));
          var _mopEnd = -1;
          function _mopOn(){
            if(MOP <= 0) return false;
            var aL = alive(A).length, bL = alive(B).length;
            if(aL === bL) return false;                  /* 両方全滅 → そこで終わり */
            var foeBase = aL ? baseHpB : baseHpA;        /* 生き残った側が殴る基地 */
            if(!(foeBase > 0)) return false;             /* もう落ちている → 終わり */
            if(_mopEnd < 0) _mopEnd = t + MOP;           /* 全滅した瞬間から数える */
            return t <= _mopEnd;
          }
          ` + A_DECL

// ---- 2) 交戦中の全滅で 即 break しない -------------------------------------
const A_HIT = "if(CONTACT){ _cAttack(f); if(!alive(A).length||!alive(B).length){ ended=true; break; }"

const B_HIT = "if(CONTACT){ _cAttack(f); if(!alive(A).length||!alive(B).length){ /* __DEFMOP_V1__ */ if(!_mopOn()){ ended=true; break; } }"

// ---- 3) ループの末尾でも 即 break しない -----------------------------------
const A_TAIL = "if(ended||!alive(A).length||!alive(B).length) break;"

const B_TAIL = "/* __DEFMOP_V1__ 全滅しても 掃討が続くあいだは 回し続ける */ if(ended) break; if((!alive(A).length||!alive(B).length) && !_mopOn()) break;"

export const DEFMOP_V1_PATCHES: DefMopPatch[] = [
  { tag: 'M01_decl', a: A_DECL, b: B_DECL },
  { tag: 'M02_hit', a: A_HIT, b: B_HIT },
  { tag: 'M03_tail', a: A_TAIL, b: B_TAIL }
]
