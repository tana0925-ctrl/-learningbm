/* tbsub.js  TB_SUB_V1  2026-10-06
 *
 * ターン制バトル（オマケ）専用のサブ属性表。
 * ここに書いた技は「ターン制バトルのときだけ」属性が変わります。
 * 既存の野生／ジム／友達／防衛／ゾンビ／タマゴ／タイプシュートには一切影響しません
 * （このファイルを読むのは tbattle.js だけです）。
 *
 * 決め方：キャラの見た目・名前と、技の名前から説明がつくものだけ。
 *   例）コアラ → ユーカリ → くさ、クラゲン → くらげ → みず、カゲハヤテ → かげ → ゴースト
 * 理屈がつかないものは入れていません（子どもが覚えられないため）。
 *
 * ダメージのある技（威力が1以上）だけに付けています。
 * 威力0の強化技に属性を付けても、相性は計算に出てこないためです。
 *
 * 技は名前で探します（番号ではありません）。名前が見つからなければ黙って無視します。
 * 直したいときは el を書き換えるか、行ごと消してください。
 */
window.TB_SUB_V1 = [
  /* --- 技の名前がはっきり語っているもの --- */
  { id: 49,   mon: 'アイス',             skill: 'こごえる風',           el: 'flying'   },
  { id: 50,   mon: 'スノーマン',         skill: 'こごえる風',           el: 'flying'   },
  { id: 51,   mon: 'ブリザード',         skill: 'こごえる風',           el: 'flying'   },
  { id: 112,  mon: 'マメ',               skill: 'ラスターカノン',       el: 'steel'    },
  { id: 113,  mon: 'ライト',             skill: 'ラスターカノン',       el: 'steel'    },
  { id: 114,  mon: 'フラッシュ',         skill: 'ラスターカノン',       el: 'steel'    },
  { id: 121,  mon: 'エンジェル',         skill: '聖なる炎',             el: 'fire'     },
  { id: 122,  mon: 'アーク',             skill: '聖なる炎',             el: 'fire'     },
  { id: 123,  mon: 'セラフィム',         skill: '聖なる炎',             el: 'fire'     },
  { id: 151,  mon: 'ミユウ',             skill: 'リボンウィップ',       el: 'fairy'    },
  { id: 152,  mon: 'なしひろし',         skill: '梨汁スプラッシュ！',   el: 'water'    },
  { id: 201,  mon: 'ユニコーン',         skill: '角ドリル',             el: 'steel'    },
  { id: 207,  mon: 'ピラニア',           skill: '砂嵐',                 el: 'ground'   },
  { id: 211,  mon: 'ペンギン',           skill: 'こごえる風',           el: 'flying'   },
  { id: 213,  mon: 'フグ',               skill: '毒のトゲ',             el: 'poison'   },
  { id: 217,  mon: 'ドラゴン',           skill: 'ドラゴンブレス',       el: 'dragon'   },
  { id: 225,  mon: 'ヌシガメ',           skill: '毒針',                 el: 'poison'   },
  { id: 226,  mon: 'キツネビ',           skill: 'ハイドロカノン',       el: 'water'    },
  { id: 227,  mon: 'ライジン',           skill: 'ソーラービーム',       el: 'grass'    },
  { id: 323,  mon: 'ケケーキ',           skill: 'クリームロック',       el: 'fairy'    },
  { id: 324,  mon: 'ドドーナツ',         skill: 'シュガーロック',       el: 'fairy'    },
  { id: 410,  mon: 'エンシェントドラゴン', skill: '終焉の炎',           el: 'fire'     },
  { id: 938,  mon: 'ひんやりカキゴオリン', skill: 'ブリザードかきごおり', el: 'ice'    },
  { id: 942,  mon: 'プロトタイプ零号',   skill: 'ギアキック',           el: 'steel'    },
  { id: 950,  mon: '石板よみのボソ',     skill: 'こっそり呪文',         el: 'ghost'    },
  { id: 953,  mon: 'ほうせき妖精',       skill: 'キラキラショット',     el: 'fairy'    },
  { id: 954,  mon: 'いせき大工',         skill: 'かいしゅうラッシュ',   el: 'rock'     },
  { id: 964,  mon: 'カケルーン',         skill: 'うず連続打ち',         el: 'water'    },
  { id: 966,  mon: 'ダッシュン',         skill: 'かぜきり',             el: 'flying'   },
  { id: 971,  mon: 'ワルーガス',         skill: 'わる一撃',             el: 'poison'   },
  { id: 985,  mon: 'ベイセーラー',       skill: 'しおかぜパンチ',       el: 'flying'   },
  { id: 990,  mon: 'ラーメンスパーク',   skill: 'あつあつキック',       el: 'electric' },
  { id: 1076, mon: 'ケンゴーン',         skill: '花鳥風月斬',           el: 'grass'    },
  { id: 1131, mon: 'カセキングりゅう',   skill: 'アンモナイトうず',     el: 'water'    },
  { id: 1152, mon: 'コジセイゴ仙人',     skill: '背水の陣',             el: 'water'    },
  { id: 1159, mon: 'イオンぼうや',       skill: 'プラマイビリビリ',     el: 'electric' },
  { id: 1161, mon: 'ウチュウ大帝',       skill: 'こうせいフレア',       el: 'fire'     },
  { id: 1171, mon: 'カソクボルト',       skill: 'とうかそくアタック',   el: 'electric' },
  { id: 1175, mon: 'レキシタイセン侯',   skill: 'さんぎょうかくめい',   el: 'steel'    },
  { id: 1204, mon: 'ゾンビ犬',           skill: 'かみつき',             el: 'ghost'    },
  { id: 1206, mon: '霧の幽霊',           skill: 'ナイトブレス',         el: 'dark'     },
  { id: 1207, mon: '屍王',               skill: '腐蝕の剣',             el: 'poison'   },
  { id: 1208, mon: '石像ゴーレム',       skill: '地鳴りクラッシュ',     el: 'ground'   },
  { id: 1211, mon: '呪いの刀匠',         skill: '黒刃一閃',             el: 'steel'    },
  { id: 1212, mon: '幽霊電車',           skill: 'ゴーストラッシュ',     el: 'ghost'    },
  { id: 1408, mon: 'キャンプ隊長',       skill: 'たき火スパーク',       el: 'electric' },
  { id: 1412, mon: 'シャドーニンジャ',   skill: '影分身斬り',           el: 'ghost'    },
  { id: 1501, mon: 'わたがしフワリン',   skill: 'あまいかおりぜめ',     el: 'fairy'    },
  { id: 1503, mon: 'モロコシオ',         skill: 'しょうゆこがしぎり',   el: 'fire'     },
  { id: 1504, mon: 'だんごさぶろう',     skill: 'みたらしからめとり',   el: 'fairy'    },
  { id: 1505, mon: 'フウリンタロウ',     skill: 'かぜきりベル',         el: 'flying'   },
  { id: 1507, mon: 'アメジロウ',         skill: 'うずまきさいみん',     el: 'water'    },
  { id: 1612, mon: 'カゲハヤテ',         skill: 'かげばしり',           el: 'ghost'    },
  { id: 1613, mon: 'イワヨロイ',         skill: 'やまなり',             el: 'ground'   },
  { id: 2113, mon: 'ヤシノカゲ',         skill: 'きょだいなかげ',       el: 'ghost'    },

  /* --- キャラの見た目・名前から説明がつくもの --- */
  { id: 5,    mon: 'ドラゴン',           skill: 'ひっかく',             el: 'dragon'   },
  { id: 61,   mon: 'ウサギ',             skill: '跳ねる',               el: 'fairy'    },
  { id: 203,  mon: 'オクトパス',         skill: '墨鉄砲',               el: 'water'    },
  { id: 210,  mon: 'コアラ',             skill: 'ひっかき',             el: 'grass'    },
  { id: 220,  mon: 'カゲムシャ',         skill: '跳ねる',               el: 'ghost'    },
  { id: 924,  mon: 'ブレードウィング',   skill: 'しゅんそくぎり',       el: 'flying'   },
  { id: 1012, mon: 'クラゲン',           skill: 'とっしん',             el: 'water'    },
  { id: 1014, mon: 'ブロックラゲ',       skill: 'とっしん',             el: 'water'    },
  { id: 1122, mon: 'ジェットコースター男', skill: 'ねじれスピン',       el: 'flying'   },
  { id: 1413, mon: '宇宙飛行士',         skill: 'ゼロGパンチ',          el: 'flying'   }
];
