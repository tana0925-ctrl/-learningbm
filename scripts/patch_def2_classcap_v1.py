# -*- coding: utf-8 -*-
"""
DEF2_CLASSCAP_V1
  防衛戦の プログラムづくりを、先生が クラスごとに「ここまで」と きめられるようにする。

  かんがえかた
    ・きめていない クラスは 既定の 0（せいげんなし）。これまでと まったく 同じで、
      子どもが じぶんで 🔓 を おして ひろげられる。
    ・上限を さげても、すでに おいてある ぶひんは のこす。
      じょうけん・うごきは もともと d2tUsed で のこる しくみが あるので、
      ブロック（くりかえす など）も 同じ しくみに そろえる。
    ・子どもには 「まだ つかえないよ」と やわらかく 出す。せめる 言い方に しない。

  さわるファイル
    ・public/defense2.js  … 子どもの がわ
    ・src/index.tsx       … 先生の がわ（画面と 道）と、よみこみ番号

  一致しなければ 何も 書かずに 止まる（fail-closed）。
"""
import io
import sys

TSX = 'src/index.tsx'
D2J = 'public/defense2.js'

# 冪等性の番兵。検証条件とは べつの 文字列に してある。
GUARD = 'DEF2CAP_GUARD_V1'

NL = chr(10)


def read(p):
    return io.open(p, encoding='utf-8').read()


def write(p, s):
    io.open(p, 'w', encoding='utf-8', newline='').write(s)


def one(s, needle, label):
    n = s.count(needle)
    if n != 1:
        print('NG: アンカー %s が %d 件（1件でないので 止める）' % (label, n))
        sys.exit(1)


def sub(s, old, new, label):
    one(s, old, label)
    return s.replace(old, new, 1)


# ────────────────────────────── 子どもの がわ ──────────────────────────────

D2_CAP_BLOCK = """  /* DEF2_CLASSCAP_V1 / DEF2CAP_GUARD_V1 ここから ---------------------
     先生が クラスごとに「ここまで」を きめられるようにする ところ。

     ・きめていない クラスは 0 が かえる。そのときは これまでと まったく 同じで、
       子どもが じぶんで 🔓 を おして ひろげられる。
     ・上限を さげても、すでに おいてある ぶひんは のこる。
       じょうけん・うごきは d2tKeep が used を 見て のこし、
       ブロックは d2tBlocksHook が used.t を 見て のこす。
       だから ほぞんずみの プログラムは 1つも かわらない。
     ・よみとりに しっぱいしたら 0（せいげんなし）。子どもの 手を 止めない。 */
  var _d2cLv = 0;
  var _d2cAsked = false;

  function d2tCapLv() {
    var n = Number(_d2cLv || 0);
    if (!(n >= 1)) return D2T_MAXLV;
    if (n > D2T_MAXLV) return D2T_MAXLV;
    return n;
  }

  function d2tCapOn() { return d2tCapLv() < D2T_MAXLV; }

  function d2tCapLoad() {
    if (_d2cAsked) return;
    _d2cAsked = true;
    try {
      jget('/api/defense/prog-cap').then(function (r) {
        var n = (r && r.ok) ? Number(r.max_level || 0) : 0;
        if (!(n >= 1)) n = 0;
        if (n === _d2cLv) return;
        _d2cLv = n;
        try { d2tRepaint(); } catch (e) { }
      });
    } catch (e) { }
  }

  /* DEF2_CLASSCAP_V1 ここまで --------------------------------------- */

"""

D2_LOCK_NOTE = """    if (lv >= d2tCapLv() && d2tCapOn()) {
      out += '<div style="margin-top:8px;background:#f1f5f9;border:1px dashed #cbd5e1;border-radius:10px;padding:8px;font-size:11px;color:#475569;font-weight:800;line-height:1.6;text-align:center;">'
        + '🔒 つぎの ぶひんは まだ つかえないよ。<br>'
        + 'いまの ぶひんで くふうしてみよう。あける日は 先生が きめるよ。'
        + '</div>';
    }
"""

D2_ACTIVE = '  function d2tActive() { return !_d2tOff && d2tReady(); }'

D2_CLAMP_OLD = NL.join([
    '    if (n > D2T_MAXLV) n = D2T_MAXLV;',
    '    return n;',
    '  }',
])
D2_CLAMP_NEW = NL.join([
    '    if (n > d2tCapLv()) n = d2tCapLv();',
    '    return n;',
    '  }',
])

D2_USEDBOX_OLD = '    var used = { c: {}, a: {} };'
D2_USEDBOX_NEW = '    var used = { c: {}, a: {}, t: {} };'

D2_USEDPUT_OLD = '        if (n.c) used.c[n.c] = 1;'
D2_USEDPUT_NEW = NL.join([
    '        if (n.c) used.c[n.c] = 1;',
    '        if (n.t) used.t[n.t] = 1;',
])

D2_BLOCKS_OLD = NL.join([
    '      var list = (lv >= 3) ? D2T_B3 : (lv === 2 ? D2T_B2 : D2T_B1);',
    '      return list.indexOf(kind) >= 0;',
])
D2_BLOCKS_NEW = NL.join([
    '      var list = (lv >= 3) ? D2T_B3 : (lv === 2 ? D2T_B2 : D2T_B1);',
    '      if (list.indexOf(kind) >= 0) return true;',
    '      /* DEF2_CLASSCAP_V1 いま つかっている ブロックは 上限を さげても けさない */',
    '      return !!d2tUsed(window._pbCur ? (window._pbCur() || []) : []).t[kind];',
])

D2_FOOT_OLD = '    if (lv < D2T_MAXLV) {'
D2_FOOT_NEW = '    if (lv < d2tCapLv()) {'

D2_RESET = '''    out += '<button onclick="_def2TreeReset()"'''

D2_UP_OLD = '    if (lv >= D2T_MAXLV) return;'
D2_UP_NEW = '    if (lv >= d2tCapLv()) return;'

D2_PAINT_OLD = NL.join([
    '      lv = d2tLevel();',
    '      window._pbInjectCss();',
])
D2_PAINT_NEW = NL.join([
    '      d2tCapLoad();',
    '      lv = d2tLevel();',
    '      window._pbInjectCss();',
])


def patch_defense2(s):
    # レベルの ふたを、クラスの 上限で おさえる
    s = sub(s, D2_CLAMP_OLD, D2_CLAMP_NEW, 'd2tLevel の ふた')
    # 上限を もつ ところを 足す
    s = sub(s, D2_ACTIVE, D2_CAP_BLOCK + D2_ACTIVE, '上限ブロックの 場所')
    # いま つかっている ブロックの しゅるいも おぼえる
    s = sub(s, D2_USEDBOX_OLD, D2_USEDBOX_NEW, 'used の はこ')
    s = sub(s, D2_USEDPUT_OLD, D2_USEDPUT_NEW, 'used に 入れる ところ')
    # つかっている ブロックは 上限が 下でも パレットに のこす
    s = sub(s, D2_BLOCKS_OLD, D2_BLOCKS_NEW, 'ブロックの ふるいわけ')
    # 🔓 は クラスの 上限で 止まる
    s = sub(s, D2_FOOT_OLD, D2_FOOT_NEW, '🔓 を 出す じょうけん')
    # 止まったら やわらかく しらせる
    s = sub(s, D2_RESET, D2_LOCK_NOTE + D2_RESET, 'しらせの 場所')
    # 🔓 を おしたときの ふたも クラスの 上限に する
    s = sub(s, D2_UP_OLD, D2_UP_NEW, '🔓 の ふた')
    # 絵を かくときに 上限を よみに 行く
    s = sub(s, D2_PAINT_OLD, D2_PAINT_NEW, '上限を よむ きっかけ')
    return s


# ────────────────────────────── 先生の がわ ──────────────────────────────

TSX_ROUTES = """
// 🧩 2026-09: DEF2_CLASSCAP_V1 / DEF2CAP_GUARD_V1
//   防衛戦の プログラムづくりを、クラス単位で「ここまで」に できるようにする。
//   単元計画に あわせたいので、担任が 自分のクラスだけ レベル上限を きめられる。
//   ・制御はこの classes.def_prog_maxlv だけ。admin_settings 側は作らない
//     （ランキングのように2箇所で持つと「両方そろわないと効かない」罠になる）
//   ・0 は「せいげんなし」。既定が 0 なので、きめていないクラスは これまでと同じ
//   ・上限を さげても、子どもが すでに 置いた命令は のこす（画面側の used が のこす）
//   ・列が まだ無い／読めないときは 0 を かえす。子どもの手を止めない
//   ・ここでは 表も列も 作らない（リクエストパスで DDL は ぜったいに 走らせない）
async function defProgMaxLvOfClass(env: any, classId: string): Promise<number> {
  if (!classId) return 0
  try {
    const row: any = await env.DB.prepare('SELECT def_prog_maxlv AS mx FROM classes WHERE id = ? LIMIT 1').bind(classId).first<any>()
    const n = Number(row?.mx || 0)
    return (n >= 1 && n <= 3) ? n : 0
  } catch (e) {
    console.error('defProgMaxLvOfClass failed:', e)
    return 0
  }
}

// 子どもの画面が よむ。よむだけ
app.get('/api/defense/prog-cap', async (c) => {
  const u = c.get('user'); if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = await defenseClassId(c.env, u.id)
  const mx = await defProgMaxLvOfClass(c.env, classId)
  return c.json({ ok: true, class_id: classId, max_level: mx })
})

// 先生の画面が よむ。自分のクラスぶんだけ まとめて かえす
app.get('/api/teacher/defprog-maxlv', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const levels: any = {}
  try {
    const res = u.role === 'admin'
      ? await c.env.DB.prepare('SELECT id, def_prog_maxlv AS mx FROM classes WHERE teacher_id IS NOT NULL LIMIT 500').all<any>()
      : await c.env.DB.prepare('SELECT id, def_prog_maxlv AS mx FROM classes WHERE teacher_id = ? LIMIT 500').bind(u.id).all<any>()
    for (const r of (res.results || [])) {
      const n = Number((r as any).mx || 0)
      levels[String((r as any).id)] = (n >= 1 && n <= 3) ? n : 0
    }
  } catch (e) {
    console.error('defprog-maxlv list failed:', e)
  }
  return c.json({ ok: true, levels })
})

// 先生が きめる。0 で せいげんなしに もどせる。
// 非管理者は AND teacher_id = ? なので、他の先生のクラスは かえられない
app.put('/api/teacher/class/:classId/defprog-maxlv', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const body = await c.req.json().catch(() => null)
  let lv = Number(body?.maxLevel || 0)
  if (!(lv >= 1 && lv <= 3)) lv = 0
  const result = u.role === 'admin'
    ? await c.env.DB.prepare('UPDATE classes SET def_prog_maxlv = ? WHERE id = ?').bind(lv, classId).run()
    : await c.env.DB.prepare('UPDATE classes SET def_prog_maxlv = ? WHERE id = ? AND teacher_id = ?').bind(lv, classId, u.id).run()
  if (!result.meta?.changes) return jsonError(c, 404, 'class_not_found')
  return c.json({ ok: true, defProgMaxLv: lv })
})
"""

TSX_UI = """
          // ══════ 🧩 DEF2_CLASSCAP_V1 防衛戦プログラムの「ここまで」（既定はせいげんなし） ══════
          const dpcSel = document.createElement('select');
          dpcSel.className = 'text-xs px-2 py-1 rounded font-bold bg-indigo-50 text-indigo-700 border border-indigo-300';
          dpcSel.title = '防衛戦のプログラムづくりで、このクラスの子が ひろげられる レベルの上限です。「せいげんなし」は これまでどおり 子どもが自分で ひろげられます。上限を下げても、もう置いてある命令は消えません。';
          dpcSel.innerHTML = '<option value="0">🧩 プログラム せいげんなし</option>'
            + '<option value="1">🧩 プログラム レベル1まで</option>'
            + '<option value="2">🧩 プログラム レベル2まで</option>'
            + '<option value="3">🧩 プログラム レベル3まで</option>';
          dpcSel.value = String((window.__defProgMaxLv && window.__defProgMaxLv[cls.id]) || 0);
          dpcSel.onchange = async ()=>{
            const v = Number(dpcSel.value || 0);
            try{
              await api('/api/teacher/class/'+cls.id+'/defprog-maxlv',{
                method:'PUT', headers:{'content-type':'application/json'},
                body: JSON.stringify({maxLevel: v})
              });
              if(window.__defProgMaxLv) window.__defProgMaxLv[cls.id] = v;
            } catch(e){ alert(String(e.message||e)); }
          };
          btnGroup.appendChild(dpcSel);
"""

TSX_STK_END = NL.join([
    '  return c.json({ ok: true, stickerEnabled: enabled })',
    '})',
    '',
])

TSX_STK_BTN = '          btnGroup.appendChild(stkBtn);' + NL

TSX_LIST_HEAD = NL.join([
    "        wrap.innerHTML='';",
    '        if(!data.classes.length){',
])

TSX_LIST_HEAD_NEW = NL.join([
    "        wrap.innerHTML='';",
    '        // DEF2_CLASSCAP_V1 クラスごとの「ここまで」を まとめて よむ。よめなくても 表示は 止めない',
    "        try{ const _dpcAll = await api('/api/teacher/defprog-maxlv'); window.__defProgMaxLv = (_dpcAll && _dpcAll.levels) || {}; }",
    '        catch(e){ window.__defProgMaxLv = {}; }',
    '        if(!data.classes.length){',
])


def patch_tsx(s):
    # 道を 3本 足す（シールけんの となりに ならべる）
    s = sub(s, TSX_STK_END, TSX_STK_END + TSX_ROUTES, '道を 入れる 場所')
    # 先生の画面に えらぶ ところを 足す
    s = sub(s, TSX_STK_BTN, TSX_STK_BTN + TSX_UI, '先生の画面の 場所')
    # えらぶ ところの いまの 値を さきに よむ
    s = sub(s, TSX_LIST_HEAD, TSX_LIST_HEAD_NEW, 'クラス一覧の あたま')
    # 子どもの がわを 入れなおしてもらう
    s = sub(s, '/defense2.js?v=15', '/defense2.js?v=16', 'よみこみ番号')
    return s


def main():
    tsx = read(TSX)
    d2j = read(D2J)

    if GUARD in tsx and GUARD in d2j:
        print('すでに適用ずみ。何も書かない')
        return

    if GUARD in tsx or GUARD in d2j:
        print('NG: 片がわだけ 適用ずみ。手で 見てから やりなおす')
        sys.exit(1)

    d2j2 = patch_defense2(d2j)
    tsx2 = patch_tsx(tsx)

    write(D2J, d2j2)
    write(TSX, tsx2)
    print('PATCH OK')


main()
