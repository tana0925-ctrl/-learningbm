#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_sticker_class_toggle.py --- シール交換けんをクラス単位でON/OFFできるようにする

  先生「ショップのシール1枚交換券、自分のクラスの子だけに使いたい」
  シールは先生が実物を渡す運用なので、他クラスの子が買っても渡せない。

  ★ 制御は classes.sticker_enabled の1箇所だけ。admin_settings 側は作らない。
    ランキングは admin_settings.ranking_enabled と classes.ranking_enabled の
    両方を見る作りになっていて、「両方ONでないと出ない」罠になっている。
    同じ轍を踏まない。

  ★ 列は先に流してある（2026-09-10）:
      ALTER TABLE classes ADD COLUMN sticker_enabled INTEGER NOT NULL DEFAULT 1;
    既定は 1（ON）＝今までどおり買える。このパッチでは DDL を一切実行しない。

  S1 GET  /api/teacher/classes ......... sticker_enabled を返す（画面のボタン用）
  S2 PUT  /api/teacher/class/:id/sticker-toggle ... 既存4本とまったく同じ作法。
                                          非管理者は AND teacher_id=? なので
                                          他の先生のクラスは変えられない
  S3 POST /api/shop/sticker/buy ........ ★コインを引く前に★ クラスを見る。
                                          OFFなら 403。state_json には触れない
  S4 GET  /api/shop/sticker/current .... enabled を返す（画面がカードを出すか決める）
      ※ POST /redeem には判定を入れない。
        OFFにしても「買ってある券」は使える。買った後に無効化されるのは
        子どもに不利益なので、ここは絶対に塞がない。
  S5 sticker.js（STICKER_JS）........... enabled=false ならカードを出さない。
                                          ただし今日の券があるときは
                                          「先生に見せる」だけ残す
  S6 教師画面 .......................... 既存のトグル列（🏆/📝/📓）に5個目を足すだけ。
                                          新しいパネルもタブも作らない
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

# ══════════════════════════════════════════════════════════
# S1 /api/teacher/classes が sticker_enabled を返す
# ══════════════════════════════════════════════════════════
S1_OLD = "menus_enabled as menusEnabled, created_at as createdAt,"
S1_NEW = "menus_enabled as menusEnabled, sticker_enabled as stickerEnabled, created_at as createdAt,"
sub('S1 クラス一覧に sticker_enabled を追加', S1_OLD, S1_NEW, 'sticker_enabled as stickerEnabled')

# ══════════════════════════════════════════════════════════
# S2 クラス単位のトグルAPI（既存4本と同じ作法）
# ══════════════════════════════════════════════════════════
S2_OLD = """  return c.json({ ok: true, menusEnabled: JSON.parse(menusEnabled) })
})
"""
S2_NEW = """  return c.json({ ok: true, menusEnabled: JSON.parse(menusEnabled) })
})

// 🎟️ 2026-09: シール1枚交換けんを、クラス単位でON/OFFする。
//   シールは先生が実物を渡す運用なので、担任が自分のクラスだけを開けられるようにする。
//   ・制御はこの classes.sticker_enabled だけ。admin_settings 側は作らない
//     （ランキングは2箇所で持っていて「両方ONでないと出ない」罠になっている）
//   ・非管理者は AND teacher_id=? なので、他の先生のクラスは変更できない
app.put('/api/teacher/class/:classId/sticker-toggle', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const body = await c.req.json().catch(() => null)
  const enabled = body?.enabled ? 1 : 0
  const result = u.role === 'admin'
    ? await c.env.DB.prepare(`UPDATE classes SET sticker_enabled=? WHERE id=?`).bind(enabled, classId).run()
    : await c.env.DB.prepare(`UPDATE classes SET sticker_enabled=? WHERE id=? AND teacher_id=?`).bind(enabled, classId, u.id).run()
  if (!result.meta?.changes) return jsonError(c, 404, 'class_not_found')
  return c.json({ ok: true, stickerEnabled: enabled })
})
"""
sub('S2 クラス単位のトグルAPI', S2_OLD, S2_NEW, "app.put('/api/teacher/class/:classId/sticker-toggle'")

# ══════════════════════════════════════════════════════════
# 共通: 児童の所属クラスで有効かどうかを見る関数
# ══════════════════════════════════════════════════════════
S3A_OLD = "app.post('/api/shop/sticker/buy', async (c) => {\n"
S3A_NEW = """// 🎟️ 2026-09: この児童のクラスでシール交換けんが使えるか。
//   クラスに入っていない子は「使える」扱いにする（今までどおり買える。既定ONと同じ考え方）。
//   読み取りは class_members → classes の1行ずつ。どちらも索引がある。
async function stickerEnabledFor(c: any, userId: string): Promise<boolean> {
  try {
    const row = await c.env.DB.prepare(
      'SELECT cl.sticker_enabled AS en FROM class_members cm JOIN classes cl ON cl.id = cm.class_id WHERE cm.user_id = ? LIMIT 1'
    ).bind(userId).first<any>()
    if (!row) return true
    return Number(row.en) !== 0
  } catch (e) {
    // 読めなかったときは止めない（買えなくなるより、買えるほうが害が小さい）
    console.error('stickerEnabledFor failed:', e)
    return true
  }
}

app.post('/api/shop/sticker/buy', async (c) => {
"""
sub('S3a クラス判定の共通関数', S3A_OLD, S3A_NEW, 'async function stickerEnabledFor(')

# ══════════════════════════════════════════════════════════
# S3 buy: ★コインを引く前に★ 判定する
# ══════════════════════════════════════════════════════════
S3_OLD = """  await ensureStickerTable(c.env)
  const dayKey = jstDayKey()
  const existing = await c.env.DB.prepare('SELECT id FROM sticker_vouchers WHERE user_id=? AND day_key=? LIMIT 1').bind(u.id, dayKey).first<any>()
  if (existing) return jsonError(c, 409, 'already_bought_today')"""
S3_NEW = """  // 🎟️ 2026-09: ★必ずコインを引く前に判定する★
  //   順番を逆にすると「OFFのクラスの子から300コインを引いてから弾く」事故になる。
  if (!(await stickerEnabledFor(c, u.id))) return jsonError(c, 403, 'sticker_disabled')
  await ensureStickerTable(c.env)
  const dayKey = jstDayKey()
  const existing = await c.env.DB.prepare('SELECT id FROM sticker_vouchers WHERE user_id=? AND day_key=? LIMIT 1').bind(u.id, dayKey).first<any>()
  if (existing) return jsonError(c, 409, 'already_bought_today')"""
sub('S3 buy はコインを引く前に判定', S3_OLD, S3_NEW, "jsonError(c, 403, 'sticker_disabled')")

# ══════════════════════════════════════════════════════════
# S4 current: enabled を返す（redeem には入れない）
# ══════════════════════════════════════════════════════════
S4A_OLD = """  await ensureStickerTable(c.env)
  const dayKey = jstDayKey()
  const v = await c.env.DB.prepare('SELECT id, status, created_at, expires_at, redeemed_at FROM sticker_vouchers WHERE user_id=? AND day_key=? ORDER BY created_at DESC LIMIT 1').bind(u.id, dayKey).first<any>()"""
S4A_NEW = """  await ensureStickerTable(c.env)
  // 🎟️ 2026-09: 画面がカードを出すかどうかを決めるために返す。
  //   OFFでも「買ってある券」は使えるので、下の voucher はそのまま返す。
  const stickerOn = await stickerEnabledFor(c, u.id)
  const dayKey = jstDayKey()
  const v = await c.env.DB.prepare('SELECT id, status, created_at, expires_at, redeemed_at FROM sticker_vouchers WHERE user_id=? AND day_key=? ORDER BY created_at DESC LIMIT 1').bind(u.id, dayKey).first<any>()"""
sub('S4a current でクラス判定を読む', S4A_OLD, S4A_NEW, 'const stickerOn = await stickerEnabledFor(c, u.id)')

S4B_OLD = "return c.json({ ok: true, boughtToday: false, serverTime: nowIso, voucher: null })"
S4B_NEW = "return c.json({ ok: true, enabled: stickerOn, boughtToday: false, serverTime: nowIso, voucher: null })"
sub('S4b current（券なし）に enabled', S4B_OLD, S4B_NEW, 'enabled: stickerOn, boughtToday: false')

S4C_OLD = "return c.json({ ok: true, boughtToday: true, serverTime: nowIso, voucher: {"
S4C_NEW = "return c.json({ ok: true, enabled: stickerOn, boughtToday: true, serverTime: nowIso, voucher: {"
sub('S4c current（券あり）に enabled', S4C_OLD, S4C_NEW, 'enabled: stickerOn, boughtToday: true')

# ══════════════════════════════════════════════════════════
# S5 sticker.js（STICKER_JS の中）
#    ※ 巨大な1行の文字列の中なので、\\n はそのまま（生の2文字）で扱う
# ══════════════════════════════════════════════════════════
S5A_OLD = "function refreshCardState(){ jget('/api/shop/sticker/current').then(function(res){ if(res&&res.ok){ _boughtToday=!!res.boughtToday; updateCardLabel(); } }); }"
S5A_NEW = ("var _stickerOn=true;\\n"
           "  function removeCard(){ var c0=document.getElementById('stickerShopCard'); if(c0&&c0.parentNode) c0.parentNode.removeChild(c0); }\\n"
           "  function refreshCardState(){ jget('/api/shop/sticker/current').then(function(res){ if(res&&res.ok){ "
           "if(typeof res.enabled!=='undefined') _stickerOn=!!res.enabled; "
           "_boughtToday=!!res.boughtToday; "
           "/* OFFのクラスで、今日の券も無いならカードごと消す。券があるときは「先生に見せる」ために残す */ "
           "if(!_stickerOn && !_boughtToday){ removeCard(); return; } "
           "ensureCard(); updateCardLabel(); } }); }")
sub('S5a 画面: enabled を受け取ってカードを出し分ける', S5A_OLD, S5A_NEW, 'var _stickerOn=true;')

S5B_OLD = ("function ensureCard(){\\n    var container=document.getElementById('shopItemsContainer');\\n"
           "    if(!container) return;\\n    if(document.getElementById('stickerShopCard')) return;\\n")
S5B_NEW = ("function ensureCard(){\\n    var container=document.getElementById('shopItemsContainer');\\n"
           "    if(!container) return;\\n"
           "    /* 🎟️ 2026-09: 先生がこのクラスでOFFにしている間は出さない。\\n"
           "       ただし今日の券を持っている子には出す（買った券は必ず使えるようにするため）。 */\\n"
           "    if(!_stickerOn && !_boughtToday){ removeCard(); return; }\\n"
           "    if(document.getElementById('stickerShopCard')) return;\\n")
sub('S5b 画面: OFFならカードを作らない', S5B_OLD, S5B_NEW, '先生がこのクラスでOFFにしている間は出さない')

S5C_OLD = "card.addEventListener('click', function(){ if(_boughtToday) openCurrent(); else doBuy(); });"
S5C_NEW = "card.addEventListener('click', function(){ if(_boughtToday) openCurrent(); else if(!_stickerOn){ alert('いまは このクラスでは つかえません。'); } else doBuy(); });"
sub('S5c 画面: OFFのときに押しても買わない', S5C_OLD, S5C_NEW, 'いまは このクラスでは つかえません。')

S5D_OLD = "else if(res && res.__status===401){ alert('ログインが ひつようです。'); }"
S5D_NEW = ("else if(res && res.__status===403){ alert('いまは このクラスでは つかえません。'); _stickerOn=false; removeCard(); }\\n"
           "      else if(res && res.__status===401){ alert('ログインが ひつようです。'); }")
sub('S5d 画面: サーバが403を返したときの表示', S5D_OLD, S5D_NEW, "res.__status===403")

# ══════════════════════════════════════════════════════════
# S6 教師画面: 既存のトグル列に5個目
# ══════════════════════════════════════════════════════════
S6_OLD = """          btnGroup.appendChild(ctBtn);

          // ====== 全メニュー表示トグル ======"""
S6_NEW = """          btnGroup.appendChild(ctBtn);

          // ====== 🎟️ シール交換けんトグル（既存の並びに足すだけ。新しいパネルは作らない） ======
          const stkBtn = document.createElement('button');
          const stkOn = (cls.stickerEnabled === undefined) ? true : !!cls.stickerEnabled;
          const stkCls = function(on){ return on
            ? 'text-xs px-2 py-1 rounded font-bold bg-amber-100 text-amber-700 border border-amber-300 hover:bg-amber-200'
            : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200'; };
          stkBtn.className = stkCls(stkOn);
          stkBtn.textContent = stkOn ? '🎟️ シール交換けんON' : '🎟️ シール交換けんOFF';
          stkBtn.title = stkOn
            ? 'クリックでこのクラスのショップから「シール1枚交換けん」を隠す（買ってある券は使えます）'
            : 'クリックでこのクラスのショップに「シール1枚交換けん」を出す';
          stkBtn.dataset.on = stkOn ? '1' : '';
          stkBtn.onclick = async ()=>{
            const newVal = !stkBtn.dataset.on;
            try{
              await api('/api/teacher/class/'+cls.id+'/sticker-toggle',{
                method:'PUT', headers:{'content-type':'application/json'},
                body: JSON.stringify({enabled: newVal})
              });
              stkBtn.dataset.on = newVal ? '1' : '';
              stkBtn.className = stkCls(newVal);
              stkBtn.textContent = newVal ? '🎟️ シール交換けんON' : '🎟️ シール交換けんOFF';
              stkBtn.title = newVal
                ? 'クリックでこのクラスのショップから「シール1枚交換けん」を隠す（買ってある券は使えます）'
                : 'クリックでこのクラスのショップに「シール1枚交換けん」を出す';
            } catch(e){ alert(String(e.message||e)); }
          };
          btnGroup.appendChild(stkBtn);

          // ====== 全メニュー表示トグル ======"""
sub('S6 教師画面のトグル列に5個目', S6_OLD, S6_NEW, "'/sticker-toggle'")

# ══════════════════════════════════════════════════════════
# 検証 ── 合言葉とは別に「結果そのもの」を見る
# ══════════════════════════════════════════════════════════
def route(path, method='post'):
    a = src.index("app.%s('%s'" % (method, path))
    return src[a:src.index('\n})\n', a)]

# ★1 いちばん大事: コインを引く前に判定しているか
buy = route('/api/shop/sticker/buy')
i_gate  = buy.index("sticker_disabled")
i_read  = buy.index("SELECT state_json FROM progress")
i_write = buy.index("state.coins = coins - STICKER_PRICE")
if not (i_gate < i_read < i_write):
    fail('buy: クラス判定がコインの読み書きより後ろにあります（OFFのクラスの子からコインを引いてしまいます）')
print('🔎 buy: クラス判定 → コイン読み取り → コイン減算 の順（コインを引く前に弾きます）')

# ★2 redeem を塞いでいないこと（買ってある券は使える）
red = route('/api/shop/sticker/redeem')
for bad in ['stickerEnabledFor', 'sticker_enabled', 'sticker_disabled']:
    if bad in red:
        fail('redeem にクラス判定が入っています（買ってある券が使えなくなります）: %s' % bad)
print('🔎 redeem には判定なし＝OFFにしても「買ってある券」は使えます')

# ★3 制御が1箇所だけであること（ランキングの二重管理を繰り返さない）
# ※ 自分で書いた説明コメントに両方の語が入るので、コメント行は除いて見る
for _l in src.split('\n'):
    _ls = _l.strip()
    if _ls.startswith('//') or _ls.startswith('*') or _ls.startswith('/*'): continue
    if 'admin_settings' in _l and 'sticker' in _l:
        fail('admin_settings 側にもシールの設定を作っています（制御は classes だけにすること）: ' + _ls[:90])
n_col = len([l for l in src.split('\n') if 'sticker_enabled' in l and not l.strip().startswith('//')])
print('🔎 sticker_enabled を使う行は %d 行。すべて classes テーブル（admin_settings には無し）' % n_col)

# ★4 他の先生のクラスを変えられないこと
tog = route('/api/teacher/class/:classId/sticker-toggle', 'put')
if 'AND teacher_id=?' not in tog:
    fail('トグルAPIに teacher_id の条件がありません（他の先生のクラスを変更できてしまいます）')
if "u.role === 'admin'" not in tog:
    fail('トグルAPIの管理者分岐が既存4本と違います')
print('🔎 トグルAPI: 非管理者は AND teacher_id=? つき（他の先生のクラスは変更できません）')

# ★5 DDL をリクエスト経路で走らせていないこと
for l in src.split('\n'):
    ls = l.strip()
    if ls.startswith('//'): continue
    if 'ALTER TABLE classes' in l or 'sticker_enabled INTEGER' in l:
        fail('コードの中で列を作ろうとしています（DDLは先生がD1で流しずみ）: ' + ls[:80])
g0 = src.index('let _adminChecked = false'); g1 = src.index('// -------------------- DB migration', g0)
for l in src[g0:g1].split('\n'):
    if 'CREATE INDEX' in l and not l.strip().startswith('//'):
        fail('起動時ミドルウェアに CREATE INDEX が復活しています')
print('🔎 このパッチは DDL を1つも実行しません')

# ★6 state_json を新たに触っていないこと
n_state_before = orig.count('state_json')
n_state_after  = src.count('state_json')
if n_state_after != n_state_before:
    fail('state_json を触る箇所が %d → %d に変わりました' % (n_state_before, n_state_after))
print('🔎 state_json を触る箇所: %d（変化なし）' % n_state_after)

# ★7 画面側が出し分けを持っていること
for must in ['var _stickerOn=true;', 'function removeCard()', "res.__status===403",
             'いまは このクラスでは つかえません。', '🎟️ シール交換けんON', "'/sticker-toggle'",
             'cls.stickerEnabled', 'sticker_enabled as stickerEnabled']:
    if must not in src: fail('入っていないものがあります: %s' % must)
print('🔎 児童画面の出し分けと、教師画面の5個目のボタンが入りました')

# ★8 既存のトグル4本を壊していないこと
for must in ["app.put('/api/teacher/class/:classId/homework-toggle'",
             "app.put('/api/teacher/class/:classId/contact-toggle'",
             "app.put('/api/teacher/class/:classId/ranking-toggle'",
             "app.put('/api/teacher/class/:classId/menus-toggle'",
             'btnGroup.appendChild(rankBtn)', 'btnGroup.appendChild(hwBtn)', 'btnGroup.appendChild(ctBtn)',
             "app.get('/sticker.js'", 'const STICKER_JS', 'ensureStickerTable',
             'idx_sticker_user_day']:
    if must not in src: fail('★既存のものが失われました: %s' % must)
print('🔎 既存のトグル4本・sticker.js の配信・券テーブルはそのままです')

# ★9 いつもの安全確認
def rc(t):
    a = t.index("app.get('/', async (c) => {"); b = t.index("app.get('/logout'", a)
    return t[a:b].count('.replace(')
if rc(src) != rc(orig):
    fail('置換チェーンの数が変わりました（%d → %d）' % (rc(orig), rc(src)))
print('🔎 置換チェーン: %d 件（パッチ前と同じ）' % rc(src))

bal  = len(re.findall(r'<div\b', src))  - len(re.findall(r'</div>', src))
bal0 = len(re.findall(r'<div\b', orig)) - len(re.findall(r'</div>', orig))
if bal != bal0: fail('<div> の釣り合いが変わりました')
print('🔎 <div> の釣り合い: 変化なし')

# ★10 他セッションの担当領域に触れていないこと
import hashlib
def area(t, s0, s1):
    a = t.index(s0); b = t.index(s1, a); return hashlib.md5(t[a:b].encode('utf-8')).hexdigest()
for name, s0, s1 in [('防衛戦', 'async function ensureDefenseTables', "app.post('/api/defense/reward-claim'"),
                     ('カルテ', 'function _buildKarteHtml', 'function downloadKartePdf')]:
    if area(src, s0, s1) != area(orig, s0, s1):
        fail('%s のコードが変わっています（このパッチでは触らない約束です）' % name)
print('🔎 防衛戦・カルテのコードには触れていません（md5 一致）')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
print('---- 入れたもの ----')
for t in done: print(' ・' + t)
if not done: print(' （なし）')
