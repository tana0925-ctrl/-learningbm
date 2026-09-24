// ==================== 🔒 ひみつのQR（校内でさがす） QRHUNT_V1 ====================
//
// 既存の「ひみつのQR」の作り替え。新しい機能を隣に足したのではない。
//
// もとの姿（2026-09-24 時点の実測）:
//   ・児童のショップ画面に「📁 画像をアップロード」だけが残っていた
//   ・QRの中身は URL ではなく BMSECRET2|... という独自文字列。だからカメラで読んでも何も起きない
//   ・発行UI（teacherQrGenBox / secretQrGenerateBtn / secretQrCoinAmount / secretQrValidMin）は
//     HTML に1つも存在せず、先生は1枚も作れない状態だった
//   ・D1 の progress 26行のうち、使った形跡があるのは1アカウント。
//     nonce を復号すると 2025-12-18 14:10〜14:20 の5回だけ。以後9か月ゼロ
//   ・キャラ復元QR（BMCHAR3）も発行・読み取りの両方の要素が無く、
//     代わりに「バックアップコード／ファイル」が生きている（player 全体を戻せる上位互換）
//
// 作り替えの要点:
//   ・QRの中身を https://learning-bm.pages.dev/q/<token> にする
//     → iPad のカメラが標準で開く。アプリ内にスキャナを作らない。jsQR も要らない
//   ・ごほうびは「ことば」を主役にする。コインは既定 0（→ 設計の根拠は docs 参照）
//   ・1人1回は D1 の台帳で確定する。クライアントの配列では守れない
//
// 設計方針（src/mi.tsx にならう）:
//   ・index.tsx へは import と registerQrHunt(app) の2行だけ
//   ・⚠️ ただし mi.tsx と違い、テーブルは runtime の CREATE TABLE では作らない。
//     DDL は migrations/0039_qr_hunt.sql だけ（2026-09-03 の障害が DDL のリクエスト実行だったため）
//
// D1 の読み取りについて:
//   ・WHERE の列に date() などの関数をかけない（索引が死ぬ。2026-08 の停止と同じ手口）
//   ・進捗は learning_results を見ない。qr_finds だけで完結する
//   ・児童側の API は1本も増やしていない。/api/student/class-mission に相乗りさせる
//
// @ts-nocheck
/* eslint-disable */

function jerr(c, status, message) { return c.json({ ok: false, error: message }, status) }

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (ch) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  })
}

// まぎらわしい字（0 O 1 l I）を抜いた32文字。
const QR_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

export function qrMakeToken() {
  const a = new Uint8Array(8)
  crypto.getRandomValues(a)
  let out = ''
  for (let i = 0; i < 8; i++) out += QR_CHARS[a[i] % QR_CHARS.length]
  return out
}

// JST の「いま」。SQL 側で日付関数を使わないぶん、ここで持つ。
function jstNow() { return new Date(Date.now() + 9 * 3600 * 1000) }
function jstYmd() { return jstNow().toISOString().slice(0, 10) }
function jstHm()  { return jstNow().toISOString().slice(11, 16) }

// 'open' | 'before' | 'after' | 'closed_now'
export function qrOpenState(h) {
  const ymd = jstYmd()
  if (ymd < String(h.start_at || '').slice(0, 10)) return 'before'
  if (ymd > String(h.end_at || '').slice(0, 10)) return 'after'
  if (h.open_from && h.open_to) {
    const hm = jstHm()
    if (hm < String(h.open_from) || hm > String(h.open_to)) return 'closed_now'
  }
  return 'open'
}

// ── 児童のホームに出すカードのもと ──
//   読み取り: qr_hunts 1行 ＋ qr_spots の枚数 ＋ その子の qr_finds（枚数ぶん）
//   ＝ 多くても「枚数 × 2 + 1」行。全件は数えない。
export async function qrHuntCard(c, classId, userId) {
  if (!classId || !userId) return null
  try {
    // ⚠️ end_at（列）には関数をかけない。右辺だけで日付を作る。索引 (class_id, end_at) が効く。
    const h = await c.env.DB.prepare(
      `SELECT id, title, start_at, end_at, open_from, open_to
         FROM qr_hunts
        WHERE class_id = ? AND end_at >= ?
        ORDER BY created_at DESC LIMIT 1`
    ).bind(classId, jstYmd()).first()
    if (!h) return null
    if (qrOpenState(h) === 'before') return null   // 始まる前は、そもそも出さない

    const tot = await c.env.DB.prepare(
      `SELECT COUNT(*) AS n FROM qr_spots WHERE hunt_id = ?`
    ).bind(h.id).first()
    const total = Number(tot?.n || 0)
    if (!total) return null

    const rows = await c.env.DB.prepare(
      `SELECT f.token, f.applied_at, s.reward_kind, s.reward_text, s.reward_monster_id, s.reward_coins
         FROM qr_finds f JOIN qr_spots s ON s.token = f.token
        WHERE f.hunt_id = ? AND f.user_id = ?`
    ).bind(h.id, userId).all()
    const list = (rows && rows.results) || []

    return {
      id: h.id,
      title: h.title,
      total: total,
      found: list.length,
      // もらった「ことば」だけを読み返せるようにする（図鑑がわり）
      words: list.filter(r => r.reward_text).map(r => String(r.reward_text)),
      // player への反映がまだのもの。homework_claims と同じ「台帳が先、反映はあと」
      pending: list
        .filter(r => !r.applied_at && (r.reward_kind === 'coin' || r.reward_kind === 'monster'))
        .map(r => ({ token: r.token, kind: r.reward_kind, monsterId: r.reward_monster_id, coins: Number(r.reward_coins || 0) })),
    }
  } catch (_e) {
    return null   // QRのせいでホームが壊れてはいけない
  }
}

async function teacherClass(c, u, classId) {
  if (!classId) return null
  if (u.role === 'admin') {
    return await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first()
  }
  return await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first()
}

export function registerQrHunt(app) {

  // ───────────────────────────────────────────────
  // 児童: QRを読んだときに開くページ
  //   ⚠️ 未ログインなら next つきでログインへ。戻り先を持たせないと中身が消える（実測ずみ）
  //   ⚠️ 外部CDNを使わない。子ども向けの画面なので、学校のネットが絞られていても必ず出る
  // ───────────────────────────────────────────────
  app.get('/q/:token', async (c) => {
    const token = String(c.req.param('token') || '').slice(0, 16)
    // ⚠️ このアプリの認証ミドルウェアは app.use('/api/*') に限定されている。
    //    つまり /q/... では c.get('user') は必ず空になる（ここで1度ハマった）。
    //    サーバで判定せず、既存の画面と同じくクライアント側で見る。
    //    下の fetch が 401 を返したら /login?next=/q/<token> に送る。
    return c.html(`<!doctype html><html lang="ja"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ひみつのQR</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#fdf6e3;font-family:"Hiragino Maru Gothic ProN","M PLUS Rounded 1c",sans-serif;padding:16px}
  .card{background:#fff;border-radius:18px;box-shadow:0 8px 24px rgba(0,0,0,.10);
        padding:24px;max-width:520px;width:100%;text-align:center}
  .env{font-size:64px;line-height:1;transition:transform .5s ease}
  .env.open{transform:rotate(-8deg) scale(1.12)}
  .ttl{font-size:13px;color:#a16207;font-weight:800;margin-bottom:10px}
  .word{font-size:19px;font-weight:800;color:#1f2937;margin:14px 0;line-height:1.6}
  .stars{font-size:26px;letter-spacing:3px;margin-top:12px}
  .cnt{font-size:13px;color:#6b7280;margin-top:4px}
  .btn{display:inline-block;margin-top:18px;background:#f59e0b;color:#fff;font-weight:800;
       border:0;border-radius:12px;padding:12px 26px;font-size:15px;text-decoration:none}
  .sub{font-size:12px;color:#9ca3af;margin-top:10px}
</style></head>
<body><div class="card" id="card">
  <div class="env" id="env">✉️</div>
  <div class="sub" id="msg">あけています…</div>
</div>
<script>
(function(){
  var TOKEN = ${JSON.stringify(token)};
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function stars(f,t){var s='';for(var i=0;i<t;i++)s+=(i<f)?'⭐️':'☆';return s;}
  function show(h){document.getElementById('card').innerHTML=h;}

  fetch('/api/qr/find/'+encodeURIComponent(TOKEN),{method:'POST'})
    .then(function(r){
      // まだログインしていない → ログイン画面へ。戻り先を持たせるのが肝心。
      if(r.status===401){ location.href='/login?next='+encodeURIComponent('/q/'+TOKEN); return null; }
      return r.json();
    })
    .then(function(j){
      if(j===null) return;
      if(!j||!j.ok){ show('<div class="env">😵</div><div class="word">うまく ひらけませんでした</div><a class="btn" href="/">もどる</a>'); return; }
      var r=j.result;
      if(r==='unknown'){ show('<div class="env">❓</div><div class="word">このQRは つかえません</div><a class="btn" href="/">もどる</a>'); return; }
      if(r==='before'){ show('<div class="env">⏳</div><div class="word">まだ はじまっていません</div><a class="btn" href="/">もどる</a>'); return; }
      if(r==='after'){ show('<div class="env">🌙</div><div class="word">このイベントは おわりました</div><a class="btn" href="/">もどる</a>'); return; }
      if(r==='closed_now'){ show('<div class="env">🕒</div><div class="word">いまは よみとれません<br><span style="font-size:14px;font-weight:400">'+esc(j.openFrom||'')+' 〜 '+esc(j.openTo||'')+' に きてね</span></div><a class="btn" href="/">もどる</a>'); return; }
      if(r==='not_member'){ show('<div class="env">🙅</div><div class="word">このQRは きみの クラスのものでは ないみたい</div><a class="btn" href="/">もどる</a>'); return; }
      if(r==='preview'){ show('<div class="env">👀</div><div class="ttl">先生用のかくにん</div><div class="word">'+(j.text?esc(j.text):'（ひとこと なし）')+'</div><div class="sub">先生が読んでも、台帳には記録されません</div><a class="btn" href="/teacher">もどる</a>'); return; }

      var head = (r==='already')
        ? '<div class="ttl">これは もう みつけていたよ</div>'
        : '<div class="ttl">🔒 '+esc(j.title||'ひみつのQR')+'</div>';
      var body = j.text ? esc(j.text) : 'みつけた！';
      if(r!=='already' && j.kind==='monster') body += '<br><span style="font-size:14px">あたらしい なかまが ふえたよ。アプリで たしかめてね</span>';
      if(r!=='already' && j.kind==='coin' && j.coins>0) body += '<br><span style="font-size:14px">'+j.coins+' コイン</span>';

      show('<div class="env open" id="env">📜</div>'+head+
           '<div class="word">'+body+'</div>'+
           '<div class="stars">'+stars(j.found,j.total)+'</div>'+
           '<div class="cnt">'+j.found+' / '+j.total+' まい みつけた</div>'+
           '<a class="btn" href="/">アプリに もどる</a>');
    })
    .catch(function(){
      show('<div class="env">📴</div><div class="word">つながりませんでした<br><span style="font-size:14px;font-weight:400">もういちど ためしてね</span></div><a class="btn" href="/">もどる</a>');
    });
})();
</script>
</body></html>`)
  })

  // ───────────────────────────────────────────────
  // 児童: 見つけた（台帳に書く）
  //   ⚠️ INSERT OR IGNORE は使わない。素の INSERT の成否で判定する
  //      （homework_claims / karte_material_uses と同じ作法）
  // ───────────────────────────────────────────────
  app.post('/api/qr/find/:token', async (c) => {
    const u = c.get('user')
    if (!u) return jerr(c, 401, 'unauthorized')
    const token = String(c.req.param('token') || '').toUpperCase().slice(0, 16)
    if (!token) return c.json({ ok: true, result: 'unknown' })

    const s = await c.env.DB.prepare(
      `SELECT s.token, s.hunt_id, s.reward_kind, s.reward_text, s.reward_monster_id, s.reward_coins,
              h.title, h.start_at, h.end_at, h.open_from, h.open_to, h.class_id
         FROM qr_spots s JOIN qr_hunts h ON h.id = s.hunt_id
        WHERE s.token = ? LIMIT 1`
    ).bind(token).first()
    if (!s) return c.json({ ok: true, result: 'unknown' })

    const st = qrOpenState(s)
    if (st !== 'open') {
      return c.json({ ok: true, result: st, title: s.title, openFrom: s.open_from, openTo: s.open_to })
    }

    const mem = await c.env.DB.prepare(
      `SELECT 1 FROM class_members WHERE class_id = ? AND user_id = ? LIMIT 1`
    ).bind(s.class_id, u.id).first()

    // 先生が下見で読んだときは、台帳に残さない（1人1回の記録を汚さない）
    if (!mem) {
      if (u.role === 'teacher' || u.role === 'admin') {
        return c.json({ ok: true, result: 'preview', title: s.title, text: s.reward_text || '' })
      }
      return c.json({ ok: true, result: 'not_member' })
    }

    // 'word' は player に反映するものが無いので、この場で確定させる
    const noApply = (s.reward_kind === 'word')
    let first = false
    try {
      await c.env.DB.prepare(
        `INSERT INTO qr_finds (token, user_id, hunt_id, found_at, applied_at)
         VALUES (?, ?, ?, datetime('now'), ` + (noApply ? `datetime('now')` : `NULL`) + `)`
      ).bind(token, u.id, s.hunt_id).run()
      first = true
    } catch (_e) {
      first = false   // すでに読んでいた
    }

    const cnt = await c.env.DB.prepare(
      `SELECT COUNT(*) AS n FROM qr_finds WHERE hunt_id = ? AND user_id = ?`
    ).bind(s.hunt_id, u.id).first()
    const tot = await c.env.DB.prepare(
      `SELECT COUNT(*) AS n FROM qr_spots WHERE hunt_id = ?`
    ).bind(s.hunt_id).first()

    return c.json({
      ok: true,
      result: first ? 'found' : 'already',
      title: s.title,
      kind: s.reward_kind,
      text: s.reward_text || '',
      monsterId: s.reward_monster_id,
      coins: Number(s.reward_coins || 0),
      found: Number(cnt?.n || 0),
      total: Number(tot?.n || 0),
    })
  })

  // 児童: キャラ／コインを player に入れ終えた、の確定
  app.post('/api/qr/applied', async (c) => {
    const u = c.get('user')
    if (!u) return jerr(c, 401, 'unauthorized')
    const body = await c.req.json().catch(() => null)
    const tokens = Array.isArray(body?.tokens) ? body.tokens.slice(0, 30) : []
    for (const t of tokens) {
      try {
        await c.env.DB.prepare(
          `UPDATE qr_finds SET applied_at = datetime('now')
            WHERE token = ? AND user_id = ? AND applied_at IS NULL`
        ).bind(String(t).slice(0, 16), u.id).run()
      } catch (_e) {}
    }
    return c.json({ ok: true })
  })

  // ───────────────────────────────────────────────
  // 先生: 一覧
  // ───────────────────────────────────────────────
  app.get('/api/teacher/qr-hunts', async (c) => {
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jerr(c, 403, 'forbidden')
    const classId = String(c.req.query('classId') || '')
    if (!(await teacherClass(c, u, classId))) return jerr(c, 404, 'class_not_found')

    const hs = await c.env.DB.prepare(
      `SELECT id, title, start_at, end_at, open_from, open_to
         FROM qr_hunts WHERE class_id = ? ORDER BY created_at DESC LIMIT 5`
    ).bind(classId).all()
    const hunts = (hs && hs.results) || []
    const out = []
    for (const h of hunts) {
      const sp = await c.env.DB.prepare(
        `SELECT token, label, sort_no, reward_kind, reward_text, reward_monster_id, reward_coins
           FROM qr_spots WHERE hunt_id = ? ORDER BY sort_no`
      ).bind(h.id).all()
      out.push({ ...h, state: qrOpenState(h), spots: (sp && sp.results) || [] })
    }
    return c.json({ ok: true, hunts: out })
  })

  // 先生: 作る（枚数は先生が決める。固定しない）
  app.post('/api/teacher/qr-hunt', async (c) => {
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jerr(c, 403, 'forbidden')
    const body = await c.req.json().catch(() => null)
    if (!body?.classId) return jerr(c, 400, 'classId required')
    if (!(await teacherClass(c, u, body.classId))) return jerr(c, 404, 'class_not_found')

    const n = Math.max(1, Math.min(60, Number(body.count) || 6))   // 既定6枚。上限は印刷の現実に合わせて60
    const id = crypto.randomUUID()
    const title = String(body.title || 'ひみつのQR').slice(0, 40)
    const startAt = String(body.startAt || jstYmd()).slice(0, 10) + ' 00:00:00'
    const endAt = String(body.endAt || jstYmd()).slice(0, 10) + ' 23:59:59'
    const openFrom = body.openFrom ? String(body.openFrom).slice(0, 5) : null
    const openTo = body.openTo ? String(body.openTo).slice(0, 5) : null

    await c.env.DB.prepare(
      `INSERT INTO qr_hunts (id, class_id, title, start_at, end_at, open_from, open_to, created_by, created_at)
       VALUES (?,?,?,?,?,?,?,?,datetime('now'))`
    ).bind(id, body.classId, title, startAt, endAt, openFrom, openTo, u.id).run()

    for (let i = 0; i < n; i++) {
      // token がぶつかる確率は 32^8 分の1。まず起きないが、起きたら1枚少なく作られるだけにする
      try {
        await c.env.DB.prepare(
          `INSERT INTO qr_spots (token, hunt_id, label, sort_no, reward_kind, reward_text, reward_coins)
           VALUES (?,?,?,?,'word','',0)`
        ).bind(qrMakeToken(), id, '', i + 1).run()
      } catch (_e) {}
    }
    return c.json({ ok: true, id })
  })

  // 先生: 1枚の中身を書きかえる（ひとことは空欄のままでよい）
  app.post('/api/teacher/qr-spot/:token', async (c) => {
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jerr(c, 403, 'forbidden')
    const token = String(c.req.param('token') || '').toUpperCase().slice(0, 16)
    const body = await c.req.json().catch(() => null)
    if (!body) return jerr(c, 400, 'invalid_json')

    const row = await c.env.DB.prepare(
      `SELECT s.token, h.class_id FROM qr_spots s JOIN qr_hunts h ON h.id = s.hunt_id WHERE s.token = ? LIMIT 1`
    ).bind(token).first()
    if (!row) return jerr(c, 404, 'not_found')
    if (!(await teacherClass(c, u, row.class_id))) return jerr(c, 403, 'forbidden')

    const kind = ['word', 'monster', 'coin'].indexOf(String(body.kind)) >= 0 ? String(body.kind) : 'word'
    const text = String(body.text || '').slice(0, 200)
    const monsterId = Number(body.monsterId) > 0 ? Math.floor(Number(body.monsterId)) : null
    // ⚠️ コインは既定0。周回と同じものさしに載せないため、上限も低くしてある
    const coins = Math.max(0, Math.min(100, Number(body.coins) || 0))
    const label = String(body.label || '').slice(0, 60)

    await c.env.DB.prepare(
      `UPDATE qr_spots SET label=?, reward_kind=?, reward_text=?, reward_monster_id=?, reward_coins=? WHERE token=?`
    ).bind(label, kind, text, monsterId, coins, token).run()
    return c.json({ ok: true })
  })

  // 先生: だれが何枚みつけたか
  app.get('/api/teacher/qr-hunt/:id/finds', async (c) => {
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jerr(c, 403, 'forbidden')
    const id = String(c.req.param('id') || '')
    const h = await c.env.DB.prepare(`SELECT id, class_id, title FROM qr_hunts WHERE id=? LIMIT 1`).bind(id).first()
    if (!h) return jerr(c, 404, 'not_found')
    if (!(await teacherClass(c, u, h.class_id))) return jerr(c, 403, 'forbidden')

    // クラスの人数ぶん × 枚数ぶん。23人×6枚なら 138行。
    const rows = await c.env.DB.prepare(
      `SELECT u.id AS userId, u.name AS name, u.login_id AS loginId,
              (SELECT COUNT(*) FROM qr_finds f WHERE f.hunt_id = ? AND f.user_id = u.id) AS found,
              (SELECT MAX(f2.found_at) FROM qr_finds f2 WHERE f2.hunt_id = ? AND f2.user_id = u.id) AS lastAt
         FROM class_members m JOIN users u ON u.id = m.user_id
        WHERE m.class_id = ?
        ORDER BY found DESC`
    ).bind(id, id, h.class_id).all()
    const tot = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM qr_spots WHERE hunt_id=?`).bind(id).first()
    return c.json({ ok: true, total: Number(tot?.n || 0), rows: (rows && rows.results) || [] })
  })

  // 先生: 印刷ページに渡すデータ（/api/ の下に置くことで認証ミドルウェアが効く）
  app.get('/api/teacher/qr-print-data', async (c) => {
    const u = c.get('user')
    if (!u) return jerr(c, 401, 'unauthorized')
    if (u.role !== 'teacher' && u.role !== 'admin') return jerr(c, 403, 'forbidden')
    const id = String(c.req.query('hunt') || '')
    const h = await c.env.DB.prepare(`SELECT id, class_id, title FROM qr_hunts WHERE id=? LIMIT 1`).bind(id).first()
    if (!h) return jerr(c, 404, 'not_found')
    if (!(await teacherClass(c, u, h.class_id))) return jerr(c, 403, 'forbidden')
    const sp = await c.env.DB.prepare(
      `SELECT token, sort_no FROM qr_spots WHERE hunt_id=? ORDER BY sort_no`
    ).bind(id).all()
    return c.json({ ok: true, title: h.title, spots: ((sp && sp.results) || []).map(x => ({ t: x.token, n: x.sort_no })) })
  })

  // ───────────────────────────────────────────────
  // 先生: 印刷ページ
  //   ⚠️ QR生成ライブラリは /qrgen.js に同梱してある（外部CDNを使わない）
  //   ⚠️ 児童側では読み込まない。ここだけ
  //   ・1枚に載せるのは QR と大きな番号だけ。場所名は刷らない
  //     （落ちていたカードから貼り場所が分かってしまうため）
  //   ・誤り訂正レベル H。掲示物は角が折れる・画びょうの穴が空くので、多少欠けても読めるように
  // ───────────────────────────────────────────────
  app.get('/teacher/qr-print', async (c) => {
    // ⚠️ /teacher/qr-print も /api/* の外なので c.get('user') は空。
    //    中身（token一覧）はサーバで埋めず、先生として /api/ から取りにいく。
    //    こうしないと、ログインしていない人にも token が見えてしまう。
    const id = String(c.req.query('hunt') || '')
    const origin = new URL(c.req.url).origin

    return c.html(`<!doctype html><html lang="ja"><head>
<meta charset="utf-8"/><title>ひみつのQR 印刷</title>
<script src="/qrgen.js?v=1"></script>
<style>
  @page{size:A4 portrait;margin:10mm}
  body{margin:0;font-family:"Hiragino Maru Gothic ProN",sans-serif;background:#eee}
  .sheet{width:190mm;margin:0 auto;background:#fff;padding:0;display:grid;
         grid-template-columns:1fr 1fr;gap:0}
  .cell{height:88mm;display:flex;flex-direction:column;align-items:center;justify-content:center;
        border:1px dashed #bbb;page-break-inside:avoid}
  .cell img,.cell canvas{width:45mm;height:45mm;image-rendering:pixelated}
  .no{font-size:30pt;font-weight:900;margin-top:3mm;color:#111}
  .bar{padding:10px;text-align:center;background:#fff;border-bottom:1px solid #ccc}
  @media print{.bar{display:none}body{background:#fff}}
</style></head><body>
<div class="bar">
  <b id="ttl">よみこみ中…</b>　
  <button onclick="window.print()">🖨 印刷する</button>
  <span style="font-size:12px;color:#666">　貼る前にラミネートかクリアファイルに入れると長もちします</span>
</div>
<div class="sheet" id="sheet"></div>
<script>
(async function(){
  var HUNT = ${JSON.stringify(id)};
  var ORIGIN = ${JSON.stringify(origin)};
  var sheet = document.getElementById('sheet');
  var r = await fetch('/api/teacher/qr-print-data?hunt=' + encodeURIComponent(HUNT));
  if(r.status === 401 || r.status === 403){ location.href = '/login?next=' + encodeURIComponent('/teacher/qr-print?hunt=' + HUNT); return; }
  var j = await r.json().catch(function(){ return null; });
  if(!j || !j.ok){ document.getElementById('ttl').textContent = 'よみこめませんでした'; return; }
  var SPOTS = j.spots;
  document.getElementById('ttl').textContent = j.title + ' ／ ' + SPOTS.length + 'まい';
  SPOTS.forEach(function(s){
    var cell = document.createElement('div');
    cell.className = 'cell';
    // 誤り訂正 H。type 0 = 必要な大きさを自動で選ぶ
    var q = qrcode(0, 'H');
    q.addData(ORIGIN + '/q/' + s.t);
    q.make();
    // createImgTag(cellSize, margin) の margin は「モジュール数×cellSize」。
    // 余白は4モジュール確保する（ここを詰めると読めなくなる）
    cell.innerHTML = q.createImgTag(6, 24) + '<div class="no">' + s.n + '</div>';
    sheet.appendChild(cell);
  });
})();
</script>
</body></html>`)
  })
}
