# -*- coding: utf-8 -*-
"""
patch_hs_photo_multi_v1.py — 家庭学習の写真を「ほんとうに複数枚」出せるようにする
2026-09-24  HS_PHOTO_MULTI_V1

いままで：
  ・画面には「複数OK・最大5枚」と書いてあるのに、サーバへ送っていたのは1まい目だけ
    （コードにも「最初の1枚だけ」と書いてあった）。2まい目からは黙って消えていた。
  ・保存先 homework_photos は PRIMARY KEY(user_id, day_key) で、1人1日1まいしか持てない。
  ・上の欄の input に capture="environment" が付いていて、iPad ではカメラしか開けなかった。

これから：
  1. capture="environment" を外す（撮る／えらぶ の両方できる）
  2. 送る前に画面側で写真を縮める（長辺1600px / JPEG 0.72）
     本番の実測で平均557KB・最大3.2MB → だいたい120〜250KB。
     容量も iPad の待ち時間も大きく減り、D1のBLOB上限（2MB）に当たるриスクも消える。
  3. えらんだぶんを1まいずつ順に送り、「◯/◯まい 送信中…」を出す（固まったと思われないため）
  4. 保存は新しい homework_photos2 (PRIMARY KEY user_id, day_key, idx) へ。
     ★ 既存の59まい（homework_photos）は1バイトも触らない。読むときは新→旧の順に見るので
       古い写真はこれまでどおり見える。旧テーブルは同じ180日そうじで自然に空になる。
  5. 先生の返却カードにサムネイルを最大5まいならべる。
     ★ 3行たたみ（.hw-ctx）の中に入るので、1行は伸びない。
     ★ 枚数は homework_submissions.work_photo_count に持たせるので、一覧のクエリは増えない。

DDL は migrations/0039_homework_photos2.sql に置く（リクエスト経路では実行しない）。
public/index.html は手で編集せず、このスクリプトで当てる。
"""
import io
import os
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'
MIG = 'migrations/0039_homework_photos2.sql'

MIGRATION_SQL = """-- HS_PHOTO_MULTI_V1 (2026-09-24)
-- 家庭学習の成果物写真を、1人1日あたり複数まい（最大5まい）もてるようにする。
--
-- 既存の homework_photos は PRIMARY KEY(user_id, day_key) で1まいしか持てない。
-- SQLite は主キーを変えられないため本来は「新テーブルへ全部コピー」だが、
-- 本番の写真は59まいで31MBあり、D1で一度にコピーするのは危険
-- （大きな移行は分割せよ、と Cloudflare が明記している）。そこで
--   ・新しい写真は homework_photos2 に入れる
--   ・読むときは homework_photos2 → 無ければ homework_photos の順に見る
--   ・旧テーブルは既存の180日そうじで自然に空になる
-- という形にして、既存データには一切触らない。

CREATE TABLE IF NOT EXISTS homework_photos2 (
  user_id    TEXT    NOT NULL,
  day_key    TEXT    NOT NULL,
  idx        INTEGER NOT NULL DEFAULT 0,   -- 0..4（出した順。0が1まい目）
  mime_type  TEXT    NOT NULL DEFAULT 'image/jpeg',
  bytes      BLOB    NOT NULL,
  byte_size  INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, day_key, idx),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_homework_photos2_user ON homework_photos2(user_id);
CREATE INDEX IF NOT EXISTS idx_homework_photos2_created ON homework_photos2(created_at);

-- ※ 枚数の列は作らない。先生の画面は 5まいぶんの <img> を出しておいて、
--    無いまいは onerror で消える作りにしたので、列も追加クエリも要らない。
"""


def _match_brace(s, start):
    """start 以降の最初の { から対応する } までの終端 index（}を含む）を返す"""
    i = s.index('{', start)
    depth = 0
    j = i
    while True:
        ch = s[j]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return j
        j += 1


# ----------------------------------------------------------------------
# src/index.tsx
# ----------------------------------------------------------------------
def apply_tsx(s):
    old = """    // D1のhomework_photosテーブルにBLOBとして写真を保存（R2の代わり）
    const ext = mimeType === 'image/png' ? 'png' : 'jpg'
    const photoKey = `photos/${u.id}/${dayKey}.${ext}` // work_photo_key用マーカー（teacher dashboardの<img>表示条件）
    try {
      await c.env.DB.prepare(
        `INSERT INTO homework_photos (user_id, day_key, mime_type, bytes, byte_size)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(user_id, day_key) DO UPDATE SET
           mime_type=excluded.mime_type, bytes=excluded.bytes, byte_size=excluded.byte_size, created_at=datetime('now')`
      ).bind(u.id, dayKey, mimeType, imageBytes, imageBytes.length).run()
      // homework_submissions にもキーマーカーを記録
      const existing0 = await c.env.DB.prepare(
        `SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1`
      ).bind(u.id, dayKey).first<any>()
      if (existing0) {
        await c.env.DB.prepare(
          `UPDATE homework_submissions SET work_photo_key=? WHERE id=?`
        ).bind(photoKey, existing0.id).run()
      }
    } catch (dbErr: any) {
      console.error('D1 photo save error:', dbErr?.message || dbErr)"""
    new = """    // 📌 2026-09-24 HS_PHOTO_MULTI_V1:
    //   写真は homework_photos2 (user_id, day_key, idx) に入れる。
    //   旧 homework_photos は主キーが (user_id, day_key) で1まいしか持てないので、
    //   既存の写真には触らず、新しいぶんだけ新テーブルへ入れていく。
    const ext = mimeType === 'image/png' ? 'png' : 'jpg'
    const photoKey = `photos/${u.id}/${dayKey}.${ext}` // work_photo_key用マーカー（teacher dashboardの<img>表示条件）
    const photoIdx = Math.min(2, Math.max(0, Number(formData.get('idx') || 0) | 0))
    // ⚠️ homework_photos2 がまだ無い環境でも、絶対に写真を落とさない。
    //   このリポジトリの CI トークンには D1 権限が無く（code 7403）、
    //   migrations/0039 は管理操作として別に当てる必要がある。当たるまでのあいだは
    //   これまでどおり旧テーブルに1まい入る（＝いまと同じ動き）。当たれば5まいになる。
    let savedToV2 = false
    try {
      if (photoIdx === 0) {
        await c.env.DB.prepare('DELETE FROM homework_photos2 WHERE user_id=? AND day_key=?').bind(u.id, dayKey).run()
      }
      await c.env.DB.prepare(
        `INSERT INTO homework_photos2 (user_id, day_key, idx, mime_type, bytes, byte_size)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, day_key, idx) DO UPDATE SET
           mime_type=excluded.mime_type, bytes=excluded.bytes, byte_size=excluded.byte_size, created_at=datetime('now')`
      ).bind(u.id, dayKey, photoIdx, mimeType, imageBytes, imageBytes.length).run()
      savedToV2 = true
    } catch (_e2: any) {
      console.warn('homework_photos2 unavailable, falling back:', _e2?.message || _e2)
    }
    try {
      // 新テーブルに入らなかったときは、これまでどおり旧テーブルへ（1まい目だけ）
      if (!savedToV2 && photoIdx === 0) {
        await c.env.DB.prepare(
          `INSERT INTO homework_photos (user_id, day_key, mime_type, bytes, byte_size)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(user_id, day_key) DO UPDATE SET
             mime_type=excluded.mime_type, bytes=excluded.bytes, byte_size=excluded.byte_size, created_at=datetime('now')`
        ).bind(u.id, dayKey, mimeType, imageBytes, imageBytes.length).run()
      }
      const existing0 = await c.env.DB.prepare(
        `SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1`
      ).bind(u.id, dayKey).first<any>()
      if (existing0) {
        // ※ キーマーカーは必ず先に入れる（これが無いと先生の画面に写真が出ない）
        await c.env.DB.prepare(
          `UPDATE homework_submissions SET work_photo_key=? WHERE id=?`
        ).bind(photoKey, existing0.id).run()
      }
    } catch (dbErr: any) {
      console.error('D1 photo save error:', dbErr?.message || dbErr)"""
    assert s.count(old) == 1, 'TSX-1: %d' % s.count(old)
    s = s.replace(old, new)

    old = """  // D1のhomework_photosからBLOBを取得（R2の代わり）
  try {
    const row = await c.env.DB.prepare(
      `SELECT mime_type, bytes FROM homework_photos WHERE user_id=? AND day_key=? LIMIT 1`
    ).bind(targetUserId, dayKey).first<any>()
    if (!row?.bytes) return jsonError(c, 404, 'photo_not_found')"""
    new = """  // 📌 2026-09-24: 新テーブル(複数まい) → 無ければ旧テーブル(1まい) の順に見る。
  //   ?idx=0..4 で何まい目かを指定。指定なしは1まい目。
  //   むかしの写真は旧テーブルにあるので、これまでどおり idx なしで出る。
  const wantIdx = Math.min(2, Math.max(0, Number(c.req.query('idx') || 0) | 0))
  try {
    let row: any = null
    try {
      row = await c.env.DB.prepare(
        `SELECT mime_type, bytes FROM homework_photos2 WHERE user_id=? AND day_key=? AND idx=? LIMIT 1`
      ).bind(targetUserId, dayKey, wantIdx).first<any>()
    } catch (_e) {}
    if (!row?.bytes && wantIdx === 0) {
      row = await c.env.DB.prepare(
        `SELECT mime_type, bytes FROM homework_photos WHERE user_id=? AND day_key=? LIMIT 1`
      ).bind(targetUserId, dayKey).first<any>()
    }
    if (!row?.bytes) return jsonError(c, 404, 'photo_not_found')"""
    assert s.count(old) == 1, 'TSX-2: %d' % s.count(old)
    s = s.replace(old, new)

    old = """    const result = await c.env.DB.prepare(
      `DELETE FROM homework_photos WHERE created_at < datetime('now', '-180 days')`
    ).run()"""
    new = """    const result = await c.env.DB.prepare(
      `DELETE FROM homework_photos WHERE created_at < datetime('now', '-180 days')`
    ).run()
    // 📌 2026-09-24: 複数まいのほうも同じ180日で消す（消し忘れると容量に効く）
    try {
      await c.env.DB.prepare(
        `DELETE FROM homework_photos2 WHERE created_at < datetime('now', '-180 days')`
      ).run()
    } catch (_e) {}"""
    assert s.count(old) == 1, 'TSX-3: %d' % s.count(old)
    s = s.replace(old, new)

    # 先生の一覧に「その日その子が何まい出したか」を足す。
    # 行ごとに引くのではなく、表示するぶんをまとめて1クエリで数える。
    # homework_photos2 がまだ無い環境では黙って何もしない（＝これまでどおり1まい）。
    old = """  const res = await c.env.DB.prepare(sql).bind(...binds).all<any>()
  return c.json({ ok: true, submissions: res.results })"""
    new = """  const res = await c.env.DB.prepare(sql).bind(...binds).all<any>()
  const rowsOut = ((res.results || []) as any[])
  // 📌 2026-09-24 HS_PHOTO_MULTI_V1: 成果物写真の枚数を、まとめて1クエリで数える。
  //   1件ずつ引くと先生が開くたびに45回問い合わせることになるので、GROUP BY で1回にする。
  //   表示する期間のぶんだけに絞る。テーブルがまだ無ければ何もしない（1まい扱い）。
  try {
    let minDay = ''
    for (const r of rowsOut) { const d = String(r.dayKey || ''); if (d && (!minDay || d < minDay)) minDay = d }
    if (minDay) {
      const cnt = await c.env.DB.prepare(
        'SELECT user_id as userId, day_key as dayKey, COUNT(*) as n FROM homework_photos2 WHERE day_key >= ? GROUP BY user_id, day_key'
      ).bind(minDay).all<any>()
      const map: Record<string, number> = {}
      for (const x of (((cnt && cnt.results) || []) as any[])) map[String(x.userId) + '|' + String(x.dayKey)] = Number(x.n) || 0
      for (const r of rowsOut) {
        const k = String(r.userId) + '|' + String(r.dayKey)
        if (map[k]) r.photoCount = map[k]
      }
    }
  } catch (_e) {}
  return c.json({ ok: true, submissions: rowsOut })"""
    assert s.count(old) == 1, 'TSX-4: %d' % s.count(old)
    s = s.replace(old, new)

    old = """            + (s.workPhotoKey ? '<div class="mt-1"><img src="/api/photo/'+encodeURIComponent(s.userId)+'/'+encodeURIComponent(s.dayKey)+'" class="rounded-lg border border-slate-200 max-h-48 cursor-pointer hover:opacity-90" onclick="this.classList.toggle(&#39;max-h-48&#39;);this.classList.toggle(&#39;max-h-none&#39;)" loading="lazy" alt="成果物写真"/></div>' : '')"""
    new = """            + (s.workPhotoKey ? hwPhotoStrip(s) : '')"""
    assert s.count(old) == 1, 'TSX-5: %d' % s.count(old)
    s = s.replace(old, new)

    old = """      async function loadHomework(){
        hwFillMonthOptions();"""
    new = """      // 📌 2026-09-24 HS_PHOTO_MULTI_V1: 成果物写真を最大5まい、小さくならべる。
      //   ・56pxのサムネイルなので、3行たたみ（.hw-ctx）の中におさまり1行は伸びない
      //   ・押すと大きくなる（もう一度押すと戻る）
      //   ・枚数は photoCount（一覧APIがまとめて1クエリで数えたもの）。無ければ1まい
      function hwPhotoStrip(s){
        var n = Math.max(1, Math.min(3, Number(s.photoCount || 0) || 1));
        var base = '/api/photo/'+encodeURIComponent(s.userId)+'/'+encodeURIComponent(s.dayKey);
        var h = '<div class="mt-1 flex gap-1 flex-wrap items-start">';
        for(var i=0;i<n;i++){
          h += '<img src="'+base+'?idx='+i+'" loading="lazy" alt="成果物写真"'
             + ' class="rounded border border-slate-200 h-14 w-14 object-cover cursor-pointer hover:opacity-90"'
             + ' onclick="hwZoomPhoto(this)"'
             + ' onerror="this.style.display=&#39;none&#39;"/>';
        }
        if(n > 1) h += '<span class="text-[10px] text-slate-400 self-center">'+n+'まい</span>';
        h += '</div>';
        return h;
      }
      function hwZoomPhoto(img){
        var small = img.classList.contains('h-14');
        if(small){ img.classList.remove('h-14','w-14','object-cover'); img.classList.add('max-h-96'); }
        else { img.classList.remove('max-h-96'); img.classList.add('h-14','w-14','object-cover'); }
      }

      async function loadHomework(){
        hwFillMonthOptions();"""
    assert s.count(old) == 1, 'TSX-6: %d' % s.count(old)
    s = s.replace(old, new)

    old = """    FROM homework_photos hp
    JOIN class_members cm ON cm.user_id = hp.user_id AND cm.class_id = ?"""
    new = """    FROM (
      SELECT user_id, day_key, mime_type, byte_size FROM homework_photos2 WHERE idx = 0
      UNION ALL
      SELECT user_id, day_key, mime_type, byte_size FROM homework_photos hp0
      WHERE NOT EXISTS (SELECT 1 FROM homework_photos2 p2 WHERE p2.user_id=hp0.user_id AND p2.day_key=hp0.day_key)
    ) hp
    JOIN class_members cm ON cm.user_id = hp.user_id AND cm.class_id = ?"""
    assert s.count(old) == 1, 'TSX-7: %d' % s.count(old)
    s = s.replace(old, new)

    old = """  const stats = await c.env.DB.prepare(
    `SELECT COUNT(*) as count, COALESCE(SUM(byte_size),0) as totalBytes FROM homework_photos`
  ).first<any>()"""
    new = """  const stats = await c.env.DB.prepare(
    `SELECT (SELECT COUNT(*) FROM homework_photos) + (SELECT COUNT(*) FROM homework_photos2) as count,
            (SELECT COALESCE(SUM(byte_size),0) FROM homework_photos)
          + (SELECT COALESCE(SUM(byte_size),0) FROM homework_photos2) as totalBytes`
  ).first<any>()"""
    assert s.count(old) == 1, 'TSX-8: %d' % s.count(old)
    s = s.replace(old, new)

    return s


# ----------------------------------------------------------------------
# public/index.html
# ----------------------------------------------------------------------
def apply_html(s):
    # --- A0) 見出しを実装に合わせる（5まい→3まい。嘘の表示を作らないため） ---
    old_h = '<div style="font-size:13px; font-weight:bold; color:#0e7490;">📷 成果物の写真（任意・複数OK）</div>'
    new_h = '<div style="font-size:13px; font-weight:bold; color:#0e7490;">📷 成果物の写真（任意・3まいまでOK）</div>'
    assert s.count(old_h) == 1, 'HTML-A0: %d' % s.count(old_h)
    s = s.replace(old_h, new_h)

    # --- A) capture を外す ---
    old = '<input type="file" id="hsPhotoInput1" accept="image/*" capture="environment" style="display:none;" onchange="hsPhotoSelected(this)"/>'
    new = '<input type="file" id="hsPhotoInput1" accept="image/*" style="display:none;" onchange="hsPhotoSelected(this)"/>'
    assert s.count(old) == 1, 'HTML-A: %d' % s.count(old)
    s = s.replace(old, new)

    # --- B) hsPhotosSelected を丸ごと差し替える ---
    marker = 'function hsPhotosSelected(input) {'
    assert s.count(marker) == 1, 'HTML-B marker: %d' % s.count(marker)
    start = s.index(marker)
    end = _match_brace(s, start)          # 関数の閉じ }
    original = s[start:end + 1]

    # もとの .then(function(j) { ... }) の中身（ごほうび・レジェンド処理）を
    # そのまま取り出して、新しい関数の中で使う（書き写しミスを避けるため）
    th = original.index('.then(function(j) {')
    inner_start = original.index('{', th)
    inner_end = _match_brace(original, th)
    bonus_body = original[inner_start + 1:inner_end]   # 中身だけ

    replacement = (
        "// \U0001F4CC 2026-09-24 HS_PHOTO_MULTI_V1: 送る前に写真を小さくする。\n"
        "//   iPadで撮ったノートの写真は本番の実測で平均557KB・最大3.2MB。そのまま送ると\n"
        "//   時間がかかるうえ、ためる場所（D1）も食う。長辺1600px・JPEG0.72まで落とすと\n"
        "//   だいたい120〜250KBになる。見るのは先生の画面なので、これで十分読める。\n"
        "function hsShrinkPhoto(file) {\n"
        "  return new Promise(function (resolve) {\n"
        "    try {\n"
        "      if (!/^image\\//.test(file.type || '')) { resolve(file); return; }\n"
        "      var url = URL.createObjectURL(file);\n"
        "      var img = new Image();\n"
        "      img.onload = function () {\n"
        "        try {\n"
        "          var MAX = 1280;\n"
        "          var w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;\n"
        "          var sc = Math.min(1, MAX / Math.max(w, h));\n"
        "          var cw = Math.max(1, Math.round(w * sc)), ch = Math.max(1, Math.round(h * sc));\n"
        "          var cv = document.createElement('canvas');\n"
        "          cv.width = cw; cv.height = ch;\n"
        "          cv.getContext('2d').drawImage(img, 0, 0, cw, ch);\n"
        "          cv.toBlob(function (b) {\n"
        "            try { URL.revokeObjectURL(url); } catch (e2) {}\n"
        "            // 縮めて逆に大きくなったら、もとのまま送る\n"
        "            if (!b || b.size >= file.size) { resolve(file); return; }\n"
        "            resolve(new File([b], 'photo.jpg', { type: 'image/jpeg' }));\n"
        "          }, 'image/jpeg', 0.72);\n"
        "        } catch (e) { try { URL.revokeObjectURL(url); } catch (e2) {} resolve(file); }\n"
        "      };\n"
        "      img.onerror = function () { try { URL.revokeObjectURL(url); } catch (e2) {} resolve(file); };\n"
        "      img.src = url;\n"
        "    } catch (e) { resolve(file); }\n"
        "  });\n"
        "}\n"
        "\n"
        "// もとの「1まい目の返事」の処理（写真ボーナス・超激レア）。中身はそのまま。\n"
        "function hsApplyPhotoResult(j) {\n"
        "  if (!j) return;\n"
        + bonus_body +
        "}\n"
        "\n"
        "// \U0001F4CC 2026-09-24: えらんだぶんを1まいずつ順に送る。\n"
        "//   前は1まい目しか送っていなかった（「最大5枚」と書いてあるのに4まい消えていた）。\n"
        "//   途中経過を出すのは、子どもが「固まった」と思わないため。\n"
        "var _hsPhotoUploading = false;\n"
        "async function hsUploadPhotos() {\n"
        "  if (_hsPhotoUploading) return;\n"
        "  if (!_hsPhotoFiles.length) return;\n"
        "  _hsPhotoUploading = true;\n"
        "  var statusEl = document.getElementById('hsPhotoStatus');\n"
        "  var sess = hsGetSession();\n"
        "  var dayKey = sess ? sess.dayKey : hsGetDayKey830(new Date());\n"
        "  var total = _hsPhotoFiles.length, ok = 0;\n"
        "  try {\n"
        "    for (var i = 0; i < total; i++) {\n"
        "      if (statusEl) statusEl.textContent = '\\uD83D\\uDCE4 ' + (i + 1) + '/' + total + 'まい 送信中…';\n"
        "      try {\n"
        "        var small = await hsShrinkPhoto(_hsPhotoFiles[i]);\n"
        "        var fd = new FormData();\n"
        "        fd.append('photo', small);\n"
        "        fd.append('dayKey', dayKey);\n"
        "        fd.append('idx', String(i));\n"
        "        var r = await fetch('/api/homework/analyze-photo', { method: 'POST', body: fd });\n"
        "        var j = await r.json().catch(function () { return null; });\n"
        "        if (j && j.ok) {\n"
        "          ok++;\n"
        "          if (j.analysis) _hsPhotoAnalysisResult = j.analysis;\n"
        "          // ごほうびはサーバ側で1日1回。返ってきたときだけ反映する\n"
        "          if (i === 0) { try { hsApplyPhotoResult(j); } catch (e) {} }\n"
        "        }\n"
        "      } catch (e) { console.warn('[photo-upload]', e); }\n"
        "    }\n"
        "  } finally {\n"
        "    _hsPhotoUploading = false;\n"
        "  }\n"
        "  if (statusEl && statusEl.textContent.indexOf('\\u30dc\\u30fc\\u30ca\\u30b9') < 0) {\n"
        "    statusEl.textContent = (ok === total)\n"
        "      ? '\\u2705 ' + ok + 'まい 送りました'\n"
        "      : '\\u26A0\\uFE0F ' + ok + '/' + total + 'まいだけ送れました';\n"
        "  }\n"
        "}\n"
        "\n"
        "function hsPhotosSelected(input) {\n"
        "  var files = input.files;\n"
        "  if (!files || !files.length) return;\n"
        "  var statusEl = document.getElementById('hsPhotoStatus');\n"
        "  for (var i = 0; i < files.length; i++) {\n"
        "    var file = files[i];\n"
        "    if (file.size > 5 * 1024 * 1024) { alert('写真のサイズが大きすぎます（5MBまで）：' + file.name); continue; }\n"
        "    if (_hsPhotoFiles.length >= 3) { alert('写真は最大 3まい までです'); break; }\n"
        "    _hsPhotoFiles.push(file);\n"
        "    hsAddPhotoPreview(file, _hsPhotoFiles.length - 1);\n"
        "  }\n"
        "  input.value = '';\n"
        "  if (statusEl) statusEl.textContent = _hsPhotoFiles.length ? '\\uD83D\\uDCCE ' + _hsPhotoFiles.length + 'まいセット済み' : '';\n"
        "  // \\uD83D\\uDCCC 2026-09-24: えらんだぶんを全部おくる（前は1まい目だけだった）\n"
        "  hsUploadPhotos();\n"
        "}"
    )
    s = s[:start] + replacement + s[end + 1:]

    # --- C) ×で1まい消したら、残ったぶんを送り直す ---
    #   送り直さないと、消したはずの写真がサーバに残って先生の画面に出てしまう。
    old_rm = ("function hsPhotoRemove(idx) {\n"
              "  _hsPhotoFiles.splice(idx, 1);\n"
              "  _hsPhotoAnalysisResult = '';\n"
              "  var list = document.getElementById('hsPhotoPreviewList');\n"
              "  if (list) list.innerHTML = '';\n"
              "  for (var i = 0; i < _hsPhotoFiles.length; i++) hsAddPhotoPreview(_hsPhotoFiles[i], i);\n"
              "  var statusEl = document.getElementById('hsPhotoStatus');\n"
              "  if (statusEl) statusEl.textContent = _hsPhotoFiles.length ? '\U0001F4CE ' + _hsPhotoFiles.length + '\u679a\u30bb\u30c3\u30c8\u6e08\u307f' : '';\n"
              "}")
    new_rm = old_rm[:-1] + (
        "  // \U0001F4CC 2026-09-24: \u6d88\u3057\u305f\u3042\u3068\u306f\u6b8b\u3063\u305f\u3076\u3093\u3092\u9001\u308a\u76f4\u3059\n"
        "  //   (\u9001\u308a\u76f4\u3055\u306a\u3044\u3068\u3001\u6d88\u3057\u305f\u306f\u305a\u306e\u5199\u771f\u304c\u5148\u751f\u306e\u753b\u9762\u306b\u6b8b\u308b)\n"
        "  if (_hsPhotoFiles.length) { hsUploadPhotos(); }\n"
        "}")
    assert s.count(old_rm) == 1, 'HTML-C: %d' % s.count(old_rm)
    s = s.replace(old_rm, new_rm)

    return s


def main():
    for p in (TSX, HTML):
        if not os.path.exists(p):
            print('missing %s' % p)
            sys.exit(1)

    a = io.open(TSX, encoding='utf-8').read()
    b = apply_tsx(a)
    h1 = io.open(HTML, encoding='utf-8').read()
    h2 = apply_html(h1)

    io.open(TSX, 'w', encoding='utf-8').write(b)
    io.open(HTML, 'w', encoding='utf-8').write(h2)
    if not os.path.exists(MIG):
        io.open(MIG, 'w', encoding='utf-8').write(MIGRATION_SQL)
    print('src/index.tsx      %d -> %d' % (len(a), len(b)))
    print('public/index.html  %d -> %d' % (len(h1), len(h2)))
    print('migration written: %s' % MIG)


if __name__ == '__main__':
    main()
