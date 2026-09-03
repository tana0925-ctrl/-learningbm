# -*- coding: utf-8 -*-
"""
コイン台帳の穴ふさぎ v1（src/index.tsx のみ／public/index.html は触らない）

直すもの
  Fix 1  シール1枚交換けん（300コイン）の支払いが、古い端末の全置換保存で復活する
         - 1a サーバ: PUT /api/student/progress に _serverSpentCoins の照合を追加
         - 1b クライアント: 購入直後に res.serverSpentCoins を player に写す
              （これが無いと 1a が「まだ引かれていない端末」と誤認して二重に引く）
  Fix 2  /api/teacher/homework/:id/return のコイン付与に「付与済みの目印」が無い
         - 2a 台帳テーブル homework_rewards（submission_id が PRIMARY KEY）
         - 2b 付与は「枠の確保 → 加算 → 失敗なら枠を解放」の順（src/mi.tsx と同じ作法）
         - 2c サーバ: PUT /api/student/progress に _hwCoinsApplied の補填を追加

作法は既存の _contactCoinsApplied / _miCoinsApplied / mi_rewards に厳密に倣う。
既存の「破壊的上書き防止（regression guard）」には一切手を触れない。

冪等：2回流しても安全（適用済みなら SKIP）。アンカーは事前に一意性を検証する。
"""
import sys

TARGET = 'src/index.tsx'

# src/index.tsx は LF。public/index.html（CRLF）とは違うので混同しないこと。
with open(TARGET, 'rb') as f:
    content = f.read().decode('utf-8')

if '\r\n' in content:
    print('FAIL: src/index.tsx に CRLF が混入している（想定外）', file=sys.stderr)
    sys.exit(1)

before_len = len(content)
applied = 0
skipped = 0


def sub(name, search, replace):
    """アンカーの一意性を検証したうえで1回だけ置換する。"""
    global content, applied, skipped
    if replace in content:
        print('SKIP: %s (already applied)' % name, file=sys.stderr)
        skipped += 1
        return
    n = content.count(search)
    if n == 0:
        print('FAIL: %s (anchor not found)' % name, file=sys.stderr)
        sys.exit(1)
    if n != 1:
        print('FAIL: %s (anchor is not unique: %d hits)' % (name, n), file=sys.stderr)
        sys.exit(1)
    content = content.replace(search, replace, 1)
    print('OK  : %s' % name, file=sys.stderr)
    applied += 1


# ────────────────────────────────────────────────────────────────
# Fix 1a + 2c : PUT /api/student/progress の照合を追加
#   ランキングかけら（_rankShardsApplied）のブロックの直後に置く。
#   破壊的上書き防止ガードはこれより前にあり、早期 return するので影響なし。
# ────────────────────────────────────────────────────────────────
A_OLD = (
    "        try { if (_inc.fractionFest) _inc.fractionFest.totalShards = _inc.lab.shards } catch (_e) {}\n"
    "        saveJson = JSON.stringify(_inc)\n"
    "      }\n"
)
A_NEW = A_OLD + (
    "      // 🎟️ シール1枚交換けんの支払い（300コイン）：サーバが引いた分を、クライアントの全置換保存でも必ず反映する。\n"
    "      //    _contactCoinsApplied / _miCoinsApplied とまったく同じ「サーバ累計 vs クライアント累計」方式で、\n"
    "      //    向きが引き算なだけ。クライアントからの申告は一切信じない：\n"
    "      //      ・サーバ累計のほうが大きいときだけ差分を引く（＝クライアントが金額を申告する余地はない）\n"
    "      //      ・クライアントの台帳が水増しされていても返金は起きず、台帳はサーバの値に戻す\n"
    "      const _srvSpent = Number(_srv._serverSpentCoins) || 0\n"
    "      const _cliSpent = Number(_inc._serverSpentCoins) || 0\n"
    "      if (_srvSpent > _cliSpent) {\n"
    "        _inc.coins = Math.max(0, (Number(_inc.coins) || 0) - (_srvSpent - _cliSpent))\n"
    "        _inc._serverSpentCoins = _srvSpent\n"
    "        saveJson = JSON.stringify(_inc)\n"
    "      } else if (_cliSpent > _srvSpent) {\n"
    "        // 台帳の水増し。コインは1枚も動かさず、台帳だけサーバの値に戻す。\n"
    "        _inc._serverSpentCoins = _srvSpent\n"
    "        saveJson = JSON.stringify(_inc)\n"
    "      }\n"
    "      // 📚 宿題の返却ボーナス（150〜250）：サーバが付与済みなら、クライアントの全置換保存でも必ず補填。\n"
    "      //    金額はサーバーの定数と homework_rewards 台帳だけで決まる（クライアントの申告は不使用）。\n"
    "      const _srvHw = Number(_srv._hwCoinsApplied) || 0\n"
    "      const _cliHw = Number(_inc._hwCoinsApplied) || 0\n"
    "      if (_srvHw > _cliHw) {\n"
    "        _inc.coins = (Number(_inc.coins) || 0) + (_srvHw - _cliHw)\n"
    "        _inc._hwCoinsApplied = _srvHw\n"
    "        saveJson = JSON.stringify(_inc)\n"
    "      } else if (_cliHw > _srvHw) {\n"
    "        // 台帳の水増し（次回以降の補填を殺すための細工）。コインは足さず、台帳だけサーバの値に戻す。\n"
    "        _inc._hwCoinsApplied = _srvHw\n"
    "        saveJson = JSON.stringify(_inc)\n"
    "      }\n"
)
sub('1a+2c progress: _serverSpentCoins / _hwCoinsApplied の照合', A_OLD, A_NEW)


# ────────────────────────────────────────────────────────────────
# Fix 2a + 2b : 宿題の返却ボーナスを「台帳に枠を取ってから付与」に変える
# ────────────────────────────────────────────────────────────────
B_OLD = (
    "  // ── 先生ボーナス：返却時に自動でコインを付与 ──\n"
    "  const noReward = (body && body.noReward === true)\n"
    "  if (!noReward) {\n"
    "  const TEACHER_BONUS = 150\n"
    "  const PHYSICAL_BONUS = 100  // 成果物ありなら追加\n"
    "  try {\n"
    "    const sub = await c.env.DB.prepare(`SELECT user_id FROM homework_submissions WHERE id=?`).bind(hwId).first<any>()\n"
    "    if (sub?.user_id) {\n"
    "      const bonusAmount = TEACHER_BONUS + (body.hasPhysical ? PHYSICAL_BONUS : 0)\n"
    "      const prog = await c.env.DB.prepare(`SELECT state_json FROM progress WHERE user_id=?`).bind(sub.user_id).first<any>()\n"
    "      if (prog?.state_json) {\n"
    "        const state = JSON.parse(prog.state_json)\n"
    "        state.coins = (Number(state.coins) || 0) + bonusAmount\n"
    "        await c.env.DB.prepare(`UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?`).bind(JSON.stringify(state), sub.user_id).run()\n"
    "      }\n"
    "    }\n"
    "  } catch (e) { console.error('teacher bonus error:', e) }\n"
    "  }\n"
)
B_NEW = (
    "  // ── 先生ボーナス：返却時に自動でコインを付与 ──\n"
    "  // 🧾 二重付与を構造的に防ぐ。src/mi.tsx の miGrantMonthlyReward（mi_rewards）とまったく同じ順番：\n"
    "  //   1) homework_rewards に INSERT して「この提出ぶんの枠」を先に確保する\n"
    "  //      submission_id が PRIMARY KEY なので、連打・二重返却では2行目が構造的に入らない\n"
    "  //   2) 確保できたときだけ progress.state_json にサーバー側でコインを加算し、\n"
    "  //      あわせて累計台帳 _hwCoinsApplied を増やす（PUT /api/student/progress 側で補填される）\n"
    "  //   3) コイン加算に失敗したら枠を解放して、次回リトライできるようにする（コインを失わせない）\n"
    "  //   金額はサーバーの定数だけで決める。児童のクライアントからの申告は一切受け取らない。\n"
    "  const noReward = (body && body.noReward === true)\n"
    "  if (!noReward) {\n"
    "  const TEACHER_BONUS = 150\n"
    "  const PHYSICAL_BONUS = 100  // 成果物ありなら追加\n"
    "  try {\n"
    "    await ensureHomeworkRewardTable(c.env)\n"
    "    const sub = await c.env.DB.prepare(`SELECT user_id FROM homework_submissions WHERE id=?`).bind(hwId).first<any>()\n"
    "    if (sub?.user_id) {\n"
    "      const bonusAmount = TEACHER_BONUS + (body.hasPhysical ? PHYSICAL_BONUS : 0)\n"
    "      // 1) 枠の確保（PRIMARY KEY 衝突＝すでに付与済み）\n"
    "      let reserved = false\n"
    "      try {\n"
    "        await c.env.DB.prepare(\n"
    "          \"INSERT INTO homework_rewards (submission_id, user_id, coins, teacher_id, created_at) VALUES (?, ?, ?, ?, datetime('now'))\"\n"
    "        ).bind(hwId, sub.user_id, bonusAmount, u.id).run()\n"
    "        reserved = true\n"
    "      } catch (_e) { reserved = false }\n"
    "      if (reserved) {\n"
    "        // 2) サーバー側でコインを加算＋累計台帳を増やす\n"
    "        let applied = false\n"
    "        try {\n"
    "          const prog = await c.env.DB.prepare(`SELECT state_json FROM progress WHERE user_id=?`).bind(sub.user_id).first<any>()\n"
    "          if (prog?.state_json) {\n"
    "            const state = JSON.parse(prog.state_json)\n"
    "            state.coins = (Number(state.coins) || 0) + bonusAmount\n"
    "            state._hwCoinsApplied = (Number(state._hwCoinsApplied) || 0) + bonusAmount\n"
    "            await c.env.DB.prepare(`UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?`).bind(JSON.stringify(state), sub.user_id).run()\n"
    "            applied = true\n"
    "          }\n"
    "        } catch (e) { console.error('teacher bonus apply error:', e) }\n"
    "        // 3) 加算できなかったら枠を解放（次回の返却でやり直せる）\n"
    "        if (!applied) {\n"
    "          try { await c.env.DB.prepare(`DELETE FROM homework_rewards WHERE submission_id=?`).bind(hwId).run() } catch (_e) {}\n"
    "        }\n"
    "      }\n"
    "    }\n"
    "  } catch (e) { console.error('teacher bonus error:', e) }\n"
    "  }\n"
)
sub('2a+2b homework return: homework_rewards で枠を確保してから付与', B_OLD, B_NEW)


# ────────────────────────────────────────────────────────────────
# Fix 2a : 台帳テーブルの用意（mi_* と同じ runtime CREATE TABLE IF NOT EXISTS）
#   既存テーブルへの破壊的変更はしない。isolate ごとに1回だけ実行して D1 の書き込みを増やさない。
# ────────────────────────────────────────────────────────────────
C_OLD = "app.post('/api/teacher/homework/:id/return', async (c) => {\n"
C_NEW = (
    "// 🧾 宿題の返却ボーナスの受け取り台帳。PRIMARY KEY(submission_id) で「同じ提出に2回目」が\n"
    "//    構造的に INSERT できないようにする（アプリ側の判定ミスでは二重付与できない）。\n"
    "//    mi_rewards(user_id, month_key) と同じ考え方。既存テーブルには一切手を触れない。\n"
    "let _hwRewardTableReady = false\n"
    "async function ensureHomeworkRewardTable(env: any) {\n"
    "  if (_hwRewardTableReady) return\n"
    "  try {\n"
    "    await env.DB.prepare(\"CREATE TABLE IF NOT EXISTS homework_rewards (submission_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, coins INTEGER NOT NULL DEFAULT 0, teacher_id TEXT, created_at TEXT)\").run()\n"
    "    _hwRewardTableReady = true\n"
    "  } catch (_e) {}\n"
    "}\n"
    "\n"
) + C_OLD
sub('2a homework_rewards テーブルの用意', C_OLD, C_NEW)


# ────────────────────────────────────────────────────────────────
# Fix 1b : sticker.js（STICKER_JS 文字列）— 購入直後にサーバの支払い台帳を端末へ写す
#   連絡帳コインで player._contactCoinsApplied を写しているのとまったく同じ作法。
#   これが無いと Fix 1a が購入直後の端末を「まだ引かれていない」と誤認して二重に引く。
#   ※ STICKER_JS は TS のダブルクォート文字列。挿入する JS にダブルクォートと
#     バックスラッシュを使わないこと（\\n は文字列内の改行エスケープとしてそのまま置く）。
# ────────────────────────────────────────────────────────────────
D_OLD = r"if(res && res.ok){\n        applyCoins(Number(res.coins));\n"
D_NEW = (
    r"if(res && res.ok){\n        applyCoins(Number(res.coins));\n"
    r"        /* 🧾 サーバの支払い台帳をこの端末にも写す。これが無いと PUT /api/student/progress の"
    r" 照合が「まだ引かれていない端末」と誤認して同じ300コインを二重に引く。"
    r" 連絡帳コインで player._contactCoinsApplied を写しているのと同じ作法。 */\n"
    r"        try{ var _sp=curP(); if(_sp && typeof res.serverSpentCoins==='number') _sp._serverSpentCoins = res.serverSpentCoins; }catch(e){}\n"
)
sub('1b sticker.js: 購入直後に _serverSpentCoins を端末へ写す', D_OLD, D_NEW)


with open(TARGET, 'wb') as f:
    f.write(content.encode('utf-8'))

print('applied=%d skipped=%d  size %d -> %d' % (applied, skipped, before_len, len(content)), file=sys.stderr)

# 適用後の内容一致チェック（当てたつもりで当たっていない、を防ぐ）
verify = open(TARGET, 'rb').read().decode('utf-8')
must_have = [
    'const _srvSpent = Number(_srv._serverSpentCoins) || 0',
    'const _srvHw = Number(_srv._hwCoinsApplied) || 0',
    'async function ensureHomeworkRewardTable(env: any)',
    'INSERT INTO homework_rewards (submission_id, user_id, coins, teacher_id, created_at)',
    'state._hwCoinsApplied = (Number(state._hwCoinsApplied) || 0) + bonusAmount',
    '_sp._serverSpentCoins = res.serverSpentCoins',
]
# 既存の安全機構が生き残っているかの番人（回帰ガード・既存の台帳）
must_survive = [
    "destructive overwrite blocked",
    "skipped: 'regression_guard'",
    '_inc._contactCoinsApplied = _srvApplied',
    '_inc._miCoinsApplied = _srvMi',
    '_inc._rankShardsApplied = _srvRk',
    "app.get('/sticker.js'",
]
bad = [s for s in must_have if s not in verify] + [s for s in must_survive if s not in verify]
if bad:
    print('FAIL: verify missing -> %r' % bad, file=sys.stderr)
    sys.exit(1)
print('verify OK', file=sys.stderr)
