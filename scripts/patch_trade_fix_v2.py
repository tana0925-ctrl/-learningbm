#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_trade_fix_v2.py   ---  友達交換の3点修正（TRADE_FIX_V2）

① 失敗理由を子どもの画面に出す
   サーバは理由を返している（例 {"ok":false,"error":"cannot_trade_special"} / 400）。
   apiJson() はそれを Error.message に載せて throw している。ところが交換画面の catch は
   e を見ずに固定文（「⚠️ エラーが発生しました」等）を出すだけで理由を捨てていた。

② キャラの絵が ❓ になるのを直す
   絵を m.emoji で読んでいるが、キャラのデータは sprite で持っている。
   過去の交換記録90件すべてが "emoji":"❓" だった。
   → _tradeEmoji() で sprite / emoji の両方を見る。さらに、サーバに保存済みの
     古い記録（❓ のまま）でも、id から手元のキャラ表を引いて絵を出しなおす。

③ 成功しても「失敗しました」と出るのを直す
   交換成立後の loadData() / 画面更新が同じ try の中にあり、そこで転ぶと
   「⚠️ 交換に失敗しました」が出ていた（中身は交換済み）。
   → 成立後の処理を内側の try で包み、外側の catch は通信の失敗だけを受ける。

やらないこと:
   - サーバ側のロジック・交換禁止リストは一切変更しない（対象キャラの決定に先生の判断が要る）。
   - public/index.html は手で編集しない。src/index.tsx の「/」ルートの replace チェーンに
     追記するだけ（既存のチェーン行には触らない）。

注意（2026-09-25 の教師ダッシュボード事故の教訓）:
   - テンプレートリテラル内の onclick で \\' を1段だけ使わない。この修正では onclick を
     一切追加しないが、生成する文字列に ' を素で入れないよう &#39; 方針を守っている。
   - 適用後は「配信された実物のHTML」を取得して構文チェックすること。

適用対象: src/index.tsx のみ
使い方:
   python3 scripts/patch_trade_fix_v2.py --check   # 当たるかだけ確認（無変更）
   python3 scripts/patch_trade_fix_v2.py           # 適用
"""

import json
import os
import re
import sys

SRC      = os.path.join("src", "index.tsx")
HTML     = os.path.join("public", "index.html")
SENTINEL = "__TRADE_FIX_V2__"
ANCHOR   = "      // __IDFIX_V1__"      # このチェーン行の直前に差し込む

# ============================================================ helpers (JS)
HELPERS_JS = r"""// __TRADE_FIX_V2__ 交換画面の共通ヘルパー（失敗理由の日本語化・キャラの絵の解決）
// サーバが返す error コードを子ども向けの日本語にする。
// 理由が画面に出ないと、子どもには「交換がこわれている」としか伝わらない。
function _tradeErrJa(e){
  var c = (e && e.message) ? String(e.message) : '';
  var M = {
    cannot_trade_special: 'このキャラは交換できない決まりです（イベントや特別なキャラ）。ほかのキャラをえらんでね。',
    offer_not_found: 'そのコードは見つかりません。うち間違いか、24時間の期限切れかもしれません。',
    cannot_trade_with_yourself: '自分のコードとは交換できません。相手のコードを入れてね。',
    from_monster_not_in_box: '相手のキャラがボックスに見つかりません。相手にコードを出しなおしてもらってね。',
    to_monster_not_in_box: 'えらんだキャラがボックスに見つかりません。画面を読みこみなおしてね。',
    from_box_invalid: 'ボックスのデータが読めませんでした。先生に知らせてね。',
    to_box_invalid: 'ボックスのデータが読めませんでした。先生に知らせてね。',
    monster_required: '渡すキャラがえらばれていません。',
    code_and_monster_required: 'コードとキャラの両方をえらんでね。',
    unauthorized: 'ログインが切れています。もう一度ログインしてね。',
    state_parse_error: 'データの読みこみに失敗しました。先生に知らせてね。',
    from_user_progress_not_found: '相手のデータが見つかりません。先生に知らせてね。',
    to_user_progress_not_found: '自分のデータが見つかりません。先生に知らせてね。'
  };
  if (M[c]) return M[c];
  if (c.indexOf('HTTP_') === 0) return 'つながりませんでした（' + c + '）。電波をたしかめて、もう一度ためしてね。';
  return 'うまくいきませんでした' + (c ? '（' + c + '）' : '') + '。もう一度ためしてね。';
}
// キャラの絵を出す。キャラ表は sprite で持っているのに emoji で読んでいたため ❓ になっていた。
// x はキャラ表の1件でも、交換APIのやりとり用オブジェクトでもよい。
// サーバに ❓ で保存されてしまった古い記録でも、id から引きなおして絵を出す。
function _tradeEmoji(x){
  if (!x) return '❓';
  var e = x.sprite || x.emoji;
  if (e && e !== '❓') return e;
  try {
    var id = Number(x.monsterId != null ? x.monsterId : x.id);
    if (isFinite(id) && typeof getMonster === 'function') {
      var m = getMonster(id);
      // getMonster は見つからないと先頭のキャラを返すので、別のキャラを出さないよう id を照合する
      if (m && Number(m.id) === id) return m.sprite || m.emoji || '❓';
    }
  } catch (_e) {}
  return '❓';
}
"""

# ============================================================ chain steps
# kind: 'str' = JS の String.replace（先頭1件のみ）／'rx' = 正規表現 /g
# (kind, old, new, 期待ヒット数)
STEPS = []

# ---------------------------------------------------------------- 0) ヘルパー挿入
STEPS.append(('str',
    "// ── モンスター交換（合言葉方式） ────────────────────────",
    HELPERS_JS + "// ── モンスター交換（合言葉方式） ────────────────────────",
    1))

# ---------------------------------------------------------------- ③ 成立後の処理を切り離す
# ページ版
STEPS.append(('str',
    """    if (!res.ok) throw new Error('api error');
    await loadData();
    var resultEl = document.getElementById('tradeLookupResultPage');
    if (resultEl) resultEl.innerHTML = '<div class="text-sm font-bold text-emerald-700 text-center py-2">✅ 交換完了！<br>' + res.fromUserName + ' さんと交換しました！<br>' + (res.received.emoji||'❓') + ' ' + res.received.name + ' Lv.' + res.received.level + ' をゲット！</div>';
    _tradeSelectedUid = null;
    renderTradeBox();""",
    """    if (!res.ok) throw new Error('api error');
    // __TRADE_FIX_V2__ ここを過ぎたら交換はサーバで成立している。
    // 以降の失敗を外側の catch に落とすと「成功したのに失敗しました」と出るので内側で受ける。
    try { await loadData(); } catch(_e){ try{ console.warn('[trade] loadData after success:', _e); }catch(_x){} }
    try {
      var resultEl = document.getElementById('tradeLookupResultPage');
      if (resultEl) {
        var _rc = res.received || {};
        resultEl.innerHTML = '<div class="text-sm font-bold text-emerald-700 text-center py-2">✅ 交換完了！<br>' + (res.fromUserName || 'ともだち') + ' さんと交換しました！<br>' + _tradeEmoji(_rc) + ' ' + (_rc.name || 'キャラ') + ' Lv.' + (_rc.level || 1) + ' をゲット！</div>';
      }
      var _msgOk = document.getElementById('tradeMsgPage');
      if (_msgOk) { _msgOk.textContent = ''; }
      _tradeSelectedUid = null;
      renderTradeBox();
    } catch(_e){
      try{ console.warn('[trade] refresh after success:', _e); }catch(_x){}
      var _el2 = document.getElementById('tradeLookupResultPage');
      if (_el2) _el2.innerHTML = '<div class="text-sm font-bold text-emerald-700 text-center py-2">✅ 交換できました！画面を読みこみなおしてね。</div>';
    }""",
    1))

# モーダル版
STEPS.append(('str',
    """    if (!res.ok) throw new Error('api error');
    // ローカルstateを最新に更新
    await loadData();
    const resultEl = document.getElementById('tradeLookupResult');
    if (resultEl) resultEl.innerHTML = `<div class="text-sm font-bold text-emerald-700 text-center py-2">✅ 交換完了！<br>${res.fromUserName} さんと交換しました！<br>${res.received.emoji||'❓'} ${res.received.name} Lv.${res.received.level} をゲット！</div>`;
    if (msgEl) { msgEl.textContent = ''; }""",
    """    if (!res.ok) throw new Error('api error');
    // __TRADE_FIX_V2__ ここを過ぎたら交換はサーバで成立している（内側で受ける）。
    try { await loadData(); } catch(_e){ try{ console.warn('[trade] loadData after success:', _e); }catch(_x){} }
    try {
      const resultEl = document.getElementById('tradeLookupResult');
      if (resultEl) {
        const _rc = res.received || {};
        resultEl.innerHTML = `<div class="text-sm font-bold text-emerald-700 text-center py-2">✅ 交換完了！<br>${res.fromUserName || 'ともだち'} さんと交換しました！<br>${_tradeEmoji(_rc)} ${_rc.name || 'キャラ'} Lv.${_rc.level || 1} をゲット！</div>`;
      }
      if (msgEl) { msgEl.textContent = ''; }
    } catch(_e){
      try{ console.warn('[trade] refresh after success:', _e); }catch(_x){}
      const _el2 = document.getElementById('tradeLookupResult');
      if (_el2) _el2.innerHTML = `<div class="text-sm font-bold text-emerald-700 text-center py-2">✅ 交換できました！画面を読みこみなおしてね。</div>`;
    }""",
    1))

# ---------------------------------------------------------------- ① 失敗理由を出す
# ページ版 issueTradeCodePage の catch
STEPS.append(('str',
    "    if (msg) { msg.textContent = '⚠️ エラーが発生しました'; msg.className = 'text-xs text-center font-bold text-rose-600 mb-2'; }",
    "    if (msg) { msg.textContent = '⚠️ ' + _tradeErrJa(e); msg.className = 'text-xs text-center font-bold text-rose-600 mb-2'; }",
    1))
# ページ版 completeTradeExchangePage の catch
STEPS.append(('str',
    "    if (msg) { msg.textContent = '⚠️ 交換に失敗しました'; msg.className = 'text-xs text-center font-bold text-rose-600 mb-2'; }",
    "    if (msg) { msg.textContent = '⚠️ ' + _tradeErrJa(e); msg.className = 'text-xs text-center font-bold text-rose-600 mb-2'; }",
    1))
# ページ版 lookupTradeCodePage の catch
STEPS.append(('str',
    """    resultEl.innerHTML = '<div class="text-xs text-rose-600 font-bold">⚠️ コードが見つかりません</div>';""",
    """    resultEl.innerHTML = '<div class="text-xs text-rose-600 font-bold">⚠️ ' + _tradeErrJa(e) + '</div>';""",
    1))
# モーダル版 lookupTradeCode の catch
STEPS.append(('str',
    """    resultEl.innerHTML = '<div class="text-xs text-rose-600 font-bold">⚠️ コードが見つかりません。有効期限切れか間違いがあります。</div>';""",
    """    resultEl.innerHTML = '<div class="text-xs text-rose-600 font-bold">⚠️ ' + _tradeErrJa(e) + '</div>';""",
    1))
# モーダル版 completeTradeExchange の catch
STEPS.append(('str',
    "    if (msgEl) { msgEl.textContent = '⚠️ 交換に失敗しました。再度お試しください。'; msgEl.className = 'text-xs text-center font-bold text-rose-600 mt-1'; }",
    "    if (msgEl) { msgEl.textContent = '⚠️ ' + _tradeErrJa(e); msgEl.className = 'text-xs text-center font-bold text-rose-600 mt-1'; }",
    1))
# モーダル版 issueTradeCode / issueTradeCodeFromAccept の catch（同一文字列が2か所 → /g）
STEPS.append(('rx',
    r"if \(msg\) \{ msg\.textContent = '⚠️ エラーが発生しました'; msg\.className = 'text-xs text-center font-bold text-rose-600 mt-1'; \}",
    "if (msg) { msg.textContent = '⚠️ ' + _tradeErrJa(e); msg.className = 'text-xs text-center font-bold text-rose-600 mt-1'; }",
    2))

# ---------------------------------------------------------------- ② 絵が ❓ になるのを直す
# 送信するやりとり用オブジェクト（3種の書き方）
STEPS.append(('str',
    "      name: m ? m.name : '？', emoji: m ? (m.emoji||'❓') : '❓',",
    "      name: m ? m.name : '？', emoji: _tradeEmoji(m),",
    1))
STEPS.append(('str',
    "name: m?m.name:'？', emoji: m?(m.emoji||'❓'):'❓',",
    "name: m?m.name:'？', emoji: _tradeEmoji(m),",
    1))
STEPS.append(('str',
    "name:m?m.name:'？', emoji:m?(m.emoji||'❓'):'❓',",
    "name:m?m.name:'？', emoji:_tradeEmoji(m),",
    1))
STEPS.append(('rx',
    r"emoji: m \? \(m\.emoji \|\| '❓'\) : '❓',",
    "emoji: _tradeEmoji(m),",
    2))
# 選択中のキャラの表示
STEPS.append(('str',
    """display.innerHTML = '<div class="text-3xl">' + (m.emoji||'❓') + '</div>""",
    """display.innerHTML = '<div class="text-3xl">' + _tradeEmoji(m) + '</div>""",
    1))
# 自分のキャラをえらぶ一覧（文字列連結版・テンプレート版）
STEPS.append(('str',
    """selectHtml += '<option value="' + e.uid + '">' + (mm.emoji||'❓') + ' '""",
    """selectHtml += '<option value="' + e.uid + '">' + _tradeEmoji(mm) + ' '""",
    1))
STEPS.append(('str',
    """selectHtml += `<option value="${e.uid}">${mm.emoji||'❓'}""",
    """selectHtml += `<option value="${e.uid}">${_tradeEmoji(mm)}""",
    1))
# 相手のキャラの表示（文字列連結版・テンプレート版）
STEPS.append(('str',
    """'<div class="flex items-center gap-2"><span class="text-3xl">' + (offer.fromMonster.emoji||'❓') + '</span>""",
    """'<div class="flex items-center gap-2"><span class="text-3xl">' + _tradeEmoji(offer.fromMonster) + '</span>""",
    1))
STEPS.append(('str',
    """<span class="text-3xl">${offer.fromMonster.emoji||'❓'}</span>""",
    """<span class="text-3xl">${_tradeEmoji(offer.fromMonster)}</span>""",
    1))
# コード発行モーダルの大きな絵
STEPS.append(('str',
    """      <div class="text-4xl">${m.emoji || '❓'}</div>""",
    """      <div class="text-4xl">${_tradeEmoji(m)}</div>""",
    1))


# ============================================================ verify / simulate
def simulate(html, verbose=False):
    """本番の「/」ルートと同じ順・同じ意味で当てて、結果とヒット数を返す。"""
    counts = []
    for i, (kind, old, new, want) in enumerate(STEPS):
        if kind == 'str':
            n = html.count(old)
            html = html.replace(old, new, 1)        # JS の String.replace と同じ（先頭1件）
            got = 1 if n >= 1 else 0
        else:
            got = len(re.findall(old, html))
            html = re.sub(old, new.replace('\\', '\\\\'), html)
        counts.append((i, kind, got, want, got == want))
        if verbose:
            mark = 'OK ' if got == want else 'NG '
            print(f"  {mark}[{i:2d}] {kind}  ヒット {got}/{want}  {old[:58]!r}")
    return html, counts


def emit_chain():
    lines = ["      // __TRADE_FIX_V2__ 交換の3点修正（理由表示・絵の❓・成功後の誤表示）既存チェーン行は非接触・追記のみ"]
    for kind, old, new, _want in STEPS:
        if kind == 'str':
            lines.append(f"      t = t.replace({json.dumps(old, ensure_ascii=False)}, {json.dumps(new, ensure_ascii=False)})")
        else:
            lines.append(f"      t = t.replace(new RegExp({json.dumps(old, ensure_ascii=False)}, 'g'), {json.dumps(new, ensure_ascii=False)})")
    return "\n".join(lines) + "\n"


def preflight_delivered(html_after):
    """⚠ 2026-09-25 の教師ダッシュボード事故の教訓:
    「ソースが正しい」は「配信物が正しい」を意味しない。
    そこで、自分の19ステップを当てた“配信後の姿”を作り、
    その中の <script> を実際に node --check にかける。ここで落ちたら push しない。"""
    import subprocess, tempfile, shutil
    if not shutil.which("node"):
        print("  [警告] node が無いため配信物の構文チェックをスキップしました")
        return True
    blocks = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>', html_after)
    bad = []
    with tempfile.TemporaryDirectory() as d:
        for j, b in enumerate(blocks):
            f = os.path.join(d, "b.js")
            open(f, "w", encoding="utf-8").write(b)
            r = subprocess.run(["node", "--check", f], capture_output=True, text=True)
            if r.returncode != 0:
                bad.append((j, (r.stderr.strip().split("\n") or [""])[-1][:200]))
    print(f"  配信後の <script> {len(blocks)} 個を構文チェック → " + ("エラーなし" if not bad else f"エラー {len(bad)} 件"))
    for j, e in bad[:5]:
        print(f"    ブロック{j}: {e}")
    if bad:
        print("::error::配信後のJSが壊れます。中止します。")
        return False

    # ⚠ 事故の直接原因は「配信後のJSが SyntaxError」だった。それは上の node --check が直接見ている。
    # 加えて、この修正が onclick を1つも新設していないことを確かめる（新設しなければ同種の事故は起こらない）。
    added = "".join(new for _k, _o, new, _w in STEPS)
    n_onclick = added.count("onclick")
    print(f"  この修正が追加する onclick の数: {n_onclick}（0 なら同種の事故は起こらない）")
    if n_onclick:
        print("::error::onclick を追加しています。エスケープ段数を見直してください。")
        return False
    # 追加テキストに素の ' を HTML 属性として埋めていないことも確認
    if re.search(r'=\s*\\?\'[^\']*\\\'', added):
        print("  [注意] 追加テキストに入れ子のクォートがあります。目視確認してください。")
    return True


def main():
    check_only = "--check" in sys.argv
    for p in (SRC, HTML):
        if not os.path.exists(p):
            sys.exit(f"見つかりません: {p}（リポジトリのルートで実行してください）")

    html = open(HTML, encoding="utf-8").read()
    src  = open(SRC,  encoding="utf-8").read()

    if SENTINEL in src:
        print("すでに適用済み（sentinel あり）。何もしません。")
        return

    # チェーン総数の実測。CHAIN_BEFORE が渡されていれば一致を必須にする（fail-closed）。
    a = src.index("app.get('/'"); b = src.index("app.get('/logout'")
    chain = src[a:b].count(".replace(")
    print(f"チェーン実測（app.get('/')〜app.get('/logout') の .replace( 総数）= {chain}")
    want = os.environ.get("CHAIN_BEFORE", "").strip()
    if want:
        if str(chain) != want:
            print(f"::error::チェーン数が合いません（実測 {chain} / 指定 {want}）。ほかの配信と競合している可能性があります。中止します。")
            sys.exit(1)
        print(f"  CHAIN_BEFORE={want} と一致")

    print(f"アンカー照合（{len(STEPS)} ステップ）:")
    html_after, counts = simulate(html, verbose=True)
    ng = [c for c in counts if not c[4]]
    if ng:
        print("\nヒット数が期待と違います。中止します:")
        for i, kind, got, want, _ in ng:
            print(f"  [{i}] {kind} ヒット {got} / 期待 {want}")
        sys.exit(1)
    print(f"→ 全 {len(STEPS)} ステップ、期待どおり一致")

    print("配信物の事前チェック:")
    if not preflight_delivered(html_after):
        sys.exit(1)

    if ANCHOR not in src:
        sys.exit(f"チェーンの挿入位置が見つかりません: {ANCHOR!r}")

    block = emit_chain()
    if check_only:
        print(f"\n--check なので {SRC} は書きかえません。追記予定 {len(STEPS)+1} 行。")
        return

    src = src.replace(ANCHOR, block + ANCHOR, 1)
    open(SRC, "w", encoding="utf-8").write(src)
    a = src.index("app.get('/'"); b = src.index("app.get('/logout'")
    print(f"{SRC} に {len(STEPS)+1} 行を追記しました（既存行は非接触）")
    print(f"適用後のチェーン実測 = {src[a:b].count('.replace(')}")


if __name__ == "__main__":
    main()
