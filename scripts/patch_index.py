"""
index.html パッチスクリプト
GitHub Actions から自動実行される。
public/index.html に差分を適用してコミット可能な状態にする。

使い方: python3 scripts/patch_index.py
"""
import sys
import os

target = 'public/index.html'

with open(target, 'rb') as f:
    content = f.read().decode('utf-8')

orig_len = len(content)
print(f"Original size: {orig_len}", file=sys.stderr)

changes_applied = 0

# ================================================================
# ここより下に変更内容を追加する（Change 1, 2, 3 ... の形式で）
# ================================================================

# ── Change 1: 写真アップロード UI ────────────────────────────
photo_ui = '''
              <div id="hsPhotoSection" style="margin-top:6px; padding:6px 8px; background:#ecfeff; border:1.5px dashed #06b6d4; border-radius:10px;">
                <div style="font-size:11px; font-weight:bold; color:#0e7490; margin-bottom:4px;">📷 成果物の写真（任意）</div>
                <div style="display:flex; align-items:center; gap:6px; flex-wrap:wrap;">
                  <label style="cursor:pointer; background:#06b6d4; color:#fff; font-size:11px; font-weight:bold; padding:4px 10px; border-radius:8px; display:inline-block;">
                    写真をえらぶ
                    <input type="file" id="hsPhotoInput" accept="image/*" capture="environment" style="display:none;" onchange="hsPhotoSelected(this)"/>
                  </label>
                  <span id="hsPhotoStatus" style="font-size:10px; color:#64748b;"></span>
                </div>
                <div id="hsPhotoPreview" style="display:none; margin-top:6px; position:relative;">
                  <img id="hsPhotoThumb" style="max-width:120px; max-height:90px; border-radius:8px; border:1px solid #ccc;"/>
                  <button type="button" onclick="hsPhotoClear()" style="position:absolute; top:-6px; right:-6px; background:#ef4444; color:#fff; border:none; border-radius:50%; width:20px; height:20px; font-size:12px; cursor:pointer; line-height:1;">×</button>
                </div>
                <div id="hsPhotoAnalysis" style="display:none; margin-top:4px; font-size:10px; color:#0e7490; background:#fff; padding:4px 6px; border-radius:6px; border:1px solid #a5f3fc;"></div>
              </div>'''

search1 = '</textarea>\r\n              <div id="hsLockOverlay" class="hs-lock hidden">'
replace1 = '</textarea>' + photo_ui + '\r\n              <div id="hsLockOverlay" class="hs-lock hidden">'

if search1 in content:
    content = content.replace(search1, replace1, 1)
    print("Change 1 applied (photo UI)", file=sys.stderr)
    changes_applied += 1
else:
    print("SKIP: Change 1 anchor not found (already applied?)", file=sys.stderr)

# ── Change 2: JS 関数 ────────────────────────────────────────
photo_js = '''window._hsPhotoAnalysisResult = '';

function hsPhotoSelected(input) {
  const file = input.files[0];
  if (!file) return;
  const statusEl = document.getElementById('hsPhotoStatus');
  const previewEl = document.getElementById('hsPhotoPreview');
  const thumbEl  = document.getElementById('hsPhotoThumb');
  const analysisEl = document.getElementById('hsPhotoAnalysis');
  if (file.size > 5 * 1024 * 1024) {
    if (statusEl) statusEl.textContent = '⚠️ 5MB以下の写真を選んでください';
    input.value = ''; return;
  }
  if (statusEl) statusEl.textContent = file.name.slice(0,20) + ' (' + (file.size/1024).toFixed(0) + 'KB)';
  const reader = new FileReader();
  reader.onload = e => {
    if (thumbEl) { thumbEl.src = e.target.result; }
    if (previewEl) { previewEl.style.display = 'block'; }
  };
  reader.readAsDataURL(file);
  if (statusEl) statusEl.textContent += ' 🔍分析中...';
  if (analysisEl) { analysisEl.style.display = 'none'; analysisEl.textContent = ''; }
  window._hsPhotoAnalysisResult = '';
  (async () => {
    try {
      const dayKey = hsGetDayKey830(new Date());
      const fd = new FormData();
      fd.append('dayKey', dayKey);
      fd.append('photo', file);
      const res = await fetch('/api/homework/analyze-photo', { method: 'POST', body: fd });
      if (res.ok) {
        const data = await res.json();
        window._hsPhotoAnalysisResult = data.analysis || '';
        if (analysisEl && data.analysis) { analysisEl.textContent = '📝 ' + data.analysis; analysisEl.style.display = 'block'; }
        if (statusEl) statusEl.textContent = file.name.slice(0,20) + ' ✅';
      } else {
        if (statusEl) statusEl.textContent = file.name.slice(0,20) + ' (分析スキップ)';
      }
    } catch(e) {
      if (statusEl) statusEl.textContent = file.name.slice(0,20) + ' (分析エラー)';
    }
  })();
}

function hsPhotoClear() {
  const input = document.getElementById('hsPhotoInput');
  const statusEl = document.getElementById('hsPhotoStatus');
  const previewEl = document.getElementById('hsPhotoPreview');
  const analysisEl = document.getElementById('hsPhotoAnalysis');
  if (input) input.value = '';
  if (statusEl) statusEl.textContent = '';
  if (previewEl) previewEl.style.display = 'none';
  if (analysisEl) { analysisEl.style.display = 'none'; analysisEl.textContent = ''; }
  window._hsPhotoAnalysisResult = '';
}

'''

search2 = '\r\nasync function hsSubmitAndExport(){'
replace2 = '\r\n' + photo_js + 'async function hsSubmitAndExport(){'

if search2 in content:
    content = content.replace(search2, replace2, 1)
    print("Change 2 applied (JS functions)", file=sys.stderr)
    changes_applied += 1
else:
    print("SKIP: Change 2 anchor not found (already applied?)", file=sys.stderr)

# ── Change 3: submit ペイロードに workPhotoAnalysis を追加 ───
search3 = '        bonusCoins: bonus.coins || 0, bonusShards: bonus.shards || 0,\r\n      };'
replace3 = '        bonusCoins: bonus.coins || 0, bonusShards: bonus.shards || 0,\r\n        workPhotoAnalysis: window._hsPhotoAnalysisResult || \'\',\r\n      };'

if search3 in content:
    content = content.replace(search3, replace3, 1)
    print("Change 3 applied (workPhotoAnalysis payload)", file=sys.stderr)
    changes_applied += 1
else:
    print("SKIP: Change 3 anchor not found (already applied?)", file=sys.stderr)

# ── Change 3b: 提出成功後に写真をクリア ──────────────────────
search3b = '      entry.dbSubmitted = true;\r\n      try { entry.dbId = r.id || null; } catch(e) {}'
replace3b = '      entry.dbSubmitted = true;\r\n      try { entry.dbId = r.id || null; } catch(e) {}\r\n      hsPhotoClear();'

if search3b in content:
    content = content.replace(search3b, replace3b, 1)
    print("Change 3b applied (hsPhotoClear after submit)", file=sys.stderr)
    changes_applied += 1
else:
    print("SKIP: Change 3b anchor not found (already applied?)", file=sys.stderr)

# ── Change 4: PB(_gcFight) hash undefined fix + deterministic seed ──
pb_hash_marker = '/*__PB_HASH_FIX__*/'
pb_hash_fn = pb_hash_marker + 'function _hash(s){s=String(s==null?"":s);var h=2166136261>>>0;for(var i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619);}return h>>>0;}'
pb_anchor = 'function _gcFight(){'
if pb_hash_marker not in content and pb_anchor in content:
    content = content.replace(pb_anchor, pb_hash_fn + pb_anchor, 1)
    print("Change 4a applied (global _hash before _gcFight)", file=sys.stderr)
    changes_applied += 1
else:
    print("SKIP: Change 4a (marker present or anchor not found)", file=sys.stderr)

pb_seed_old = 'var _seed=(((Date.now()>>>0)^0x9e3779b9)>>>0); var _erng=_abRng((_seed^0x9a3b)>>>0);'
pb_seed_new = 'var _seed=((_hash(String(_gcGid))^0x9e3779b9)>>>0); var _erng=_abRng((_seed^0x9a3b)>>>0);'
if pb_seed_old in content:
    content = content.replace(pb_seed_old, pb_seed_new, 1)
    print("Change 4b applied (deterministic PB seed)", file=sys.stderr)
    changes_applied += 1
else:
    print("SKIP: Change 4b (seed anchor not found / already applied)", file=sys.stderr)

# ================================================================

print(f"Changes applied: {changes_applied}", file=sys.stderr)
print(f"New size: {len(content)} (delta: +{len(content) - orig_len} bytes)", file=sys.stderr)

if changes_applied == 0:
    print("No changes needed. Exiting.", file=sys.stderr)
    sys.exit(0)

with open(target, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"Written to {target}", file=sys.stderr)
