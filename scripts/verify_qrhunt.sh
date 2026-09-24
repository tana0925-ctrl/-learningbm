#!/usr/bin/env bash
# QRHUNT_V1 デプロイ直後の確認。
#
# ⚠️ ログインは一切しません。児童アカウントに触れず、HTTPで取得して中身を見るだけです。
#    （先生のブラウザには児童のセッションが残っていることがあるため）
#
# 使い方:  bash scripts/verify_qrhunt.sh
set -u
BASE="${1:-https://learning-bm.pages.dev}"
NG=0
ok(){ printf '  ✓ %s\n' "$1"; }
ng(){ printf '  ✗ %s\n' "$1"; NG=$((NG+1)); }

echo "═══ ① 配信された /login の JS が構文として通るか（最重要）═══"
curl -s "$BASE/login" -o /tmp/_login.html
node - <<'EOF' || NG=$((NG+1))
const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync('/tmp/_login.html','utf8');
const scripts=[...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
if(!scripts.length){ console.log('  ✗ インラインscriptが見つからない'); process.exit(1); }
let bad=null;
scripts.forEach(s=>{ try{ new vm.Script(s); }catch(e){ bad=e.message; } });
if(bad){ console.log('  ✗ 構文エラー: '+bad); console.log('  ⚠️ ログインボタンが動きません。ただちに戻してください。'); process.exit(1); }
console.log('  ✓ インラインscript '+scripts.length+'個すべて構文OK');
if(!/var _safeNext/.test(html)){ console.log('  ✗ next の仕組みが入っていない'); process.exit(1); }
console.log('  ✓ next の仕組みが入っている');
EOF

echo "═══ ② 配信HTMLに旧QRの読み取り入口が残っていないか ═══"
curl -s "$BASE/" -o /tmp/_root.html
for pat in 'jsQR(' 'cdn.jsdelivr.net/npm/jsqr' 'id="secretQrSection"' 'id="shop-qr-file-input"' 'char-restore-qr-file-input'; do
  n=$(grep -o -F "$pat" /tmp/_root.html | wc -l)
  [ "$n" -eq 0 ] && ok "$pat = 0件" || ng "$pat = ${n}件（残っている）"
done
n=$(grep -o -E 'getUserMedia|BarcodeDetector' /tmp/_root.html | wc -l)
[ "$n" -eq 0 ] && ok "カメラAPI = 0件" || ng "カメラAPI = ${n}件"
grep -q 'qrhunt.js' /tmp/_root.html && ok "qrhunt.js が読み込まれている" || ng "qrhunt.js が入っていない"
a=$(grep -o '<script' /tmp/_root.html | wc -l); b=$(grep -o '</script>' /tmp/_root.html | wc -l)
[ "$a" -eq "$b" ] && ok "<script>/</script> = $a/$b" || ng "<script>/</script> = $a/$b（不一致＝置換で壊れた）"

echo "═══ ③ 資産ルートが200で返るか（_routes.json 忘れの検出）═══"
for p in /qrhunt.js /qrgen.js; do
  c=$(curl -s -o /dev/null -w '%{http_code}' "$BASE$p")
  [ "$c" = "200" ] && ok "$p = 200" || ng "$p = $c"
done
# /teacher/qr-print は未ログインでも枠だけ返る（中身は /api/ 側で認証）
c=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/teacher/qr-print?hunt=x")
[ "$c" = "200" ] && ok "/teacher/qr-print = 200" || ng "/teacher/qr-print = $c"
# 未ログインで中身が漏れていないこと
c=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/teacher/qr-print-data?hunt=x")
[ "$c" = "401" ] && ok "/api/teacher/qr-print-data = 401（未ログインは弾く）" || ng "/api/teacher/qr-print-data = $c（401のはず）"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/qr/find/AAAAAAAA")
[ "$c" = "401" ] && ok "/api/qr/find = 401（未ログインは弾く）" || ng "/api/qr/find = $c（401のはず）"

echo "═══ ④ 既存ページが全部200か ═══"
for p in / /login /signup /recover /himitsu /teacher /teacher-signup; do
  c=$(curl -s -o /dev/null -w '%{http_code}' "$BASE$p")
  [ "$c" = "200" ] && ok "$p = 200" || ng "$p = $c"
done

echo
if [ "$NG" -eq 0 ]; then echo "═══ すべて通りました ═══"; exit 0
else echo "═══ ⚠️ ${NG}件 失敗。戻すことを検討してください ═══"; exit 1; fi
