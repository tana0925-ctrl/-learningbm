// 配信されるHTMLの中のJSを、ビルド後・コミット前に構文チェックする。
// 2026-09-29: 教師画面の script が1つでも壊れると画面が丸ごと動かなくなるため
//   （9/26に2時間止まった原因）、パッチを流すたびにここで止める。
import fs from 'fs';
import { execFileSync } from 'child_process';

const mod = await import(process.cwd() + '/dist/_worker.js');
const env = { ASSETS: { fetch: async () => new Response('', { status: 404 }) } };
let bad = 0;
for (const path of ['/teacher', '/admin', '/login', '/teacher-recovery']) {
  const res = await mod.default.fetch(new Request('http://localhost' + path), env, { waitUntil() {} });
  const html = await res.text();
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m, i = 0, n = 0;
  while ((m = re.exec(html))) {
    i++;
    const attrs = m[1] || '', body = m[2] || '';
    if (/\bsrc\s*=/.test(attrs)) continue;
    if (/type\s*=\s*["']?(application\/json|text\/template)/i.test(attrs)) continue;
    n++;
    const tmp = '/tmp/_rc' + i + '.js';
    fs.writeFileSync(tmp, body);
    try { execFileSync('node', ['--check', tmp], { stdio: 'pipe' }); }
    catch (e) {
      bad++;
      console.log('### SyntaxError ' + path + ' script#' + i);
      console.log(String(e.stderr || '').split('\n').slice(0, 6).join('\n'));
    }
  }
  console.log(path + ': status ' + res.status + ', ' + html.length + ' chars, ' + n + ' inline scripts checked');
}
// public/ のそのまま配る JS も見る（teacher-ai.js など）
for (const f of ['teacher-ai.js', 'drillpark.js', 'teacher-preview.js', 'student-karte.js']) {
  const p = 'dist/' + f;
  if (!fs.existsSync(p)) continue;
  try { execFileSync('node', ['--check', p], { stdio: 'pipe' }); console.log(f + ': OK'); }
  catch (e) { bad++; console.log('### SyntaxError ' + f); console.log(String(e.stderr || '').split('\n').slice(0, 6).join('\n')); }
}
if (bad) { console.log('NG: ' + bad + ' script blocks have syntax errors'); process.exit(1); }
console.log('OK: all scripts parse');
