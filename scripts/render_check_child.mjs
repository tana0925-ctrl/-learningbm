// 児童ページ（/）の配信HTMLの中のJSを、ビルド後・コミット前に構文チェックする。
// render_check.mjs は教師画面などしか見ていなかったので、児童ページ用を別に用意した。
// public/index.html をさわる便は、必ずこれを通すこと。
//
// 注意: 児童ページは public/index.html を ASSETS から読んで、
//       そこに src/index.tsx の .replace() チェーンをかけて作られる。
//       ASSETS を空にすると「中身ゼロのHTMLで全部合格」になってしまうので、
//       本物の public/index.html を返すようにしてある。
import fs from 'fs';
import { execFileSync } from 'child_process';

const mod = await import(process.cwd() + '/dist/_worker.js');
const env = {
  ASSETS: {
    fetch: async (req) => {
      const u = new URL(typeof req === 'string' ? req : req.url);
      const p = (!u.pathname || u.pathname === '/') ? '/index.html' : u.pathname;
      try {
        const buf = fs.readFileSync(process.cwd() + '/public' + p);
        return new Response(buf, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
      } catch (e) {
        return new Response('', { status: 404 });
      }
    }
  }
};
let bad = 0;

for (const path of ['/']) {
  const res = await mod.default.fetch(new Request('http://localhost' + path), env, { waitUntil() {} });
  const html = await res.text();
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m, i = 0, n = 0;
  while ((m = re.exec(html))) {
    i++;
    const attrs = m[1] || '';
    const body = m[2] || '';
    if (/\bsrc\s*=/.test(attrs)) continue;
    if (/type\s*=\s*["']?(application\/json|text\/template)/i.test(attrs)) continue;
    n++;
    const tmp = '/tmp/_rcc' + i + '.js';
    fs.writeFileSync(tmp, body);
    try {
      execFileSync('node', ['--check', tmp], { stdio: 'pipe' });
    } catch (e) {
      bad++;
      console.log('### SyntaxError ' + path + ' script#' + i);
      console.log(String(e.stderr || '').split('\n').slice(0, 6).join('\n'));
    }
  }
  console.log(path + ': HTML ' + html.length + ' バイト、script ' + n + ' 個を検査');
  // 中身が来ていないのに「検査0個で合格」にならないようにする
  if (html.length < 1000000) {
    console.log('### ' + path + ' のHTMLが小さすぎる（' + html.length + ' バイト）。チェーンが動いていないかもしれない。');
    bad++;
  }
  if (n < 20) {
    console.log('### ' + path + ' の script が ' + n + ' 個しかない。少なすぎる。');
    bad++;
  }
}

if (bad) {
  console.log('### NG ' + bad + ' 件');
  process.exit(1);
}
console.log('OK: 児童ページの配信JSに構文エラーなし');
