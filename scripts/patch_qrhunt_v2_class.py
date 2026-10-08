# -*- coding: utf-8 -*-
"""
QRHUNT_V2_CLASS — 「クラスをえらんでください」で行き止まりになるのを直す。

何が起きていたか（2026-10-08 先生の報告・本番で確認）:
  QR欄は、クラス共同ミッションのカードにある選択欄 cmClassFilter を
  借りていた。片づけ便でそのカードが折りたたみの中に入り、
  先生からは「どこで選ぶのか」が分からなくなった。
  その結果ずっと「クラスをえらんでください」のまま、
  枚数も期間も「作る」ボタンも出ない行き止まりになっていた。

直しかた（他の便を巻き込まない最小の形）:
  ・QR欄の中に、自前のクラス選択 <select id="qrClassFilter"> を置く
  ・/api/teacher/classes から自分で取る（他カードに依存しない）
  ・クラスが1つなら自動で選ぶ。2つ以上でも先頭を既定にする
    → 「作る」フォームが必ず出る。行き止まりを作らない
  ・選び直したら その場で一覧を読み直す

※ チェーン（配信の t.replace）には1本も触らない。増減ゼロ。
※ public/index.html にも触らない。
"""
import io, os, sys

SRC = 'src/index.tsx'

def chain_count(t):
    i = t.index("app.get('/', async (c) => {")
    j = t.index("app.get('/logout'", i)
    return t[i:j].count('.replace(')

s = io.open(SRC, encoding='utf-8').read()
orig = len(s)

if 'QRHUNT_V2_CLASS' in s:
    print('NG: すでに当たっています'); sys.exit(1)

_raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
_before = chain_count(s)
if _raw:
    if not _raw.isdigit():
        print('NG: CHAIN_BEFORE が数字でない: %r' % _raw); sys.exit(1)
    print('チェーン = %d （渡された値 = %s）' % (_before, _raw))
    if _before != int(_raw):
        print('NG: チェーンが %d 件。渡された %s と合わないので止めます。' % (_before, _raw)); sys.exit(1)
else:
    print('チェーン = %d （CHAIN_BEFORE 未指定）' % _before)

def sub(name, old, new):
    global s
    n = s.count(old)
    if n != 1:
        print('  !! %-22s 見つかった数=%d (期待=1) → 中止' % (name, n)); sys.exit(1)
    s = s.replace(old, new, 1)
    print('  ok %s' % name)


# ── ① 自前のクラス選択を持つ。cmClassFilter には頼らない ──
sub('C1 loadQrHunts',
"""async function loadQrHunts(){
        var box = document.getElementById('qrHuntBox'); if(!box) return;
        var sel = document.getElementById('cmClassFilter');
        var classId = sel ? sel.value : '';
        if(!classId){ box.innerHTML = '<span class="text-slate-400">クラスをえらんでください</span>'; return; }
        try{""",
"""/* QRHUNT_V2_CLASS: QR欄の中で完結させる。
         もとは別カードの cmClassFilter を借りていたが、片づけ便でその
         カードが折りたたみに入り「どこで選ぶのか」が分からなくなった。
         ここで自分のクラス一覧を持ち、必ず「作る」まで出す。 */
      var __qrClasses = null;      // [{id,name}] 一度だけ取る
      var __qrClassId  = '';       // いま選んでいるクラス

      async function qrLoadClasses(){
        if(__qrClasses) return __qrClasses;
        try{
          var j = await fetch('/api/teacher/classes').then(function(r){return r.json();});
          __qrClasses = (j && j.classes) || [];
        }catch(e){ __qrClasses = []; }
        return __qrClasses;
      }

      function qrClassId(){
        var mine = document.getElementById('qrClassFilter');
        if(mine && mine.value) return mine.value;
        if(__qrClassId) return __qrClassId;
        var cm = document.getElementById('cmClassFilter');   // 昔のカードが在れば参考にする
        return cm ? cm.value : '';
      }

      window.onQrClassChange = function(v){ __qrClassId = v; loadQrHunts(); };

      function qrClassPicker(){
        var cs = __qrClasses || [];
        if(!cs.length){
          return '<p class="text-xs text-red-600 mb-2">クラスが見つかりませんでした。先に「クラス・名簿」でクラスを作ってください。</p>';
        }
        var h = '<div class="flex items-center gap-2 mb-3">'
          + '<label class="text-xs font-bold text-gray-600 whitespace-nowrap">どのクラス</label>'
          + '<select id="qrClassFilter" class="border p-2 rounded text-sm bg-white flex-1" onchange="onQrClassChange(this.value)">';
        for(var i=0;i<cs.length;i++){
          h += '<option value="' + qrEsc(cs[i].id) + '"' + (cs[i].id===__qrClassId ? ' selected' : '') + '>' + qrEsc(cs[i].name) + '</option>';
        }
        return h + '</select></div>';
      }

      async function loadQrHunts(){
        var box = document.getElementById('qrHuntBox'); if(!box) return;
        await qrLoadClasses();
        /* クラスを選ばせて止めない。1つなら自動、2つ以上でも先頭を既定にする。
           先生はプルダウンで選び直せる。 */
        if(!__qrClassId){
          var cm = document.getElementById('cmClassFilter');
          if(cm && cm.value) __qrClassId = cm.value;
          else if(__qrClasses.length) __qrClassId = __qrClasses[0].id;
        }
        var classId = __qrClassId;
        if(!classId){ box.innerHTML = qrClassPicker(); return; }
        try{""")

# ② 一覧の先頭にクラス選択を差し込む
sub('C2 picker in html',
"""          var hs = (j && j.hunts) || [];
          var html = '';
          if(!hs.length){""",
"""          var hs = (j && j.hunts) || [];
          var html = qrClassPicker();   // QRHUNT_V2_CLASS: 欄の中で選べるようにする
          if(!hs.length){""")

# ③ 読みこみ失敗時もクラス選択は残す
sub('C3 error keeps picker',
"""        }catch(e){ box.innerHTML = '<span class="text-red-600">よみこみに失敗しました</span>'; }
      }

      async function createQrHunt(){
        var sel = document.getElementById('cmClassFilter');
        var msg = document.getElementById('qrNewMsg');
        var classId = sel ? sel.value : '';
        if(!classId){ msg.textContent = 'クラスをえらんでください'; return; }""",
"""        }catch(e){ box.innerHTML = qrClassPicker() + '<span class="text-red-600">よみこみに失敗しました</span>'; }
      }

      async function createQrHunt(){
        var msg = document.getElementById('qrNewMsg');
        var classId = qrClassId();   // QRHUNT_V2_CLASS
        if(!classId){ msg.textContent = 'クラスが見つかりませんでした'; return; }""")

_after = chain_count(s)
print('\\n適用後のチェーン = %d （%d のまま であること）' % (_after, _before))
if _after != _before:
    print('NG: チェーンが変わりました（%d -> %d）。書き込まずに止めます。' % (_before, _after)); sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('完了: %d → %d bytes' % (orig, len(s)))
