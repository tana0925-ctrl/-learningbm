# -*- coding: utf-8 -*-
# DEFSTAGE_CHARS_V1（第3便・第2段：げんていキャラと結果画面）
#   1) public/defstage_monsters.js を読み込む1行を .replace チェーンに足す。
#      （キャラの中身はそのファイル側。public/index.html は手で編集しない）
#   2) public/defense2.js の結果画面に「ステージNクリア！つぎはステージN+1」と
#      もらったコイン・げんていキャラを出す。表示する値はサーバが返す stage_bonus だけ。
# 配布そのものは第1段（defense_stage_rewards 台帳）。ここは見た目だけで、
# コインもキャラも1つも動かさない。
# アンカーが一致しなければ何も書かずに止まる（fail-closed）。
import io
import sys

SRC = 'src/index.tsx'
D2 = 'public/defense2.js'
SENTINEL_SRC = '__DEFSTAGE_CHARS_V1__'
SENTINEL_D2 = 'DEFSTAGE_CHARS_V1'
CHAIN_BEFORE = 73
CHAIN_AFTER = 74


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def need(label, text, s, want):
    got = s.count(text)
    if got != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, got, want))
        sys.exit(1)


A_SRC = '''      t = t.replace('</body>', '<script src="/student-karte.js?v=1"></script></body>')
'''

N_SRC = A_SRC + '''      // 👾 __DEFSTAGE_CHARS_V1__ 防衛戦ステージ初クリアの げんていキャラ（4体）の名前とすがた。
      //    index.html は手で編集しない。中身は public/defstage_monsters.js。
      t = t.replace('</body>', '<script src="/defstage_monsters.js?v=1"></script></body>')
'''

A_D2 = '''      hero += '</div>';
'''

N_D2 = A_D2 + '''      /* DEFSTAGE_CHARS_V1 ステージ初クリアのごほうび。
         出すのは /api/defense/status が返した stage_bonus だけ。
         金額もキャラもサーバが決めた値で、ここでは1つも足さない。 */
      try {
        var _sb = st && st.stage_bonus;
        if (win && _sb && _sb.stage) {
          var _sbLines = '';
          if (_sb.coins > 0) {
            _sbLines += '<div style="font-size:15px;font-weight:900;">🪙 ボーナス ' + Number(_sb.coins) + ' コイン</div>';
          }
          if (_sb.monster_id) {
            var _sbM = null;
            try { _sbM = window.getMonster ? window.getMonster(Number(_sb.monster_id)) : null; } catch (e2) { _sbM = null; }
            var _sbHit = !!(_sbM && Number(_sbM.id) === Number(_sb.monster_id));
            var _sbNm = _sbHit ? _sbM.name : 'げんていキャラ';
            var _sbSp = _sbHit ? (_sbM.sprite || '🎁') : '🎁';
            _sbLines += '<div style="font-size:15px;font-weight:900;margin-top:2px;">' + esc(_sbSp) + ' げんてい ' + esc(_sbNm) + ' をゲット！</div>';
          }
          hero += '<div style="border-radius:14px;padding:12px;margin:8px 0 10px;text-align:center;background:linear-gradient(135deg,#fef3c7,#fde68a);border:2px solid #f59e0b;color:#7c2d12;">'
            + '<div style="font-size:20px;font-weight:900;">🏁 ステージ' + Number(_sb.stage) + ' クリア！</div>'
            + '<div style="font-size:13px;font-weight:800;margin:2px 0 6px;">つぎは ステージ' + Number(_sb.next || (Number(_sb.stage) + 1)) + '</div>'
            + _sbLines
            + '</div>';
        }
      } catch (e) {}
'''

# ------------------------------------------------------------------
s = io.open(SRC, encoding='utf-8').read()
d = io.open(D2, encoding='utf-8').read()
before = chain_count(s)
done_src = SENTINEL_SRC in s
done_d2 = SENTINEL_D2 in d

if done_src and done_d2:
    print('すでに適用済み（番兵あり）。何も書かない。chain =', before)
    sys.exit(0)

if done_src != done_d2:
    print('NG: 片方だけ適用済み（src=%s, defense2=%s）。手で見てから流し直す。' % (done_src, done_d2))
    sys.exit(1)

if before != CHAIN_BEFORE:
    print('NG: 流す前のチェーンが %d 件（期待 %d）' % (before, CHAIN_BEFORE))
    sys.exit(1)

need('student-karte の読み込み', A_SRC, s, 1)
need('結果画面の hero 締め', A_D2, d, 1)
need('defstage_monsters がまだ無いこと', 'defstage_monsters', s, 0)
need('def2HypeHtml', 'function def2HypeHtml(log, st){', d, 1)
need('esc', 'function esc(s){', d, 1)

s = s.replace(A_SRC, N_SRC, 1)
d = d.replace(A_D2, N_D2, 1)

after = chain_count(s)
ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


# --- 増えたのは自分の1件だけ ---
chk('チェーン', after, CHAIN_AFTER)
chk('増えた件数', after - before, 1)
chk('番兵(src)', s.count(SENTINEL_SRC), 1)
chk('読み込む1行', s.count('<script src="/defstage_monsters.js?v=1"></script>'), 1)
chk('番兵(defense2)', d.count(SENTINEL_D2), 1)
chk('ステージクリアの見出し', d.count('クリア！'), 1)
chk('つぎのステージ', d.count('つぎは ステージ'), 1)
chk('stage_bonus だけを見ている', d.count('st.stage_bonus'), 1)
# --- 表示側で値をつくっていないこと ---
for _w in ('player.coins', 'saveData(', 'fetch(', 'MONSTERS.push'):
    _i = d.index('/* DEFSTAGE_CHARS_V1')
    _j = d.index('var top = c.list[0]||{};', _i)
    if _w in d[_i:_j]:
        print('NG: 結果画面の中で %s を使っている（表示だけにする）' % _w)
        ok[0] = False
# --- 壊してはいけないもの（src） ---
chk('__DEFSTAGE_BONUS_V1__', s.count('__DEFSTAGE_BONUS_V1__'), 7)
chk('__DEFSTAGE_SENTINEL_V1__', s.count('__DEFSTAGE_SENTINEL_V1__'), 1)
chk('__DEF_SNAP_SPDSKILLS_V1__', s.count('__DEF_SNAP_SPDSKILLS_V1__'), 1)
chk('__DEF_RESOLVE_VERIFY_V1__', s.count('__DEF_RESOLVE_VERIFY_V1__'), 1)
chk('log の v===2 条件', s.count('Number(_dvLog.v) === 2'), 1)
chk('baseHpA の有限数条件', s.count('Number.isFinite(Number(_dvRep.baseHpA))'), 1)
chk('retry true', s.count('retry: true'), 2)
chk('log の 900000 上限', s.count('900000'), 1)
chk('defense_standing', s.count('defense_standing'), 4)
chk('defense_carry_lock', s.count('defense_carry_lock'), 1)
chk('defAutoAdvanceV1', s.count('defAutoAdvanceV1'), 3)
chk('ensureDefenseTables() の呼び出し', s.count('ensureDefenseTables()'), 0)
chk('基地HP 380', s.count('DEFENSE_BASE_HP = 380'), 1)
chk('勝利コイン 20', s.count('DEFENSE_WIN_COINS = 20'), 1)
chk('defStageEnemies の呼び出し', s.count('defStageEnemies('), 3)
chk('ステージ前進の UPDATE', s.count('UPDATE defense_stage SET stage = stage + 1'), 2)
chk('降格の書き込み', s.count('UPDATE defense_stage SET stage - 1'), 0)
chk('台帳の予約', s.count("UPDATE defense_stage_rewards SET applied_at = datetime('now')"), 1)
chk('台帳の解放', s.count('UPDATE defense_stage_rewards SET applied_at = NULL'), 1)
# --- 壊してはいけないもの（defense2） ---
chk('defense2 の早期抜け', d.count('__DEF2_SKIP_LOCAL_V1__'), 1)
chk('defense2 の makeResolve', d.count('function makeResolve(orig){'), 1)
# --- dry-run は書き込みゼロ ---
_a = s.index("app.get('/api/teacher/defense/dry-run'")
_b = s.index("app.post('/api/defense/resolve'", _a)
_blk = s[_a:_b]
for _w in ('INSERT', 'UPDATE', 'DELETE', '.run()', '.batch('):
    if _w in _blk:
        print('NG: dry-run に書き込み %s が入っている' % _w)
        ok[0] = False

if not ok[0]:
    print('検証に落ちたので何も書かない')
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
io.open(D2, 'w', encoding='utf-8').write(d)
print('OK: 適用した。chain =', before, '->', after)
