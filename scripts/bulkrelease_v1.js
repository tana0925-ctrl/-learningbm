/* BULKRELEASE_V1 ボックスの「まとめてにがす」。既存の1体ずつの機能はそのまま。 */
(function () {
    'use strict';
    if (window.__bulkReleaseV1) { return; }
    window.__bulkReleaseV1 = 1;

    var MAX = 20;
    var realConfirm = window.confirm;
    var realAlert = window.alert;
    var sel = {};          /* uid -> true */
    var rows = [];

    function esc(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    function player() {
        try { return (typeof window.getPlayer === 'function') ? window.getPlayer() : null; }
        catch (e) { return null; }
    }
    function mon(id) {
        try { return window.getMonster(id) || null; } catch (e) { return null; }
    }
    function nameOf(id) { var m = mon(id); return (m && m.name) ? m.name : ('No.' + id); }
    function spriteOf(id) {
        var m = mon(id);
        try {
            if (typeof window.monSpriteHtml === 'function') {
                return window.monSpriteHtml(id, (m && m.sprite) || '？');
            }
        } catch (e) { }
        return esc((m && m.sprite) || '？');
    }

    /* 一覧を作る。守るものには locked を立てる */
    function build() {
        var p = player();
        if (!p) { return []; }
        var list = [];
        try { list = window.getAllBoxEntries() || []; } catch (e) { list = []; }

        var count = {};
        list.forEach(function (e) { count[e.monsterId] = (count[e.monsterId] || 0) + 1; });
        var party = Array.isArray(p.party) ? p.party.map(Number) : [];

        var out = list.map(function (e) {
            var why = '';
            if (party.indexOf(Number(e.monsterId)) >= 0) { why = 'パーティ'; }
            else if (e.isActive) { why = 'つかっている'; }
            else if ((count[e.monsterId] || 0) <= 1) { why = 'さいごの1体'; }
            return {
                uid: e.uid,
                id: Number(e.monsterId),
                name: nameOf(e.monsterId),
                lv: Number(e.level || 1),
                stars: Number(e.stars || 0),
                locked: !!why,
                why: why,
                nth: 1
            };
        });

        /* 同じ種類の中で 何体目か（よわい順）。1体目は「2体目から」に入らない */
        var byId = {};
        out.forEach(function (r) { (byId[r.id] = byId[r.id] || []).push(r); });
        Object.keys(byId).forEach(function (k) {
            byId[k].sort(function (a, b) {
                /* にがせない子を先に置く＝のこす1体として数える */
                if (a.locked !== b.locked) { return a.locked ? -1 : 1; }
                return (b.stars - a.stars) || (b.lv - a.lv) || (a.uid < b.uid ? -1 : 1);
            });
            byId[k].forEach(function (r, i) { r.nth = i + 1; });
        });
        out.sort(function (a, b) { return (a.id - b.id) || (a.nth - b.nth); });
        return out;
    }

    function selectedRows() {
        return rows.filter(function (r) { return sel[r.uid]; });
    }

    function setSel(uid, on) {
        if (on) {
            if (Object.keys(sel).length >= MAX) {
                realAlert.call(window, '1回に にがせるのは ' + MAX + '体までです。');
                return false;
            }
            sel[uid] = true;
        } else {
            delete sel[uid];
        }
        return true;
    }

    function refreshHeader() {
        var n = Object.keys(sel).length;
        var h = document.getElementById('brHeadCount');
        if (h) { h.textContent = n + '体 えらんでいます（' + MAX + '体まで）'; }
        var b = document.getElementById('brGoBtn');
        if (b) {
            b.disabled = (n === 0);
            b.style.opacity = n === 0 ? '0.45' : '1';
            b.textContent = n === 0 ? 'にがす' : ('えらんだ ' + n + '体を にがす');
        }
    }

    function paintRow(r) {
        var el = document.getElementById('brRow_' + r.uid);
        if (!el) { return; }
        var on = !!sel[r.uid];
        el.style.background = on ? '#fee2e2' : '#fff';
        el.style.borderColor = on ? '#ef4444' : '#e5e7eb';
        var cb = el.querySelector('input');
        if (cb) { cb.checked = on; }
    }

    function openPanel() {
        rows = build();
        sel = {};
        var ov = document.getElementById('brOverlay');
        if (ov) { ov.remove(); }
        ov = document.createElement('div');
        ov.id = 'brOverlay';
        ov.style.cssText = 'position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,.45);' +
            'display:flex;align-items:center;justify-content:center;padding:12px;';

        var card = document.createElement('div');
        card.style.cssText = 'background:#fff;border-radius:14px;max-width:960px;width:100%;' +
            'max-height:92vh;display:flex;flex-direction:column;overflow:hidden;';

        var head = document.createElement('div');
        head.style.cssText = 'padding:10px 14px;border-bottom:1px solid #e5e7eb;';
        head.innerHTML =
            '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            '<b style="font-size:16px">まとめて にがす</b>' +
            '<span id="brHeadCount" style="font-size:14px;color:#b91c1c;font-weight:bold"></span>' +
            '<span style="flex:1"></span>' +
            '<button id="brCloseBtn" style="padding:6px 12px;border-radius:8px;background:#e5e7eb">とじる</button>' +
            '</div>' +
            '<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;font-size:13px">' +
            '<button id="brPickDup" style="padding:5px 10px;border-radius:8px;background:#dbeafe">同じ種類の2体目から</button>' +
            '<button id="brPickNoStar" style="padding:5px 10px;border-radius:8px;background:#dbeafe">★0だけ</button>' +
            '<span style="display:inline-flex;align-items:center;gap:4px">' +
            'レベル<input id="brLvInput" type="number" min="1" max="100" value="10" ' +
            'style="width:56px;border:1px solid #cbd5e1;border-radius:6px;padding:3px 5px">以下' +
            '<button id="brPickLv" style="padding:5px 10px;border-radius:8px;background:#dbeafe">えらぶ</button>' +
            '</span>' +
            '<button id="brClear" style="padding:5px 10px;border-radius:8px;background:#f1f5f9">ぜんぶ はずす</button>' +
            '</div>';

        var body = document.createElement('div');
        body.style.cssText = 'padding:10px 14px;overflow:auto;flex:1;';
        var grid = document.createElement('div');
        grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px;';

        rows.forEach(function (r) {
            var d = document.createElement('div');
            d.id = 'brRow_' + r.uid;
            d.style.cssText = 'border:2px solid #e5e7eb;border-radius:10px;padding:5px 6px;' +
                'display:flex;align-items:center;gap:6px;font-size:13px;background:#fff;' +
                (r.locked ? 'opacity:.5;' : 'cursor:pointer;');
            var star = r.stars > 0 ? ' <span style="color:#f59e0b">★' + r.stars + '</span>' : '';
            if (r.locked) {
                d.innerHTML = '<span style="width:16px;text-align:center">🔒</span>' +
                    '<span style="font-size:22px;line-height:1">' + spriteOf(r.id) + '</span>' +
                    '<span style="flex:1;min-width:0"><span style="display:block;overflow:hidden;' +
                    'text-overflow:ellipsis;white-space:nowrap">' + esc(r.name) + '</span>' +
                    '<span style="color:#64748b">Lv' + r.lv + star + ' ' + esc(r.why) + '</span></span>';
            } else {
                d.innerHTML = '<input type="checkbox" style="width:16px;height:16px">' +
                    '<span style="font-size:22px;line-height:1">' + spriteOf(r.id) + '</span>' +
                    '<span style="flex:1;min-width:0"><span style="display:block;overflow:hidden;' +
                    'text-overflow:ellipsis;white-space:nowrap">' + esc(r.name) + '</span>' +
                    '<span style="color:#64748b">Lv' + r.lv + star + '</span></span>';
                d.addEventListener('click', function (ev) {
                    if (ev.target && ev.target.tagName === 'INPUT') { return; }
                    if (setSel(r.uid, !sel[r.uid])) { paintRow(r); refreshHeader(); }
                });
                d.querySelector('input').addEventListener('change', function (ev) {
                    if (!setSel(r.uid, ev.target.checked)) { ev.target.checked = false; }
                    paintRow(r); refreshHeader();
                });
            }
            grid.appendChild(d);
        });

        body.appendChild(grid);

        var foot = document.createElement('div');
        foot.style.cssText = 'padding:10px 14px;border-top:1px solid #e5e7eb;display:flex;gap:8px;' +
            'align-items:center;justify-content:flex-end;';
        foot.innerHTML =
            '<span style="flex:1;font-size:12px;color:#64748b">' +
            '🔒 は にがせません（パーティ・つかっている・さいごの1体）</span>' +
            '<button id="brGoBtn" style="padding:8px 16px;border-radius:10px;background:#ef4444;' +
            'color:#fff;font-weight:bold">にがす</button>';

        card.appendChild(head);
        card.appendChild(body);
        card.appendChild(foot);
        ov.appendChild(card);
        document.body.appendChild(ov);

        document.getElementById('brCloseBtn').onclick = closePanel;
        document.getElementById('brClear').onclick = function () {
            sel = {}; rows.forEach(paintRow); refreshHeader();
        };
        document.getElementById('brPickDup').onclick = function () {
            pick(function (r) { return r.nth >= 2; });
        };
        document.getElementById('brPickNoStar').onclick = function () {
            pick(function (r) { return r.stars === 0; });
        };
        document.getElementById('brPickLv').onclick = function () {
            var v = Number((document.getElementById('brLvInput') || {}).value || 0);
            if (!(v > 0)) { return; }
            pick(function (r) { return r.lv <= v; });
        };
        document.getElementById('brGoBtn').onclick = go;
        refreshHeader();
    }

    function pick(fn) {
        sel = {};
        var hit = rows.filter(function (r) { return !r.locked && fn(r); });
        var over = hit.length > MAX;
        hit.slice(0, MAX).forEach(function (r) { sel[r.uid] = true; });
        rows.forEach(paintRow);
        refreshHeader();
        if (over) {
            realAlert.call(window, 'あてはまるのは ' + hit.length + '体ですが、'
                + '1回に にがせるのは ' + MAX + '体までなので ' + MAX + '体だけ えらびました。');
        }
    }

    function closePanel() {
        var ov = document.getElementById('brOverlay');
        if (ov) { ov.remove(); }
        sel = {};
    }

    function go() {
        var list = selectedRows();
        if (!list.length) { return; }
        if (list.length > MAX) {
            realAlert.call(window, '1回に にがせるのは ' + MAX + '体までです。');
            return;
        }
        var names = list.slice(0, 3).map(function (r) { return r.name + ' Lv' + r.lv; });
        var msg = names.join('、');
        if (list.length > 3) { msg += ' ほか' + (list.length - 3) + '体'; }
        msg += '、ぜんぶで ' + list.length + '体を にがします。\n';
        var starN = list.filter(function (r) { return r.stars > 0; }).length;
        if (starN > 0) { msg += '★がついている子が ' + starN + '体 入っています。\n'; }
        msg += 'もどせません。いいですか？';

        if (!realConfirm.call(window, msg)) { return; }

        if (window.__BULKRELEASE_DRYRUN) {
            window.__BULKRELEASE_LAST = list.map(function (r) { return r.uid; });
            realAlert.call(window, '（けいこ）' + list.length + '体ぶん よびだすところまで できました。');
            closePanel();
            return;
        }

        var keep = {
            c: window.confirm, a: window.alert,
            s: window.saveData, r: window.renderBox
        };
        var done = 0, failed = [];
        try {
            window.confirm = function () { return true; };
            window.alert = function () { };
            try { window.saveData = function () { }; } catch (e) { }
            try { window.renderBox = function () { }; } catch (e) { }
            list.forEach(function (r) {
                try { window.releaseBoxMonster(r.uid); } catch (e) { failed.push(r.name); return; }
                if (window.findBoxEntry(r.uid)) { failed.push(r.name); } else { done++; }
            });
        } finally {
            window.confirm = keep.c;
            window.alert = keep.a;
            window.saveData = keep.s;
            window.renderBox = keep.r;
        }

        try { window.saveData(); } catch (e) { }
        try { window.renderBox(); } catch (e) { }
        closePanel();

        var m = done + '体を にがしました。';
        if (failed.length) { m += '\nにがせなかった子: ' + failed.join('、'); }
        realAlert.call(window, m);
    }

    /* ボックス画面にボタンを置く */
    function mountButton() {
        var scr = document.getElementById('screen-box');
        var grid = document.getElementById('boxGrid');
        if (!scr || !grid || document.getElementById('brOpenBtn')) { return; }
        var wrap = document.createElement('div');
        wrap.style.cssText = 'display:flex;justify-content:flex-end;margin:4px 0 6px;';
        wrap.innerHTML = '<button id="brOpenBtn" style="padding:6px 14px;border-radius:10px;' +
            'background:#fecaca;color:#7f1d1d;font-weight:bold;font-size:13px">まとめて にがす</button>';
        grid.parentNode.insertBefore(wrap, grid);
        document.getElementById('brOpenBtn').onclick = openPanel;
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', mountButton);
    } else {
        mountButton();
    }
    setInterval(mountButton, 2000);

    window.openBulkRelease = openPanel;
})();
