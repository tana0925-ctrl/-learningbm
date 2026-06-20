import sys
def patch_file(path, edits):
    data=open(path,'rb').read().decode('utf-8')
    for old,new,g in edits:
        if new in data and old not in data:
            print('skip '+g, file=sys.stderr); continue
        c=data.count(old)
        if c!=1:
            print('ANCHOR x'+str(c)+' '+g, file=sys.stderr); sys.exit(1)
        data=data.replace(old,new,1)
    open(path,'wb').write(data.encode('utf-8'))
    print('ok', file=sys.stderr)
EDITS=[
  ('      function _kRadar(vals){', '      function _kHBar(items, color){\n        if(!items||!items.length) return \'<div style="font-size:11px;color:#94a3b8;padding:4px 8px">データなし</div>\';\n        var n=items.length, rowH=24, W=520, labelW=150, barX=labelW+6, barMaxW=W-barX-92, H=n*rowH+4;\n        var s=\'<svg width="\'+W+\'" height="\'+H+\'" viewBox="0 0 \'+W+\' \'+H+\'" xmlns="http://www.w3.org/2000/svg" style="max-width:100%">\';\n        for(var i=0;i<n;i++){ var it=items[i]; var rate=Math.max(0,Math.min(100,it.rate||0)); var y=i*rowH+rowH/2; var bw=Math.max(barMaxW*rate/100,2);\n          var lab=String(it.label||\'\'); if(lab.length>12) lab=lab.slice(0,11)+\'…\';\n          s+=\'<text x="\'+labelW+\'" y="\'+(y+4)+\'" font-size="11" font-weight="700" fill="#334155" text-anchor="end">\'+lab+\'</text>\';\n          s+=\'<rect x="\'+barX+\'" y="\'+(y-8)+\'" width="\'+barMaxW+\'" height="16" rx="8" fill="#f1f5f9"/>\';\n          s+=\'<rect x="\'+barX+\'" y="\'+(y-8)+\'" width="\'+bw.toFixed(1)+\'" height="16" rx="8" fill="\'+color+\'"/>\';\n          s+=\'<text x="\'+(barX+barMaxW+5)+\'" y="\'+(y+4)+\'" font-size="10" font-weight="700" fill="\'+color+\'" text-anchor="start">\'+rate+\'%（\'+(it.total||0)+\'問）</text>\';\n        }\n        s+=\'</svg>\'; return s;\n      }\n      function _kRadar(vals){', 'H1_hbar_helper'),
  ("+_kDonut(ov.sunCount,ov.cloudCount,ov.rainCount)+'</div>'); H.push('</div></div>');", '+_kDonut(ov.sunCount,ov.cloudCount,ov.rainCount)+\'</div>\'); H.push(\'</div>\'); var goodBars=good.map(function(s){return {label:_unitJa(s.unit),rate:s.rate,total:s.total};}); var growBars=grow.map(function(s){return {label:_unitJa(s.unit),rate:s.rate,total:s.total};}); var revBars=reviewWeak.map(function(s){var rg=_unitGrade(s.unit); return {label:(rg?rg+\'年 \':\'\')+_unitJa(s.unit),rate:s.rate,total:s.total};}); H.push(\'<div style="margin-top:8px;border-top:1px dashed #e2e8f0;padding-top:6px">\'); H.push(\'<div style="font-weight:800;color:#16a34a;font-size:12px;margin-bottom:2px">💪 とくいな単元（いまの学年）</div>\'+_kHBar(goodBars,\'#22c55e\')); H.push(\'<div style="font-weight:800;color:#ea580c;font-size:12px;margin:6px 0 2px">🌱 これから伸ばす単元（いまの学年）</div>\'+_kHBar(growBars,\'#f97316\')); if(revBars.length){ H.push(\'<div style="font-weight:800;color:#0369a1;font-size:12px;margin:6px 0 2px">🔁 下の学年の復習（まずここから）</div>\'+_kHBar(revBars,\'#3b82f6\')); } H.push(\'</div>\'); H.push(\'</div>\');', 'H2_unit_bars'),
]
patch_file('src/index.tsx', EDITS)
print('DONE', file=sys.stderr)
