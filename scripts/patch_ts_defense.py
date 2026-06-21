import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip:',repr(old[:40])); continue
        if old not in data:
            print('ANCHOR NOT FOUND',path,repr(old[:70])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old),repr(old[:70])); sys.exit(1)
        data=data.replace(old,new); print('ok',path,repr(old[:40]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ('// ===== 授業メモAPI（クラス全体メモ＋児童ごとメモ・教師は自分のクラスのみ） =====',
     "// ===== 学習の記録（ポートフォリオ）取り込みAPI =====\nfunction _recNorm(s){ return String(s==null?'':s).replace(/[Ａ-Ｚａ-ｚ０-９]/g,function(ch){return String.fromCharCode(ch.charCodeAt(0)-65248);}).replace(/[ \u3000]/g,'').toLowerCase(); }\nfunction _recHalfDate(v){ var s=String(v==null?'':v).replace(/[０-９]/g,function(ch){return String.fromCharCode(ch.charCodeAt(0)-65248);}); s=s.split('年').join('-').split('月').join('-').split('日').join('').split('/').join('-').split('.').join('-').trim(); if(s.charAt(s.length-1)==='-') s=s.slice(0,-1); return s; }\nfunction _recParseText(text){\n  var NL=String.fromCharCode(10);\n  var lines=String(text||'').split(NL);\n  var blocks=[]; var cur=null; var bodyMode=false;\n  for(var i=0;i<lines.length;i++){\n    var rawLine=String(lines[i]==null?'':lines[i]);\n    var line=rawLine.trim();\n    var mk=line.match(/^===\\s*\\[([^\\]]*)\\]\\s*(.*?)\\s*===$/);\n    if(mk){\n      if(cur) blocks.push(cur);\n      cur={ idRaw:String(mk[1]||'').trim(), nameRaw:String(mk[2]||'').trim(), title:'', day:'', subject:'', unit:'', body:'' };\n      bodyMode=false; continue;\n    }\n    if(!cur) continue;\n    if(!bodyMode){\n      var ci=line.indexOf('：'); if(ci<0) ci=line.indexOf(':');\n      var k=(ci>=0)?line.slice(0,ci).replace(/[ \u3000]/g,''):'';\n      var v=(ci>=0)?line.slice(ci+1).trim():'';\n      if(k.indexOf('タイトル')>=0||k.indexOf('題名')>=0){ cur.title=v; continue; }\n      if(k.indexOf('日付')>=0||k.indexOf('日時')>=0||k.indexOf('実施日')>=0){ cur.day=_recHalfDate(v); continue; }\n      if(k.indexOf('教科')>=0||k.indexOf('科目')>=0){ cur.subject=v; continue; }\n      if(k.indexOf('単元')>=0){ cur.unit=v; continue; }\n      if(k.indexOf('本文')>=0||k.indexOf('内容')>=0){ bodyMode=true; if(v){ cur.body+=v; } continue; }\n      continue;\n    } else { cur.body += (cur.body?NL:'') + rawLine; }\n  }\n  if(cur) blocks.push(cur);\n  for(var b=0;b<blocks.length;b++){ blocks[b].body=String(blocks[b].body||'').replace(/\\s+$/,''); }\n  return blocks;\n}\n// ===== 授業メモAPI（クラス全体メモ＋児童ごとメモ・教師は自分のクラスのみ） ====="),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE P1_helpers')
