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
  ('/[\\s\u3000]/g','/[\\\\s\u3000]/g','normId'),
  ('/\\r?\\n/','/\\\\r?\\\\n/','split'),
  ('/^[\\s\u3000]*[=＝]{2,}[\\s\u3000]*[\\[［]\\s*([^\\]］]+?)\\s*[\\]］]/','/^[\\\\s\u3000]*[=＝]{2,}[\\\\s\u3000]*[\\\\[［]\\\\s*([^\\\\]］]+?)\\\\s*[\\\\]］]/','marker'),
  ('/^\\s+|\\s+$/g','/^\\\\s+|\\\\s+$/g','trim'),
  ('/<style>[\\s\\S]*?<\\/style>/','/<style>[\\\\s\\\\S]*?<\\\\/style>/','stylere'),
  ('/<body>([\\s\\S]*?)<\\/body>/','/<body>([\\\\s\\\\S]*?)<\\\\/body>/','bodyre'),
]
patch_file('src/index.tsx', EDITS)
print('DONE', file=sys.stderr)
