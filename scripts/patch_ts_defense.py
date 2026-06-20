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
  ("async function callGemini(env: any, body: any, model = 'gemini-2.5-flash'): Promise<{ ok: boolean, text: string, source: string }> {", "async function callGemini(env: any, body: any, model = 'gemini-3.5-flash'): Promise<{ ok: boolean, text: string, source: string }> {", 'M1_model'),
]
patch_file('src/index.tsx', EDITS)
print('DONE', file=sys.stderr)
