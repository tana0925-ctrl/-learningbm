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
  ("const aiResult: any = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {\n        messages: [{ role: 'user', content: prompt }],", "const aiResult: any = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct-fast', {\n        messages: [{ role: 'user', content: prompt }],", 'F1_classai_fallback'),
  ("const aiRes: any = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {\n          messages: [", "const aiRes: any = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct-fast', {\n          messages: [", 'F2_comment_fallback'),
]
patch_file('src/index.tsx', EDITS)
print('DONE', file=sys.stderr)
