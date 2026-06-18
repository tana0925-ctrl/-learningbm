import sys
NL=chr(10)
def patch_file(path, edits, label):
    data=open(path,'rb').read().decode('utf-8')
    for old,new,guard in edits:
        if guard and guard in data:
            print('['+label+'] skip', file=sys.stderr); continue
        c=data.count(old)
        if c!=1:
            print('['+label+'] ANCHOR x'+str(c), file=sys.stderr); sys.exit(1)
        data=data.replace(old,new,1)
    open(path,'wb').write(data.encode('utf-8'))
    print('['+label+'] ok', file=sys.stderr)

old="  function injectButton() {"+NL+"    if (el('tsLaunchBtn')) return;"
new="  function injectButton() {"+NL+"    return; /* float btn disabled: launch from battle menu */"+NL+"    if (el('tsLaunchBtn')) return;"
patch_file('public/typeshoot.js', [(old, new, "/* float btn disabled")], 'typeshoot.js')
print('DONE', file=sys.stderr)
