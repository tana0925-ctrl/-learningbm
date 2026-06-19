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
  ('🤖 AIからのアドバイス','🤖 阪神マンからのアドバイス','han-screen'),
  ('🤖 AIからの アドバイス','🤖 阪神マンからのアドバイス','han-karte'),
  ('あなたは小学校の先生のサポート役です。以下の児童の家庭学習データをもとに、①取り組みの良い点、②気になる点、③次の声かけ・支援の提案、を小学校の先生向けにやさしい日本語でまとめてください。','あなたはアプリの修行エリアにいる関西弁の応援キャラ「阪神マン」です。以下の児童の家庭学習データをもとに、①ええところ（取り組みの良い点）②気になるところ③おすすめの学習・声かけ、を関西弁で、子どもが読んで前向きになれるようにやさしくまとめてください。やりすぎず、先生がそのまま使える範囲でお願いします。','han-single'),
  ('以下は同じクラスの複数の児童の家庭学習データです。各児童ごとに、「=== [児童ID] 名前 ===」の目印の行を そのまま変えずに残し、その下に ①取り組みの良い点 ②気になる点 ③おすすめの学習 を、小学校の先生向けにやさしい日本語で書いてください。児童IDと目印は絶対に変更しないでください。','以下は同じクラスの複数の児童の家庭学習データです。あなたは関西弁の応援キャラ「阪神マン」です。各児童ごとに、「=== [児童ID] 名前 ===」の目印の行を そのまま変えずに残し、その下に ①ええところ（取り組みの良い点）②気になるところ ③おすすめの学習・声かけ を、関西弁で子どもを励ますようにやさしく書いてください。児童IDと目印は絶対に変更しないでください。やりすぎず、先生がそのまま使える範囲で。','han-bulk'),
]
patch_file('src/index.tsx', EDITS)
print('DONE', file=sys.stderr)
