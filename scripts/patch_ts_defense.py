import sys

def patch_file(path, edits):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        data = f.read()
    for old, new in edits:
        if new in data and old not in data:
            print('skip:', repr(old[:40])); continue
        if old not in data:
            print('ANCHOR NOT FOUND', path, repr(old[:70])); sys.exit(1)
        if data.count(old) != 1:
            print('NOT UNIQUE', data.count(old), repr(old[:70])); sys.exit(1)
        data = data.replace(old, new); print('ok', path, repr(old[:40]))
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(data)

PUB_EDITS = [
    ('// 連続提出ごほうび：オチャ（Lv60でオチャ大魔王）（記録日カウント）',
     'try { if (!rest && player && !player.shardBanned && player.reflectShardDate !== dayKey) { var _refb = 1; if (streakAfter >= 6) _refb = 3; else if (streakAfter >= 3) _refb = 2; bonus.shards = (Number(bonus.shards) || 0) + _refb; player.reflectShardDate = dayKey; window.__reflectBonusShards = _refb; } else { window.__reflectBonusShards = 0; } } catch(e) { window.__reflectBonusShards = 0; }\n    // 連続提出ごほうび：オチャ（Lv60でオチャ大魔王）（記録日カウント）'),
    ("'✅ 提出完了！' + rewardText + 'ゲット！' + streakText;",
     "'✅ 提出完了！' + rewardText + 'ゲット！' + streakText + ((window.__reflectBonusShards>0) ? ' 🔹ふりかえりボーナス かけら+'+window.__reflectBonusShards+'！' : '');"),
]

patch_file('public/index.html', PUB_EDITS)
print('DONE')
