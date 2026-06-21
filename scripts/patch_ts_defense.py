import sys

def patch_file(path, edits):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        data = f.read()
    for old, new in edits:
        if new in data and old not in data:
            print('skip (already applied):', repr(old[:40]))
            continue
        if old not in data:
            print('ANCHOR NOT FOUND in', path, '::', repr(old[:60]))
            sys.exit(1)
        if data.count(old) != 1:
            print('ANCHOR NOT UNIQUE', data.count(old), repr(old[:60]))
            sys.exit(1)
        data = data.replace(old, new)
        print('ok', path, '::', repr(old[:40]))
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(data)

SRV_EDITS = [
    # 1) callGemini fetch: add a 30s timeout so a slow/hanging Gemini call can't stall the worker
    ("""      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })""",
     """      const _ac = new AbortController(); const _to = setTimeout(() => _ac.abort(), 30000)
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: _ac.signal,
      }).finally(() => clearTimeout(_to))"""),
    # 2) class-ai-analysis fallback: timeout + try/catch, never return 500, friendly message
    ("""    // フォールバック
    if (!analysisText) {
      const aiResult: any = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct-fast', {
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 1024
      })
      analysisText = aiResult.response || aiResult.result || ''
    }
    return c.json({ ok: true, analysis: analysisText })
  } catch (e: any) {
    return c.json({ ok: false, error: e.message || 'AI error' }, 500)
  }""",
     """    // フォールバック（タイムアウト付き・失敗しても500にしない）
    if (!analysisText) {
      try {
        const aiResult: any = await Promise.race([
          c.env.AI.run('@cf/meta/llama-3.1-8b-instruct-fast', {
            messages: [{ role: 'user', content: prompt }],
            max_tokens: 1024
          }),
          new Promise((_, rej) => setTimeout(() => rej(new Error('workers_ai_timeout')), 20000))
        ])
        analysisText = aiResult.response || aiResult.result || ''
      } catch (fe: any) {
        console.error('class-ai fallback failed:', fe?.message || fe)
      }
    }
    if (!analysisText) {
      return c.json({ ok: false, error: 'AI分析を生成できませんでした。少し時間をおいて再度お試しください。（管理者の方へ：解消しない場合は GEMINI_API_KEY の有効期限切れの可能性があります）' })
    }
    return c.json({ ok: true, analysis: analysisText })
  } catch (e: any) {
    return c.json({ ok: false, error: e.message || 'AI error' }, 500)
  }"""),
]

patch_file('src/index.tsx', SRV_EDITS)
print('DONE')
