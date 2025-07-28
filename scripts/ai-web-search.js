#!/usr/bin/env node
/* eslint-env node */

const query = process.argv.slice(2).join(' ') || 'what was a positive news story from today?'
const geminiKey = process.env.GEMINI_API_KEY
const openaiKey = process.env.OPENAI_API_KEY
const userLocation = process.env.OPENAI_USER_LOCATION
const searchContextSize = process.env.OPENAI_SEARCH_CONTEXT_SIZE

if (!geminiKey && !openaiKey) {
  console.error('Please set GEMINI_API_KEY or OPENAI_API_KEY environment variable')
  process.exit(1)
}

const useOpenAI = !!openaiKey
const useGemini = !useOpenAI && !!geminiKey

async function run() {
  try {
    if (useOpenAI) {
      const body = {
        model: 'gpt-4.1',
        tools: [{ type: 'web_search_preview' }],
        input: query,
        tool_choice: { type: 'web_search_preview' }
      }

      if (userLocation) {
        body.user_location = userLocation
      }
      if (searchContextSize) {
        const size = parseInt(searchContextSize, 10)
        if (!Number.isNaN(size)) {
          body.search_context_size = size
        }
      }

      const response = await fetch('https://api.openai.com/v1/responses', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${openaiKey}`
        },
        body: JSON.stringify(body)
      })
      if (!response.ok) {
        throw new Error(`OpenAI API error: ${response.status}`)
      }
      const data = await response.json()

      const text =
        data.output_text ||
        data.output ||
        data.response ||
        data.text ||
        data.choices?.[0]?.message?.content
      console.log(text || '')

      if (Array.isArray(data.annotations)) {
        const urls = data.annotations
          .filter(a => a.url)
          .map(a => a.url)
        if (urls.length) {
          console.log('\nCitation URLs:\n' + urls.join('\n'))
        }
      }
    } else if (useGemini) {
      const body = {
        contents: [{ parts: [{ text: query }] }],
        generationConfig: {
          temperature: 0.3,
          topK: 1,
          topP: 0.8,
          maxOutputTokens: 1024,
          candidateCount: 1
        },
        tools: [{ google_search: {} }]
      }
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })
      if (!response.ok) {
        throw new Error(`Gemini API error: ${response.status}`)
      }
      const data = await response.json()
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text
      console.log(text || JSON.stringify(data, null, 2))
    }
  } catch (err) {
    console.error('Request failed:', err.message)
    process.exit(1)
  }
}

run()
