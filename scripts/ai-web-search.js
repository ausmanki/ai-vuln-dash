#!/usr/bin/env node
/* eslint-env node */

const query = process.argv.slice(2).join(' ') || 'what was a positive news story from today?'
const geminiKey = process.env.GEMINI_API_KEY
const openaiKey = process.env.OPENAI_API_KEY

if (!geminiKey && !openaiKey) {
  console.error('Please set GEMINI_API_KEY or OPENAI_API_KEY environment variable')
  process.exit(1)
}

const useGemini = !!geminiKey

async function run() {
  try {
    if (useGemini) {
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
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro-latest:generateContent?key=${geminiKey}`
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
    } else {
      const body = {
        model: 'gpt-4.1',
        tools: [{ type: 'web_search_preview' }],
        input: query
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
      const text = data.choices?.[0]?.message?.content || data.result
      console.log(text || JSON.stringify(data, null, 2))
    }
  } catch (err) {
    console.error('Request failed:', err.message)
    process.exit(1)
  }
}

run()
