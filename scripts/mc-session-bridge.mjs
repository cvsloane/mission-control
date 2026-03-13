#!/usr/bin/env node

/**
 * Mission Control Session Bridge
 *
 * Scans local ~/.claude/projects/ for Claude Code session JSONL files,
 * parses session stats, and POSTs them to a remote Mission Control instance.
 *
 * Designed to run on heavisidelinux via a systemd timer, bridging sessions
 * to the MC deployment on apps-vps.
 *
 * Usage:
 *   MC_URL=https://mc.heavisidetechnology.com MC_API_KEY=<key> node scripts/mc-session-bridge.mjs
 *
 * Environment:
 *   MC_URL       — Mission Control base URL (required)
 *   MC_API_KEY   — API key with operator role (required)
 *   CLAUDE_HOME  — Override ~/.claude location (optional)
 *   SOURCE_HOST  — Hostname to report (default: os.hostname())
 */

import { readdirSync, readFileSync, statSync, writeFileSync, existsSync } from 'node:fs'
import { join, basename } from 'node:path'
import os from 'node:os'

const MC_URL = process.env.MC_URL
const MC_API_KEY = process.env.MC_API_KEY
const CLAUDE_HOME = process.env.CLAUDE_HOME || join(os.homedir(), '.claude')
const SOURCE_HOST = process.env.SOURCE_HOST || os.hostname()
const STATE_FILE = join(CLAUDE_HOME, '.mc-bridge-state.json')

// Session is "active" if last activity within this window
const ACTIVE_THRESHOLD_MS = 90 * 60 * 1000
const FUTURE_TOLERANCE_MS = 60 * 1000

// Rough per-token pricing for cost estimation
const MODEL_PRICING = {
  'claude-opus-4-6': { input: 15 / 1_000_000, output: 75 / 1_000_000 },
  'claude-sonnet-4-6': { input: 3 / 1_000_000, output: 15 / 1_000_000 },
  'claude-haiku-4-5': { input: 0.8 / 1_000_000, output: 4 / 1_000_000 },
}
const DEFAULT_PRICING = { input: 3 / 1_000_000, output: 15 / 1_000_000 }

function clampTimestamp(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return 0
  const now = Date.now()
  if (ms > now + FUTURE_TOLERANCE_MS) return now
  return ms
}

function parseSessionFile(filePath, projectSlug, fileMtimeMs) {
  try {
    const content = readFileSync(filePath, 'utf-8')
    const lines = content.split('\n').filter(Boolean)
    if (lines.length === 0) return null

    let sessionId = null
    let model = null
    let gitBranch = null
    let projectPath = null
    let userMessages = 0
    let assistantMessages = 0
    let toolUses = 0
    let inputTokens = 0
    let outputTokens = 0
    let cacheReadTokens = 0
    let cacheCreationTokens = 0
    let firstMessageAt = null
    let lastMessageAt = null
    let lastUserPrompt = null

    for (const line of lines) {
      let entry
      try { entry = JSON.parse(line) } catch { continue }

      if (!sessionId && entry.sessionId) sessionId = entry.sessionId
      if (!gitBranch && entry.gitBranch) gitBranch = entry.gitBranch
      if (!projectPath && entry.cwd) projectPath = entry.cwd

      if (entry.timestamp) {
        if (!firstMessageAt) firstMessageAt = entry.timestamp
        lastMessageAt = entry.timestamp
      }

      if (entry.isSidechain) continue

      if (entry.type === 'user' && entry.message) {
        userMessages++
        const msg = entry.message
        if (typeof msg.content === 'string' && msg.content.length > 0) {
          lastUserPrompt = msg.content.slice(0, 500)
        }
      }

      if (entry.type === 'assistant' && entry.message) {
        assistantMessages++
        if (entry.message.model) model = entry.message.model
        const usage = entry.message.usage
        if (usage) {
          inputTokens += (usage.input_tokens || 0)
          cacheReadTokens += (usage.cache_read_input_tokens || 0)
          cacheCreationTokens += (usage.cache_creation_input_tokens || 0)
          outputTokens += (usage.output_tokens || 0)
        }
        if (Array.isArray(entry.message.content)) {
          for (const block of entry.message.content) {
            if (block.type === 'tool_use') toolUses++
          }
        }
      }
    }

    if (!sessionId) return null

    const pricing = (model && MODEL_PRICING[model]) || DEFAULT_PRICING
    const estimatedCost =
      inputTokens * pricing.input +
      cacheReadTokens * pricing.input * 0.1 +
      cacheCreationTokens * pricing.input * 1.25 +
      outputTokens * pricing.output

    const totalInputTokens = inputTokens + cacheReadTokens + cacheCreationTokens

    const parsedFirstMs = firstMessageAt ? clampTimestamp(new Date(firstMessageAt).getTime()) : 0
    const parsedLastMs = lastMessageAt ? clampTimestamp(new Date(lastMessageAt).getTime()) : 0
    const mtimeMs = clampTimestamp(fileMtimeMs)
    const effectiveLastMs = Math.max(parsedLastMs, mtimeMs)
    const effectiveFirstMs = parsedFirstMs || mtimeMs
    const isActive = effectiveLastMs > 0 && (Date.now() - effectiveLastMs) < ACTIVE_THRESHOLD_MS

    return {
      sessionId,
      projectSlug,
      projectPath,
      model,
      gitBranch,
      userMessages,
      assistantMessages,
      toolUses,
      inputTokens: totalInputTokens,
      outputTokens,
      estimatedCost: Math.round(estimatedCost * 10000) / 10000,
      firstMessageAt: effectiveFirstMs ? new Date(effectiveFirstMs).toISOString() : null,
      lastMessageAt: effectiveLastMs ? new Date(effectiveLastMs).toISOString() : null,
      lastUserPrompt,
      isActive,
    }
  } catch (err) {
    console.warn(`Failed to parse ${filePath}: ${err.message}`)
    return null
  }
}

function loadState() {
  try {
    if (existsSync(STATE_FILE)) {
      return JSON.parse(readFileSync(STATE_FILE, 'utf-8'))
    }
  } catch { /* ignore corrupt state */ }
  return { mtimes: {} }
}

function saveState(state) {
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2))
}

function scanSessions(incremental = true) {
  const projectsDir = join(CLAUDE_HOME, 'projects')
  let projectDirs
  try {
    projectDirs = readdirSync(projectsDir)
  } catch {
    return []
  }

  const state = incremental ? loadState() : { mtimes: {} }
  const sessions = []
  const newMtimes = {}

  for (const projectSlug of projectDirs) {
    const projectDir = join(projectsDir, projectSlug)
    let stat
    try { stat = statSync(projectDir) } catch { continue }
    if (!stat.isDirectory()) continue

    let files
    try { files = readdirSync(projectDir).filter(f => f.endsWith('.jsonl')) } catch { continue }

    for (const file of files) {
      const filePath = join(projectDir, file)
      let fileStat
      try { fileStat = statSync(filePath) } catch { continue }

      const key = `${projectSlug}/${file}`
      const prevMtime = state.mtimes[key] || 0

      // Skip files unchanged since last scan (incremental mode)
      if (incremental && fileStat.mtimeMs <= prevMtime) continue

      newMtimes[key] = fileStat.mtimeMs
      const parsed = parseSessionFile(filePath, projectSlug, fileStat.mtimeMs)
      if (parsed) sessions.push(parsed)
    }
  }

  // Merge mtimes: keep old entries, update changed ones
  if (incremental) {
    Object.assign(state.mtimes, newMtimes)
    saveState(state)
  }

  return sessions
}

async function main() {
  if (!MC_URL) {
    console.error('MC_URL environment variable is required')
    process.exit(1)
  }
  if (!MC_API_KEY) {
    console.error('MC_API_KEY environment variable is required')
    process.exit(1)
  }

  const fullScan = process.argv.includes('--full')
  const sessions = scanSessions(!fullScan)

  if (sessions.length === 0) {
    console.log('No new/changed sessions to sync')
    return
  }

  console.log(`Sending ${sessions.length} session(s) from ${SOURCE_HOST} to ${MC_URL}`)

  const url = `${MC_URL.replace(/\/$/, '')}/api/claude/sessions`
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': MC_API_KEY,
    },
    body: JSON.stringify({
      source_host: SOURCE_HOST,
      sessions,
    }),
  })

  if (!response.ok) {
    const text = await response.text()
    console.error(`MC responded ${response.status}: ${text}`)
    process.exit(1)
  }

  const result = await response.json()
  console.log(`OK: ${result.message}`)
}

main().catch(err => {
  console.error('Bridge failed:', err.message)
  process.exit(1)
})
