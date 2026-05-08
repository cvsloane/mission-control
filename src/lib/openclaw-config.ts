import { existsSync, readFileSync } from 'node:fs'
import { parseJsonRelaxed } from '@/lib/json-relaxed'

export function readOpenClawConfigFile<T = Record<string, any>>(configPath: string): T {
  const raw = readFileSync(configPath, 'utf-8')
  return parseJsonRelaxed<T>(raw)
}

export function tryReadOpenClawConfigFile<T = Record<string, any>>(configPath?: string | null): T | null {
  if (!configPath || !existsSync(configPath)) return null
  try {
    return readOpenClawConfigFile<T>(configPath)
  } catch {
    return null
  }
}
