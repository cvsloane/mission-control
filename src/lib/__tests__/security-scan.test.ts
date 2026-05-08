import os from 'node:os'
import { afterEach, describe, expect, it, vi } from 'vitest'

const CONFIG_PATH = '/tmp/openclaw.json'

type LoadOptions = {
  docker?: boolean
  gatewayHost?: string
  openclawConfig?: string | null
  execMap?: Array<[needle: string, output: string]>
}

const originalEnv = { ...process.env }

async function loadSecurityScan(options: LoadOptions = {}) {
  vi.resetModules()

  const docker = options.docker ?? false
  const gatewayHost = options.gatewayHost ?? '127.0.0.1'
  const openclawConfig = options.openclawConfig ?? null
  const execMap = options.execMap ?? []

  vi.doMock('node:fs', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:fs')>()
    const mocked = {
      ...actual,
      existsSync: (target: string) => {
        if (target === '/.dockerenv') return docker
        if (target === CONFIG_PATH) return openclawConfig !== null
        return false
      },
      readFileSync: (target: string) => {
        if (target === CONFIG_PATH && openclawConfig !== null) return openclawConfig
        throw new Error(`Unexpected readFileSync: ${target}`)
      },
      statSync: () => ({
        mode: 0o100600,
        mtimeMs: Date.now(),
      }),
      readdirSync: () => [],
    }
    return {
      ...mocked,
      default: mocked,
    }
  })

  vi.doMock('node:child_process', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:child_process')>()
    const mocked = {
      ...actual,
      execSync: (cmd: string) => {
        for (const [needle, output] of execMap) {
          if (cmd.includes(needle)) return output
        }
        throw new Error(`Unhandled execSync: ${cmd}`)
      },
    }
    return {
      ...mocked,
      default: mocked,
    }
  })

  vi.doMock('@/lib/config', () => ({
    config: {
      openclawConfigPath: CONFIG_PATH,
      gatewayHost,
      gatewayPort: 18789,
      dbPath: '/tmp/mission-control.db',
      retention: {
        activities: 90,
        auditLog: 365,
        logs: 30,
        notifications: 60,
        pipelineRuns: 90,
        tokenUsage: 90,
        gatewaySessions: 90,
      },
    },
  }))

  vi.doMock('@/lib/db', () => ({
    getDatabase: () => ({
      prepare: () => ({
        get: () => ({ integrity_check: 'ok' }),
      }),
    }),
  }))

  vi.doMock('@/lib/injection-guard', () => ({}))

  return import('@/lib/security-scan')
}

describe('runSecurityScan', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.resetModules()
    process.env = { ...originalEnv }
  })

  it('accepts JSON5-style OpenClaw configs', async () => {
    process.env.AUTH_PASS = 'averysecurepassword'
    process.env.API_KEY = 'a'.repeat(64)
    process.env.MC_ALLOWED_HOSTS = 'localhost,127.0.0.1'
    process.env.MC_ENABLE_HSTS = '1'
    process.env.MC_COOKIE_SECURE = '1'

    const { runSecurityScan } = await loadSecurityScan({
      openclawConfig: `{
        // OpenClaw uses JSON5-style config files
        "gateway": {
          "bind": "loopback",
          "auth": {
            "mode": "token",
            "token": "secret-token",
          },
        },
        "session": {
          "dmScope": "per-channel-peer",
        },
        "tools": {
          "profile": "coding",
          "exec": {
            "security": "sandbox",
          },
          "fs": {
            "workspaceOnly": true,
          },
        },
        "logging": {
          "redactSensitive": "tools",
        },
        "elevated": {
          "enabled": false,
        },
      }`,
      execMap: [
        ['getcap $(which node)', ''],
        ['find "', ''],
        ['ss -tlnp', '0'],
        ['timedatectl status', 'System clock synchronized: yes'],
        ['ufw status', 'Status: active'],
        ['iptables -L -n', '16'],
        ['nft list ruleset', '1'],
        ['lsblk -o TYPE', '1'],
        ['cat /proc/sys/kernel/randomize_va_space', 'aslr=2\ncore_pattern=|/bin/false\nsyn_cookies=1'],
        ['cat /sys/fs/selinux/enforce', '1'],
        ['aa-status --enabled', '0'],
        ['systemctl is-active fail2ban', 'active'],
        ['mount 2>/dev/null | grep " /tmp "', 'tmpfs on /tmp type tmpfs (rw,noexec)'],
      ],
    })

    const scan = runSecurityScan()
    const configValid = scan.categories.openclaw.checks.find((check) => check.id === 'config_valid')

    expect(configValid?.status).toBe('pass')
    expect(configValid?.detail).toContain('parsed successfully')
  })

  it('keeps Docker host-only checks out of the score', async () => {
    process.env.AUTH_PASS = 'averysecurepassword'
    process.env.API_KEY = 'a'.repeat(64)
    process.env.MC_ALLOWED_HOSTS = 'mc.heavisidetechnology.com,100.77.226.26,100.*'
    process.env.MC_ENABLE_HSTS = '1'
    process.env.MC_COOKIE_SECURE = '1'

    vi.spyOn(os, 'uptime').mockReturnValue(6 * 86400)

    const { runSecurityScan } = await loadSecurityScan({
      docker: true,
      gatewayHost: 'host.docker.internal',
      execMap: [
        ['getcap $(which node)', ''],
        ['timedatectl status', ''],
        ['ufw status', ''],
        ['iptables -L -n', '0'],
        ['nft list ruleset', '0'],
        ['ss -tlnp', '0'],
        ['lsblk -o TYPE', '0'],
        ['find "', ''],
        ['cat /proc/sys/kernel/randomize_va_space', 'aslr=2\ncore_pattern=|/bin/false\nsyn_cookies=1'],
        ['cat /sys/fs/selinux/enforce', ''],
        ['aa-status --enabled', '1'],
        ['systemctl is-active fail2ban', ''],
        ['mount 2>/dev/null | grep " /tmp "', 'tmpfs on /tmp type tmpfs (rw,noexec)'],
      ],
    })

    const scan = runSecurityScan()
    const firewall = scan.categories.os.checks.find((check) => check.id === 'firewall')
    const ntp = scan.categories.os.checks.find((check) => check.id === 'ntp_sync')
    const gatewayLocal = scan.categories.network.checks.find((check) => check.id === 'gateway_local')

    expect(firewall?.status).toBe('warn')
    expect(firewall?.affectsScore).toBe(false)
    expect(ntp?.affectsScore).toBe(false)
    expect(gatewayLocal?.status).toBe('warn')
    expect(gatewayLocal?.affectsScore).toBe(false)
    expect(scan.categories.os.score).toBe(100)
    expect(scan.categories.network.score).toBe(100)
  })
})
