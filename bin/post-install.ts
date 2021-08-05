#!/usr/bin/env node
import { spawnSync } from 'child_process'
import path from 'path'
import fs from 'fs'
import pkgUp from 'pkg-up'

function needInstall () {
  try {
    require('frida')
    return false
  } catch (_) {
    return true
  }
}

async function reinstall (): Promise<void> {
  console.error('Sidecar: checking frida installation (frida_binding.node) failed, try to reinstall with cdn mirror...')

  const env = {
    ...process.env,
    npm_config_frida_binary_host_mirror: 'https://cdn.chatie.io/mirrors/github.com/frida/frida/releases/download',
  }

  const pkgRoot = await pkgUp()
  if (!pkgRoot) {
    throw new Error('no package.json found')
  }

  const cwdCurrent  = path.resolve(pkgRoot, 'node_modules/frida')
  const cwdParent   = path.resolve(pkgRoot, '../node_modules/frida')

  const cwd = fs.existsSync(cwdCurrent)
    ? cwdCurrent
    : cwdParent

  const args = [
    'prebuild-install',
    '--tag-prefix',
    '',
  ]

  const ret = await spawnSync(
    'npx',
    [...args],
    {
      cwd,
      env,
    },
  )

  // console.log(ret)
  if (ret.status === 0) {
    console.log('Sidecar: install frida_binding.node successed.')
  } else {
    const message = ret.error || ret.stdout?.toString() || ret.stderr?.toString()
    console.error('Sidecar: install failed:', message)
  }
}

async function main () {
  if (needInstall()) {
    await reinstall()
  }
}

main()
  .catch(console.error)
