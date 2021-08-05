#!/usr/bin/env node
import { spawnSync } from 'child_process'
import path from 'path'

function needInstall () {
  try {
    require('frida')
    return false
  } catch (_) {
    return true
  }
}

async function main () {
  if (needInstall()) {
    console.error('Sidecar: checking frida installation (frida_binding.node) failed, try to reinstall with cdn mirror...')

    const env = {
      ...process.env,
      npm_config_frida_binary_host_mirror: 'https://cdn.chatie.io/mirrors/github.com/frida/frida/releases/download',
    }
    const cwd = path.resolve('node_modules/frida')

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
}

main()
  .catch(console.error)
