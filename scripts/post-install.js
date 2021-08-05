#!/usr/bin/env node
const { spawnSync } = require('child_process')
const path          = require('path')
const fs            = require('fs')
const pkgDir        = require('pkg-dir')

function needInstall () {
  try {
    require('frida')
    return false
  } catch (_) {
    return true
  }
}

async function reinstall () {
  console.error('Sidecar: checking frida installation (frida_binding.node) failed, try to reinstall with cdn mirror...')

  const pkgRoot = await pkgDir(__dirname)
  if (!pkgRoot) {
    throw new Error('no package.json found')
  }

  const innerCwd = path.resolve(pkgRoot, 'node_modules/frida')
  const outerCwd = path.resolve(pkgRoot, '../frida')

  const cwd = fs.existsSync(innerCwd) ? innerCwd
    : fs.existsSync(outerCwd) ? outerCwd
      : undefined

  if (!cwd) {
    throw new Error('can not find "node_modules/frida"')
  }

  const args = [
    'prebuild-install',
    '--tag-prefix',
    '',
  ]

  const env = {
    ...process.env,
    npm_config_frida_binary_host_mirror: 'https://cdn.chatie.io/mirrors/github.com/frida/frida/releases/download',
  }

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
    const message = ret.error || ret.stdout.toString() || ret.stderr.toString()
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
