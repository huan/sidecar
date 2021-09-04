#!/usr/bin/env node --experimental-vm-modules
/**
 * https://github.com/huan/sidecar
 *
 * Author: Huan <zixia@zixia.net>
 * License: Apache-2.0
 *
 * CLI Apps in TypeScript with `cmd-ts` (Part 1)
 *  Using `cmd-ts` to easily build a type-safe TypeScript CLI app
 *
 *  https://gal.hagever.com/posts/type-safe-cli-apps-in-typescript-with-cmd-ts-part-1/
 */
/* eslint-disable sort-keys */
import {
  binary,
  run,
  subcommands,
}                     from 'cmd-ts'
// import {
//   REGISTER_INSTANCE,
// }                     from 'ts-node'

import { VERSION }  from '../src/version.js'
// import { log }      from '../src/config.js'

import {
  metadata,
  source,
}               from '../src/dump/mod.js'

/**
 * Check ts-node loaded or not
 *  See: https://github.com/TypeStrong/ts-node/blob/5643ad64cf39ee0dfa2a9323e8d1dd9f400e5884/src/index.ts#L54-L68
 *
 * Update:
 *  - Huan(202109): We enable ESM
 */
// if (!process[REGISTER_INSTANCE]) {
//   log.verbose('sidecar-dump', 'Loading `ts-node/register`...')
//   require('ts-node/register')
// }

const sidecarDump = subcommands({
  name: 'sidecar-dump',
  description: 'Sidecar utility for dumping metadata/source for a sidecar class',
  version: VERSION,
  cmds: {
    metadata,
    source,
  },
})

run(
  binary(sidecarDump),
  process.argv,
).catch(console.error)
