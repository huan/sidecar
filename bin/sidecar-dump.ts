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
import {
  binary,
  run,
  subcommands,
}                 from 'cmd-ts'

import { VERSION } from '../src/version'

import {
  view,
  meta,
}         from '../src/dump/mod'

// import { sidecarMetadata } from '../src/decorators/sidecar/sidecar-metadata'

/* eslint-disable sort-keys */

const sidecarDump = subcommands({
  name: 'sidecar-dump',
  description: 'Sidecar dumping utility',
  version: VERSION,
  cmds: {
    view,
    meta,
  },
})

run(
  binary(sidecarDump),
  process.argv,
).catch(console.error)
