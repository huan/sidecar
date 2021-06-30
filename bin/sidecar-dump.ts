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
  command,
  number,
  option,
  positional,
  run,
  string,
  subcommands,
}                 from 'cmd-ts'
import { File }   from 'cmd-ts/dist/cjs/batteries/fs'

import vm from 'vm'
import fs from 'fs'

import { VERSION } from '../src/version'

import { sidecarView } from '../src/frida-agent/sidecar-view'
// import { sidecarMetadata } from '../src/decorators/sidecar/sidecar-metadata'

import ts from 'typescript'

/**
 * https://stackoverflow.com/a/28731918/1123955
 */
const loadTsSource = async (file: string): Promise<string> => {
  const source = await (await fs.promises.readFile(file)).toString()
  const result = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
    },
  })
  return result.outputText // var x = 'hello world';
}

/* eslint-disable sort-keys */

const view = command({
  name: 'view',
  description: 'Sidecar dumping view',
  args: {
    file: positional({ type: File, displayName: 'decorated class file' }),
  },
  handler: async ({ file }) => {
    const source = await loadTsSource(file)
    console.log(source)

    const context = {
      sidecarView,
      view: undefined,
      exports: {},
      require,
    }
    vm.createContext(context) // Contextify the object
    vm.runInContext(`const { Klass } = ${source}`, context)

    vm.runInContext('view = sidecarView(Klass)', context)

    console.log(context.view)
  },
})

const meta = command({
  name: 'metadata',
  description: 'Sidecar dumping metadata',
  args: {
    file: positional({ type: File, displayName: 'decorated class file' }),
    name: option({ type: string, long: 'name' }),
    age: option({ type: number, long: 'age' }),

  },
  handler: (args) => {
    console.log('meta: ', args.file, args.name, args.age)
  },
})

const dump = subcommands({
  name: 'sidecar-dump',
  description: 'Sidecar dumping utility',
  version: VERSION,
  cmds: {
    view,
    meta,
  },
})

run(
  binary(dump),
  process.argv,
).catch(console.error)
