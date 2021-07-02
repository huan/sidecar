import vm from 'vm'
import path from 'path'

import {
  command,
  positional,
}                 from 'cmd-ts'
import { File }   from 'cmd-ts/dist/cjs/batteries/fs'

import { sidecarView } from '../frida-agent/sidecar-view'
import { sidecarMetadata } from '../decorators/sidecar/sidecar-metadata'

// import { bundleTsFile } from './bundle-ts-file'

/* eslint-disable sort-keys */

const view = command({
  name: 'view',
  description: 'Dump sidecar view data',
  args: {
    file: positional({
      type        : File,
      displayName : 'decorated class file',
    }),
  },
  handler: async ({ file }) => {
    // const source = await bundleTsFile(file)
    // console.log(source)
    const context = {
      sidecarView,
      sidecarMetadata,
      view: undefined,
      exports: {},
      require,
      module,

      __filename: file,
      __dirname: path.dirname(require.resolve(file)),
    }
    vm.createContext(context) // Contextify the object
    console.log(1)
    vm.runInContext("require('ts-node/register')", context)
    console.log(2, file)
    vm.runInContext(`const { ChatboxSidecar } = require('${file}')`, context)
    console.log(3)

    // vm.runInContext(`const { Klass } = ${source}`, context)

    vm.runInContext('view = sidecarMetadata(ChatboxSidecar)', context)
    // vm.runInContext('view = sidecarView(sidecarMetadata(ChatboxSidecar))', context)
    vm.runInContext('console.log("view:", view)', context)
    vm.runInContext('console.log("######################")', context)
    console.log(4)

    console.log('out view:', context.view)
  },
})

export { view }
