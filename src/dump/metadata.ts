import vm from 'vm'
import path from 'path'

import {
  command,
  positional,
}                 from 'cmd-ts'
import { File }   from 'cmd-ts/dist/cjs/batteries/fs'

import { getMetadataSidecar } from '../decorators/sidecar/metadata-sidecar'

// import { bundleTsFile } from './bundle-ts-file'

/* eslint-disable sort-keys */

const metadata = command({
  name: 'metadata',
  description: 'Dump sidecar metadata',
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
      getMetadataSidecar,
      metadata: undefined,
      exports: {},
      require,
      module,

      __filename: file,
      __dirname: path.dirname(require.resolve(file)),
    }
    vm.createContext(context) // Contextify the object
    // console.log(1)
    // vm.runInContext("require('ts-node/register')", context)
    // console.log(2, file)
    vm.runInContext(`const { ChatboxSidecar } = require('${file}')`, context)
    // console.log(3)

    // vm.runInContext(`const { Klass } = ${source}`, context)

    vm.runInContext('metadata = JSON.stringify(getMetadataSidecar(ChatboxSidecar), null, 2)', context)
    // vm.runInContext('view = sidecarView(sidecarMetadata(ChatboxSidecar))', context)
    // vm.runInContext('console.log("metadata:", metadata)', context)
    // vm.runInContext('console.log("######################")', context)
    // console.log(4)

    // console.log('Sidecar file: ', file)
    console.log(context.metadata)
  },
})

export { metadata }
