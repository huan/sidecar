import vm from 'vm'
import path from 'path'

import {
  command,
  positional,
}                 from 'cmd-ts'
import { File }   from 'cmd-ts/dist/cjs/batteries/fs'

import { getMetadataSidecar } from '../decorators/sidecar/metadata-sidecar'
import { buildAgentSource } from '../agent/build-agent-source'

// import { bundleTsFile } from './bundle-ts-file'

/* eslint-disable sort-keys */

const agentSource = command({
  name: 'agent-source',
  description: 'Dump sidecar agent source',
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
      buildAgentSource,
      agentSource: undefined,
      exports: {},
      require,
      module,

      __filename: file,
      __dirname: path.dirname(require.resolve(file)),
    }
    vm.createContext(context) // Contextify the object
    // vm.runInContext("require('ts-node/register')", context)

    const source = `
      const { ChatboxSidecar } = require('${file}')
      const metadata = getMetadataSidecar(ChatboxSidecar)
      buildAgentSource(metadata).then(source => agentSource = source)
    `

    vm.runInContext(source, context)

    // vm.runInContext(`const { Klass } = ${source}`, context)

    // vm.runInContext('metadata = JSON.stringify(getMetadataSidecar(ChatboxSidecar), null, 2)', context)
    // vm.runInContext('view = sidecarView(sidecarMetadata(ChatboxSidecar))', context)
    // vm.runInContext('console.log("metadata:", metadata)', context)
    // vm.runInContext('console.log("######################")', context)
    // console.log(4)

    // console.log('Sidecar file: ', file)
    await new Promise(setImmediate)
    console.log(context.agentSource)
  },
})

export { agentSource }
