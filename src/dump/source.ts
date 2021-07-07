/* eslint-disable sort-keys */
import vm from 'vm'
import path from 'path'

import {
  command,
  option,
  optional,
  positional,
  string,
}                 from 'cmd-ts'
import { File }   from 'cmd-ts/dist/cjs/batteries/fs'
import slash      from 'slash'

import { log }    from '../config'

import { getMetadataSidecar }   from '../decorators/sidecar/metadata-sidecar'
import { buildAgentSource }     from '../agent/build-agent-source'

import { extractClassNameList } from './extract-class-names'

const source = command({
  name: 'source',
  description: 'Dump sidecar agent source',
  args: {
    file: positional({
      type        : File,
      displayName : 'classFile',
      description : 'The file contains the sidecar class',
    }),
    name: option({
      description: 'The name of class that decorated by @Sidecar',
      long: 'name',
      short: 'n',
      type: optional(string),
    }),
  },
  handler: async ({
    file,
    name,
  }) => {
    file = slash(file)
    log.verbose('sidecar-dump <source>',
      'file<%s>, name<%s>',
      file,
      name || '',
    )
    /**
     * Check the class name parameter
     */
    if (!name) {
      const classNameList = await extractClassNameList(file)
      if (classNameList.length === 0) {
        throw new Error(`There's no @Sidecar decorated class name found in file ${file}`)
      } else if (classNameList.length > 1) {
        console.error(`Found multiple @Sidecar decorated classes in ${file}, please specify the class name by --name:\n`)
        console.error(classNameList.map(x => '  ' + x).join('\n'))
        return
      }
      name = classNameList[0]
    }

    const context = {
      agentSource: undefined,
      buildAgentSource,
      getMetadataSidecar,
      require,

      __filename : file,
      __dirname  : path.dirname(require.resolve(file)),
    }
    vm.createContext(context) // Contextify the object

    const source = [
      `const { ${name} } = require('${file}')`,
      `const metadata = getMetadataSidecar(${name})`,
      'buildAgentSource(metadata).then(source => agentSource = source)',
    ].join('\n')
    log.silly('sidecar-dump <source>', source)

    vm.runInContext(source, context)

    /**
     * Wait to the next event loop
     *  so that the Promise inside the VM can be executed
     */
    await new Promise(setImmediate)

    console.log(context.agentSource)
  },
})

export { source }
