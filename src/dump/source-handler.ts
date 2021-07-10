/* eslint-disable sort-keys */
import vm from 'vm'
import path from 'path'

import slash      from 'slash'

import { log }    from '../config'

import { getMetadataSidecar }   from '../decorators/sidecar/metadata-sidecar'
import { buildAgentSource }     from '../agent/build-agent-source'

import { extractClassNameList } from './extract-class-names'

const sourceHandler = async ({
  file,
  name,
}: {
  file: string,
  name?: string,
}): Promise<string> => {
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
      /**
       * return empty string when error
       */
      return ''
    }
    name = classNameList[0]
    log.silly('sidecar-dump <source>',
      'detected class name: "%s"',
      name,
    )
  }

  const context = {
    buildAgentSource,
    getMetadataSidecar,
    require,

    __filename : file,
    __dirname  : path.dirname(require.resolve(file)),
  }

  const code = [
    '(async () => {',
    [
      `const { ${name} } = require('${file}')`,
      `const metadata = getMetadataSidecar(${name})`,
      'const output = await buildAgentSource(metadata)',
      'return output',
    ].join('\n'),
    '})()',
  ].join('\n')
  log.silly('sidecar-dump <source>', code)

  const script = new vm.Script(code)
  const generatedCode = await script.runInNewContext(context)

  return generatedCode
}

export { sourceHandler }
