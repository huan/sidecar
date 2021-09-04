/* eslint-disable sort-keys */
import slash      from 'slash'
import { pathToFileURL } from 'url'

import { log }    from '../config.js'
import vm         from './vm.js'

import { getMetadataSidecar }   from '../decorators/sidecar/metadata-sidecar.js'
import { buildAgentSource }     from '../agent/build-agent-source.js'

import { extractClassNameList } from './extract-class-names.js'

const sourceHandler = async ({
  file,
  name,
}: {
  file: string,
  name?: string,
}): Promise<string> => {
  console.info('slash:', slash(file))
  console.info('pathToFileURL:', pathToFileURL(file).href)
  file = slash(file)
  // file = pathToFileURL(file).href

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

  const context = vm.createContext({
    buildAgentSource,
    console,
    generated: undefined,
    getMetadataSidecar,
  }) as {
    generated?: string,
  }

  const code = [
    `const { ${name} } = await import('${file}')`,
    `const metadata = getMetadataSidecar(${name})`,
    'generated = await buildAgentSource(metadata)',
  ].join('\n')

  log.silly('sidecar-dump <source>', code)

  const importModuleDynamically = (
    identifier: string
  ) => import(identifier)

  const module = new vm.SourceTextModule(code, {
    context,
    importModuleDynamically,
  })

  await module.link(() => {})
  await module.evaluate()

  if (!context.generated) {
    throw new Error('no context.generated found')
  }

  return context.generated
}

export { sourceHandler }
