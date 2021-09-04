/* eslint-disable sort-keys */
// import slash      from 'slash'
import { pathToFileURL } from 'url'

import { log }    from '../config.js'

import { getMetadataSidecar }   from '../decorators/sidecar/metadata-sidecar.js'
import { extractClassNameList } from './extract-class-names.js'
import vm from './vm.js'

const metadataHandler = async ({
  file,
  name,
}: {
  file: string,
  name?: string,
}): Promise<string> => {
  file = pathToFileURL(file).href  // convert windows path to posix
  log.verbose('sidecar-dump <metadata>',
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
  }

  const context = vm.createContext({
    console,
    getMetadataSidecar,
    metadata: undefined,
  }) as {
    metadata?: string,
  }

  const code = [
    `const { ${name} } = await import('${file}')`,
    `metadata = JSON.stringify(getMetadataSidecar(${name}), null, 2)`,
  ].join('\n')
  log.silly('sidecar-dump <metadata>', code)

  const importModuleDynamically = (
    identifier: string
  ) => import(identifier)

  const module = new vm.SourceTextModule(code, {
    context,
    importModuleDynamically,
  })

  await module.link(() => {})
  await module.evaluate()

  if (!context.metadata) {
    throw new Error('no context.metadata found')
  }

  return context.metadata
}

export { metadataHandler }
