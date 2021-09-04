import vm from 'vm'

/**
 * importModuleDynamically for vm module is cached #36351
 *  https://github.com/nodejs/node/issues/36351
 */
declare module 'vm' {
  export interface SourceTextModuleOptions {
    importModuleDynamically: (
      specifier: string,
      module?: any,
    ) => any
    context?: vm.Context
  }

  export type Linker = (
    specifier: string,
    extra: Object,
    referencingModule: any,
  ) => any

  export class SourceTextModule {

    constructor (
      code: string,
      options?: SourceTextModuleOptions,
    )

    link (linker: Linker): Promise<void>
    evaluate (): Promise<void>

  }
}

export { vm }
export default vm
