import {
  log,
}                         from '../../config'
import { RET_SYMBOL }     from '../../ret'
import { SidecarBody }    from '../../sidecar-body'
import { CALL_RET_ERROR } from './constants'

function updateRpcDescriptor (
  target      : any,
  propertyKey : string,
  descriptor  : PropertyDescriptor,
): PropertyDescriptor {
  log.verbose('Sidecar',
    'updateRpcDescriptor(%s, %s, descriptor)',
    target.constructor.name,
    propertyKey,
  )

  descriptor.value().then((result: any) => {
    /**
     * FIXME: Huan(202006)
     *  check Ret value and deal the error more gentle
     */
    if (result !== RET_SYMBOL) {
      throw new Error(`The ${target.constructor.name}.${propertyKey}(...) must be defined to return the Ret() value to make Sidecar @Call happy.`)
    }
    return result
  }).catch((e: Error) => {
    target[CALL_RET_ERROR] = e
    console.error(e)
  })

  async function proxyMethod (
    this: SidecarBody,
    ...args: any[]
  ) {
    // // https://github.com/huan/clone-class/blob/master/src/instance-to-class.ts
    // const klass = (this.constructor.name as any as typeof SidecarBody)

    // console.log('target:', target)
    // console.log('target.name:', target.name)
    // console.log('target.constructor.name:', target.constructor.name)

    log.verbose(
      `${target.constructor.name}`,
      `${propertyKey}(%s)`,
      args.join(', '),
    )
    // console.log('this:', this)
    return this.script!.exports[propertyKey](...args)
  }

  /**
   * Update the method
   */
  descriptor.value = proxyMethod
  return descriptor
}

export { updateRpcDescriptor }
