/**
 * Data Type:
 *  https://en.wikipedia.org/wiki/Data_type
 *
 * TypeScript Decorators: Parameter Decorators
 *  https://blog.wizardsoftheweb.pro/typescript-decorators-parameter-decorators/
 */
import {
  NativeType,
  PointerType,
}               from '../frida'

/**
 *
 * @param nativeType
 * @param pointerTypeList
 * @returns
 */
const Type = (
  nativeType: NativeType,
  ...pointerTypeList: (undefined | PointerType)[]
) => (
  target: Object,
  propertyKey: string | symbol,
  parameterIndex: number,
) => {
  console.log(nativeType, pointerTypeList)
  const types = Reflect.getMetadata('design:paramtypes', target, key)
  const s = types.map((a: any) => a.name).join()
  console.log(`${key} param types: ${s}`)
  // const s2 = types.map((a: any) => a).join()
  // console.log(`${key} param types2: ${s2}`)

  const r = Reflect.getMetadata('design:returntype', target, key)
  console.log(`${key} return type: ${r.name}`)
}

export { Type }
