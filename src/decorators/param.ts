import {
  NativeType,
  PointerType,
}               from '../frida'

const Param = (
  nativeType: NativeType,
  ...pointerChain: (undefined | PointerType)[]
) => (
  target: Object,
  propertyKey: string | symbol,
  parameterIndex: number,
) => {
  console.log(nativeType, pointerChain)
  const types = Reflect.getMetadata('design:paramtypes', target, key)
  const s = types.map((a: any) => a.name).join()
  console.log(`${key} param types: ${s}`)
  // const s2 = types.map((a: any) => a).join()
  // console.log(`${key} param types2: ${s2}`)

  const r = Reflect.getMetadata('design:returntype', target, key)
  console.log(`${key} return type: ${r.name}`)
}

export { Param }
