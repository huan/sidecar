/**
 * Huan(202106) see:
 *  http://blog.wolksoftware.com/decorators-metadata-reflection-in-typescript-from-novice-to-expert-part-4
 */
import 'reflect-metadata'

function logType (target : any, key : string) {
  const t = Reflect.getMetadata('design:type', target, key)
  console.log(`${key} type: ${t.name}`)
  console.log('t:', t)
}

// ///////////////////

class Foo {}
interface InterfaceFoo {}

function logParamTypes (target : any, key : string) {
  const types = Reflect.getMetadata('design:paramtypes', target, key)
  const s = types.map((a: any) => a.name).join()
  console.log(`${key} param types: ${s}`)
  // const s2 = types.map((a: any) => a).join()
  // console.log(`${key} param types2: ${s2}`)

  const r = Reflect.getMetadata('design:returntype', target, key)
  console.log(`${key} return type: ${r.name}`)
}

class Demo {

  @logType // apply property decorator
  public attr1: Demo

  constructor () {
    this.attr1 = {} as any
  }

  @logParamTypes // apply parameter decorator
  doSomething (
    param1 : string,
    param2 : number,
    param3 : Foo,
    param4 : { test : string },
    param5 : InterfaceFoo,
    param6 : Function,
    param7 : (a : number) => void,
  ) : number {
    void param1
    void param2
    void param3
    void param4
    void param5
    void param6
    void param7
    return 1
  }

}

void Demo
