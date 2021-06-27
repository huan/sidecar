/**
 * Huan(202106) see:
 *  http://blog.wolksoftware.com/decorators-metadata-reflection-in-typescript-from-novice-to-expert-part-4
 *
 * TypeScript Decorators Examples
 *  https://gist.github.com/remojansen/16c661a7afd68e22ac6e
 *
 * TypeScript Decorators: Parameter Decorators
 *  https://blog.wotw.pro/typescript-decorators-parameter-decorators/
 */
import 'reflect-metadata'

function decorateProperty (target : any, key : string) {
  console.log('decorateProperty')
  const t = Reflect.getMetadata('design:type', target, key)
  console.log(`${key} type: ${t.name}`)
  console.log('t:', t)
}

function decorateMethod (target : any, key : string) {
  console.log('decorateMethod')
  const types = Reflect.getMetadata('design:paramtypes', target, key)
  const s = types.map((a: any) => a.name).join()
  console.log(`${key} param types: ${s}`)
  // const s2 = types.map((a: any) => a).join()
  // console.log(`${key} param types2: ${s2}`)

  const r = Reflect.getMetadata('design:returntype', target, key)
  console.log(`${key} return type: ${r.name}`)
}

function decorateParam (
  target: Object,
  propertyKey: string,
  parameterIndex: number,
) {
  console.log('decorateParam')
  void target
  void propertyKey
  void parameterIndex
}

function decorateClass <
  T extends {
    new (...args: any[]): {},
  }
> (
  constructor:T,
) {
  void constructor
  console.log('decorateClass')
}

@decorateClass
class Demo {

  @decorateProperty // apply property decorator
  public attr1: Demo

  constructor () {
    this.attr1 = {} as any
  }

  @decorateMethod // apply parameter decorator
  doSomething (
    @decorateParam param1 : string,
      param2 : number,
      // param3 : Foo,
      param4 : { test : string },
      // param5 : InterfaceFoo,
      param6 : Function,
      param7 : (a : number) => void,
  ) : number {
    void param1
    void param2
    // void param3
    void param4
    // void param5
    void param6
    void param7
    return 1
  }

}

void Demo
void decoratorFactory

function decoratorFactory (this: any, ...args : any[]) {
  switch (args.length) {
    case 1:
      return decorateClass.apply(this, args)
    case 2:
      return decorateProperty.apply(this, args)
    case 3:
      if (typeof args[2] === 'number') {
        return decorateParam.apply(this, args)
      }
      return decorateMethod.apply(this, args)
    default:
      throw new Error()
  }
}
