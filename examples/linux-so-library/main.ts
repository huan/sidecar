import assert from 'assert'

import {
  attach,
  detach,
}           from '../../src/mod'

import { FactorialSidecar } from './factorial-sidecar'

async function main () {
  const sidecar = new FactorialSidecar()
  await attach(sidecar)

  const ret = await sidecar.factorial(3)
  assert(typeof ret === 'number', 'factorial() returns type `number`')
  assert(ret === 6, 'factorial(3)=6')
  console.log('factorial(3)=' + ret)

  await new Promise((resolve) => setTimeout(resolve, 3000))
  void detach
  void assert
  // await detach(sidecar)
}

main()
.catch(console.error)
