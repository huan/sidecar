import {
  attach,
  detach,
}           from '../src/mod'

import { ChatboxSidecar } from './chatbox-sidecar'

async function main () {
  const sidecar = new ChatboxSidecar()
  await attach(sidecar)

  sidecar.on('hook', payload => {
    console.log(payload)
  })
  await sidecar.mo('Hello from Sidecar')

  /**
   * Call sidecar.mo(...) periodly
   */
  const timer = setInterval(() => sidecar.mo('Hello from Sidecar setInterval'), 5 * 1000)

  /**
   * detach after 10 seconds.
   */
  setTimeout(async () => {
    clearInterval(timer)
    await detach(sidecar)
  }, 10 * 1000)

}

main()
  .catch(console.error)
