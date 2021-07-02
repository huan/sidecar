import { log } from 'brolog'

import { MessagingSidecar } from './messaging-sidecar'

log.level('verbose')

async function main () {
  const sidecar = new MessagingSidecar()

  process.on('SIGINT',  () => sidecar.stop().catch(console.error))
  process.on('SIGTERM', () => sidecar.stop().catch(console.error))

  await sidecar.init()
  await sidecar.start()

  sidecar.on('hook', payload => {
    console.log('MessagingSidecar event[hook]:', payload)
  })

  await sidecar.mo('hello from MessagingSidecar!')
}

main()
  .catch(console.error)
