import { ChatboxSidecar } from './chatbox-sidecar'

async function main () {
  const sidecar = new ChatboxSidecar()
  sidecar.on('hook', payload => {
    console.log(payload)
  })

  setInterval(() => sidecar.mo('Hello from setInterval'), 3000)
}

main()
  .catch(console.error)
