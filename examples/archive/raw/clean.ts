import type {
  Session,
  Script,
}           from './frida.js'
import { log } from 'brolog'

function clean (
  session: Session,
  script: Script,
): void {
  log.verbose('Sidecar', 'clean()')

  script.unload().catch(console.error)
  session.detach().catch(console.error)
}

export { clean }
