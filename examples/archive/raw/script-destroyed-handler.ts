import type { ScriptDestroyedHandler } from './frida.js'
import { log } from 'brolog'

const scriptDestroyedHandler: ScriptDestroyedHandler = () => {
  log.verbose('Sidecar', 'scriptDestroyedHandler()')
}

export { scriptDestroyedHandler }
