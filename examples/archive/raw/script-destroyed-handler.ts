import { ScriptDestroyedHandler } from './frida'
import { log } from 'brolog'

const scriptDestroyedHandler: ScriptDestroyedHandler = () => {
  log.verbose('Sidecar', 'scriptDestroyedHandler()')
}

export { scriptDestroyedHandler }
