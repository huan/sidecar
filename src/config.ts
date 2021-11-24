/// <reference path="./frida-agent.d.ts" />
import 'reflect-metadata'

import { log } from 'brolog'
import { wrapAsyncError } from 'gerror'

const wrapAsync = wrapAsyncError(e => log.error('Sidecar', 'wrapAsyncError: %s\n%s', e.message, e.stack))

export {
  log,
  wrapAsync,
}
