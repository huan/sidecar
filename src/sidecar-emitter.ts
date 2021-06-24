import { EventEmitter } from 'stream'
import TypedEventEmitter  from 'typed-emitter'

import { HookPayload } from './schema'

export type HookListener = (payload: HookPayload) => void

interface SidecarEvents {
  hook: HookListener
}

type SidecarEmitterType = new () => TypedEventEmitter<
  SidecarEvents
>

const SidecarEmitter = EventEmitter as SidecarEmitterType

export { SidecarEmitter }
