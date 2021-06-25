import { EventEmitter } from 'stream'
import TypedEventEmitter  from 'typed-emitter'

import { HookEventPayload } from './schema'

export type HookEventListener = (payload: HookEventPayload) => void

interface SidecarEvents {
  hook: HookEventListener
}

type SidecarEmitterType = new () => TypedEventEmitter<
  SidecarEvents
>
const SidecarEmitter = EventEmitter as SidecarEmitterType

class SidecarBody extends SidecarEmitter {

}

export { SidecarBody }
