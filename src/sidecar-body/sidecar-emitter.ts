import { EventEmitter } from 'stream'
import TypedEventEmitter  from 'typed-emitter'

import {
  HookEventPayload,
}                     from '../schema'

export type HookEventListener = (payload: HookEventPayload) => void
export type DestroyEventListener = () => void

interface SidecarEvents {
  destroy : DestroyEventListener
  error   : Error
  hook    : HookEventListener
}

type SidecarEmitterType = new () => TypedEventEmitter<
  SidecarEvents
>
const SidecarEmitter = EventEmitter as SidecarEmitterType

export { SidecarEmitter }
