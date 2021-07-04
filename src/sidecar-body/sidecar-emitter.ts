import { EventEmitter } from 'stream'
import TypedEventEmitter  from 'typed-emitter'

import {
  HookEventPayload,
}                     from '../schema'

export type AttachedEventListener = () => void
export type DetachedEventListener = () => void
export type InitedEventListener   = () => void

export type HookEventListener = (payload: HookEventPayload) => void

interface SidecarEvents {
  attached : AttachedEventListener
  detached : DetachedEventListener
  error    : Error
  hook     : HookEventListener
  inited   : InitedEventListener
}

type SidecarEmitterType = new () => TypedEventEmitter<
  SidecarEvents
>
const SidecarEmitter = EventEmitter as SidecarEmitterType

export { SidecarEmitter }
