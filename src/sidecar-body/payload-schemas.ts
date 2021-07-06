export interface SidecarBodyEventPayloadLog {
  type    : 'log'
  payload : {
    level   : string,
    message : string,
    prefix  : string,
  }
}

export interface SidecarBodyEventPayloadHook {
  type    : 'hook',
  payload : {
    method : string,
    args: {
      [k: string]: null | string | number
    },
    // data?: null | Buffer,
  }
}

export type SidecarBodyEventPayload = SidecarBodyEventPayloadHook
                                    | SidecarBodyEventPayloadLog

export type SidecarBodyEventType = SidecarBodyEventPayload['type']

const isSidecarBodyEventPayloadLog = (
  payload: SidecarBodyEventPayload
): payload is SidecarBodyEventPayloadLog => payload.type === 'log'

const isSidecarBodyEventPayloadHook = (
  payload: SidecarBodyEventPayload
): payload is SidecarBodyEventPayloadHook => payload.type === 'hook'

export {
  isSidecarBodyEventPayloadHook,
  isSidecarBodyEventPayloadLog,
}
