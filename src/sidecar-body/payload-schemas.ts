export interface SidecarBodyEventPayloadLog {
  type    : 'log',
  payload : string,
}

export interface SidecarBodyEventPayloadHook {
  type    : 'hook',
  payload : {
    method : string,
    args: {
      [k: string]: null | string | number
    },
    data?: null | Buffer,
  }
}

export type SidecarBodyEventPayload = SidecarBodyEventPayloadHook
                                    | SidecarBodyEventPayloadLog

export type SidecarBodyEventType = SidecarBodyEventPayload['type']
