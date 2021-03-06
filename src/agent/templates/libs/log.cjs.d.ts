import type {
  SidecarPayloadHook,
  SidecarPayloadLog,
}                     from '../../../sidecar-body/payload-schemas.js'

/* eslint camelcase: 0 */
declare module './log.cjs' {

  export declare namespace log {

    export function error (
      prefix: string,
      message: string,
      ...args: any[],
    )

    export function warn (
      prefix: string,
      message: string,
      ...args: any[],
    )

    export function info (
      prefix: string,
      message: string,
      ...args: any[],
    )

    export function verbose (
      prefix: string,
      message: string,
      ...args: any[],
    )

    export function silly (
      prefix: string,
      message: string,
      ...args: any[],
    )

    export function level (
      newLevel: number | 'silent' | 'error'  | 'warn'  | 'info'  | 'verbose' | 'silly'
    )
  }

}
