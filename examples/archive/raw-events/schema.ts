export interface SidecarFridaPayload {
  method: string,
  args: {
    [k: string]: null | string | number
  },
  data?: null | Buffer,
}
