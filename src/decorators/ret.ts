const RET_SYMBOL = Symbol('PLACE_HOLDER_FOR_RETURN')

function Ret (...args: any[]): any {
  void args // nop. Just for making TypeScript happy
  /**
   * You can safely ignore the following return value: RET
   * Because it will be replaced by the docorator
   * with the real return value.
   */
  return RET_SYMBOL
}

export {
  RET_SYMBOL,
  Ret,
}
