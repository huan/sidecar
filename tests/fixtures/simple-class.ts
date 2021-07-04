function decorator (...args: any[]): any { void args }

@decorator
class Test {
  n?: number
}

export { Test }
