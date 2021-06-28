import {
  log,
}             from '../../config'

function updateClassName <T extends Function> (
  klass : T,
  name  : string
): T {
  log.verbose('Sidecar', 'updateClassName(%s, %s)',
    klass.name,
    name,
  )

  Object.defineProperty(
    klass,
    'name',
    {
      writable: true,
    }
  )

  ;(klass as any).name = name

  Object.defineProperty(
    klass,
    'name',
    {
      writable: false,
    }
  )

  return klass
}

export { updateClassName }
