/**
 * partial.js -> libs/
 * partial.mustache -> templates/
 */
import fs from 'fs'

const PARTIAL_LOOKUP_MAP = new Map([
  ['js', 'libs'],
  ['mustache', 'templates'],
])

function partialLookup (partial: string) {
  const ext = partial.split('.').pop()
  if (!ext) {
    throw new Error('unknown partial name: ' + partial)
  }

  const folder = PARTIAL_LOOKUP_MAP.get(ext)
  if (!folder) {
    throw new Error('unknown partial name: ' + partial)
  }

  return fs.readFileSync(
    require.resolve(
      '../'
      + folder
      + '/'
      + partial
    )
  ).toString()
}

export { partialLookup }
