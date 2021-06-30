/**
 * partial.js -> libs/
 * partial.mustache -> templates/
 */
import fs from 'fs'
import path from 'path'

function partialLookup (partial: string) {
  const file = path.join(
    __dirname,
    'templates',
    partial,
  )
  if (!file) {
    throw new Error(`partial name "${partial}" not found from path "${file}"`)
  }

  return fs.readFileSync(file).toString()
}

export { partialLookup }
