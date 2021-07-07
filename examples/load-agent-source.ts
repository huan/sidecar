import fs   from 'fs'
import path from 'path'

function loadAgentSource () {
  const file = path.join(
    __dirname,
    'agent-source.js',
  )

  const initAgentSource = fs
    .readFileSync(file)
    .toString()

  return initAgentSource
}

export { loadAgentSource }
