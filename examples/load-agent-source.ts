import fs   from 'fs'
import path from 'path'

function loadAgentScript () {
  const file = path.join(
    __dirname,
    'agent-source.js',
  )

  const initAgentScript = fs
    .readFileSync(file)
    .toString()

  return initAgentScript
}

export { loadAgentScript }
