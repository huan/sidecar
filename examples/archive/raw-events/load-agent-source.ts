const { makeCompiler } = require('frida-compile')

/**
 * See: https://github.com/frida/frida-compile/blob/ca091615186f83c0f2326f07fbfd4eac86056fd7/index.js#L31-L40
 */
async function loadAgentSource (): Promise<string> {
  const compile = makeCompiler(
    require.resolve('./agent.ts'),
    {},
    {},
  )
  const result = await compile() as { bundle: Buffer }
  const agentSource = result.bundle.toString()

  return agentSource
}

export { loadAgentSource  }
