import fs from 'fs'

async function extractClassNameList (
  file: string,
): Promise<string[]> {
  const buf = await fs.promises.readFile(file)
  return extractClassNameListFromSource(buf.toString())
}

async function extractClassNameListFromSource (
  source: string
): Promise<string[]> {
  /**
   * Extract the @Sidecar decorated classes
   */
  const REGEXP = /@Sidecar\s*\(.*?\)\s*class\s+([A-Za-z0-9\-_]+)/sg

  return Array.from(
    source.matchAll(REGEXP)
  ).map(m => m[1])
}

export {
  extractClassNameListFromSource,
  extractClassNameList,
}
