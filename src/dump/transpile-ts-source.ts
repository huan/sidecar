import fs from 'fs'
import ts, { ScriptTarget } from 'typescript'

/**
 * https://stackoverflow.com/a/28731918/1123955
 */
const transpileTsSource = (source: string): string => {
  // https://github.com/microsoft/TypeScript/blob/62f9155a9d3c734854f3340e2b74fb799bf407fe/src/services/transpile.ts#L105
  const output = ts.transpile(source, {
    module: ts.ModuleKind.CommonJS,
    target: ScriptTarget.ES2015,  // https://bytearcher.com/articles/es6-vs-es2015-name/
  })
  return output // var x = 'hello world';
}

const transpileTsSourceFile = async (file: string): Promise<string> => transpileTsSource(
  await (await fs.promises.readFile(file)).toString()
)

export {
  transpileTsSource,
  transpileTsSourceFile,
}
