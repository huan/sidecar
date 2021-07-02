import browserify from 'browserify'
import tsify from 'tsify'

const options = {
  noImplicitAny          : true,
  target                 : 'es6',   // https://github.com/TypeStrong/tsify#es2015-formerly-known-as-es6
} as any

const bundleTsFile = (file: string) => new Promise<string>((resolve, reject) => {
  const stream = browserify()
    .add(file)
    .plugin(tsify, options)
    .bundle()

  const chunkList = [] as Buffer[]

  stream
    .on('data', chunk => chunkList.push(chunk))
    .on('error', reject)
    .on('end', () => resolve(Buffer.concat(chunkList).toString()))
})

export { bundleTsFile }
