#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { transpileTsSource } from './transpile-ts-source'

test('loadTsSource()', async t => {
  const TS = 'const n: number = 42'
  const EXPECTED_JS = 'const n = 42;\n'

  const output = transpileTsSource(TS)

  t.equal(output, EXPECTED_JS, 'should transpile TS to JS correct')
})
