#!/usr/bin/env ts-node
import { test }  from 'tstest'

import { getSidecarMetadataFixture } from '../../../tests/fixtures/sidecar-metadata.fixture'

import {
  getMetadataSidecar,
  updateMetadataSidecar,
}                         from './metadata-sidecar'

test('update & get view metadata', async t => {
  const VALUE = getSidecarMetadataFixture()
  const TARGET = {}

  updateMetadataSidecar(
    TARGET,
    VALUE,
  )

  const data = getMetadataSidecar(
    TARGET,
  )

  t.deepEqual(data, VALUE, 'should get the view data the same as we set(update)')
})
