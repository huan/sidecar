#!/usr/bin/env ts-node
import { test }  from 'tstest'

import {
  sidecarView,
}                       from './sidecar-view'

import { SIDECAR_METADATA } from '../../../tests/fixtures/sidecar-metadata.fixture'
import { SIDECAR_VIEW }     from '../../../tests/fixtures/sidecar-view.fixture'

test('sidecarView()', async t => {

  const view = sidecarView(SIDECAR_METADATA)
  // console.log(JSON.stringify(view, null, 2))
  t.deepEqual(view, SIDECAR_VIEW, 'should get the correct sidecar view for the metadata')
})
