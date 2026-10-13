import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const [root, disk] = process.argv.slice(2)
const require = createRequire(root + '/package.json')
const { default: Disposable } = await import(require.resolve('promise-toolbox/Disposable'))
const { fileRestoreMethods } = await import(root + '/@xen-orchestra/backups/_fileRestore.mjs')
let active = 0
const adapter = {
  getDisk: Disposable.factory(async function* () {
    active++
    try { yield disk } finally { active-- }
  }),
  _getPartition() { throw new Error('legacy host mount must not execute') },
  _getLvmPhysicalVolume() { throw new Error('legacy host LVM must not execute') },
  _listLvmLogicalVolumes() { throw new Error('legacy host LVM must not execute') },
}
const partitions = await fileRestoreMethods.listPartitions.call(adapter, 'fixture')
assert.equal(partitions.length, 1)
const id = partitions[0].id
assert.deepEqual(await fileRestoreMethods.listPartitionFiles.call(adapter, 'fixture', id, '/docs'), { sentinel: {} })
for (const format of ['tgz', 'zip']) {
  const stream = await fileRestoreMethods.fetchPartitionFiles.call(adapter, 'fixture', id, ['/docs'], format)
  let size = 0
  for await (const chunk of stream) size += chunk.length
  assert(size > 20)
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(active, 0)
}
console.log('installed XO listing and streamed archive APIs use the isolated helper')
