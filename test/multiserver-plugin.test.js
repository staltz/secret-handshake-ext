const test = require('node:test')
const assert = require('node:assert')
const cl = require('chloride')
const base58 = require('bs58')
const b4a = require('b4a')
const shsePlugin = require('../lib/multiserver-plugin')

function hash(str) {
  return cl.crypto_hash_sha256(b4a.from(str))
}

const alice = cl.crypto_sign_seed_keypair(hash('alice'))
const bob = cl.crypto_sign_seed_keypair(hash('bob'))
const appKey = hash('app_key')

test('multiserver-plugin name and create', (t) => {
  const plugin = shsePlugin({ keypair: alice, appKey, timeout: 10e3 })

  assert.equal(plugin.name, 'shse')
  assert.equal(typeof plugin.create, 'function')
})

test('multiserver-plugin stringify', (t) => {
  const plugin = shsePlugin({ keypair: alice, appKey, timeout: 10e3 })
  assert.equal(
    plugin.stringify(),
    `shse:${base58.encode(alice.publicKey)}`,
    'plugin stringify'
  )
})

test('multiserver-plugin parse', (t) => {
  const plugin = shsePlugin({ keypair: alice, appKey, timeout: 10e3 })

  const buf1 = hash('foo')
  const buf2 = hash('bar')
  const pubkey = base58.encode(buf1)
  const extra = base58.encode(buf2)

  assert.deepEqual(
    plugin.parse(`shse:${pubkey}`),
    { name: 'shse', pubkey: buf1, extra: null },
    'parse just pubkey'
  )
  assert.deepEqual(
    plugin.parse(`shse:${pubkey}:${extra}`),
    { name: 'shse', pubkey: buf1, extra: buf2 },
    'parse pubkey+extra'
  )
  assert.deepEqual(plugin.parse(`shse:notgreat`), null, 'parse invalid pubkey')
  assert.deepEqual(
    plugin.parse(`shse:${pubkey}:notgreat`),
    null,
    'parse invalid extra'
  )
})
