const test = require('node:test')
const assert = require('node:assert')
const p = require('node:util').promisify
const cl = require('chloride')
const base58 = require('bs58')
const b4a = require('b4a')

function hash(str) {
  return cl.crypto_hash_sha256(b4a.from(str))
}

test('secret-stack plugin for shse', async (t) => {
  const clKeypair = cl.crypto_sign_seed_keypair(hash('alice'))
  const keypair = {
    curve: 'ed25519',
    public: base58.encode(clKeypair.publicKey),
    private: base58.encode(clKeypair.secretKey),
    _public: b4a.from(clKeypair.publicKey),
    _private: b4a.from(clKeypair.secretKey),
  }

  const peer = require('secret-stack/bare')()
    .use(require('secret-stack/plugins/net'))
    .use(require('../lib/secret-stack-plugin'))
    .call(null, {
      shse: { caps: 'a' },
      global: {
        keypair
      }
    })

  assert.equal(peer.shse.pubkey, keypair.public)

  await p(peer.close)(true)
})
