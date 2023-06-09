const base58 = require('bs58')
const SHSe = require('./multiserver-plugin')

/**
 * @typedef {import('./crypto').ChlorideKeypair} Keypair
 */

/**
 * @param {{ public?: any; private?: any; }} keys
 * @returns {Keypair}
 */
function toSodiumKeypair(keys) {
  if (typeof keys.public !== 'string' || typeof keys.private !== 'string') {
    return /** @type {Keypair} */ (keys)
  }
  return {
    publicKey: Buffer.from(base58.decode(keys.public)),
    secretKey: Buffer.from(base58.decode(keys.private)),
  }
}

module.exports = {
  name: 'multiserver-shse',
  version: '0.0.1',
  init(/** @type {any} */ sstack, /** @type {any} */ config) {
    const timeoutHandshake = config.timers?.handshake ?? 15e3

    const shseCap = config.caps?.shse
    if (!shseCap) {
      throw new Error('shse secret-stack plugin must have caps.shse configured')
    }

    const shse = SHSe({
      keys: config.keys && toSodiumKeypair(config.keys),
      appKey: Buffer.from(base58.decode(shseCap)),
      timeout: timeoutHandshake,
      authorize(pubkey, extra, cb) {
        sstack.auth({ pubkey, extra }, cb)
      },
    })

    sstack.pubkey = shse.pubkey

    sstack.multiserver.transform({
      name: 'shse',
      create: () => shse,
    })
  },
}
