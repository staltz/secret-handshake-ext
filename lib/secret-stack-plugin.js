const base58 = require('bs58')
const b4a = require('b4a')
const MultiserverSHSe = require('./multiserver-plugin')

/**
 * @typedef {import('./chloride').ChlorideKeypair} ChlorideKeypair
 */

/**
 * @param {{ public?: any; private?: any; }} keypair
 * @returns {ChlorideKeypair}
 */
function toChlorideKeypair(keypair) {
  if (typeof keypair.public !== 'string' || typeof keypair.private !== 'string') {
    return /** @type {ChlorideKeypair} */ (keypair)
  }
  return {
    publicKey: b4a.from(base58.decode(keypair.public)),
    secretKey: b4a.from(base58.decode(keypair.private)),
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

    const shse = MultiserverSHSe({
      keypair: config.keypair && toChlorideKeypair(config.keypair),
      appKey: b4a.from(base58.decode(shseCap)),
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
