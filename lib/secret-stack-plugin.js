const base58 = require('bs58')
const b4a = require('b4a')
const MultiserverSHSe = require('./multiserver-plugin')

/**
 * @typedef {import('./chloride').ChlorideKeypair} ChlorideKeypair
 *
 * @typedef {Buffer | Uint8Array} B4A
 */

/**
 * @param {{ public?: any; private?: any; }} keypair
 * @returns {ChlorideKeypair}
 */
function toChlorideKeypair(keypair) {
  if (
    typeof keypair.public !== 'string' ||
    typeof keypair.private !== 'string'
  ) {
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
  init(/** @type {any} */ api, /** @type {any} */ config) {
    const timeoutHandshake = config.timers?.handshake ?? 15e3

    const shseCap = config.caps?.shse
    if (!shseCap) {
      throw new Error('SHSe secret-stack plugin must have caps.shse configured')
    }
    if (!config.keypair) {
      throw new Error('SHSe secret-stack plugin needs opts.keypair')
    }
    const chlorideKeypair = toChlorideKeypair(config.keypair)

    const shse = MultiserverSHSe({
      keypair: chlorideKeypair,
      appKey: b4a.from(base58.decode(shseCap)),
      timeout: timeoutHandshake,
      authorize(pubkey, extra, cb) {
        api.auth(
          { pubkey, extra },
          function authorizing(
            /** @type {Error | null} */ err,
            /** @type {any} */ auth
          ) {
            if (err) return cb(err)
            // default to 'always authorize' if no auth implementation exists
            else if (typeof auth === 'undefined') return cb(null, true)
            else cb(null, auth)
          }
        )
      },
    })

    /**
     * @param {B4A} publicKey
     */
    function identify(publicKey) {
      return {
        pubkey: base58.encode(publicKey),
      }
    }

    api.shse = identify(chlorideKeypair.publicKey)

    api.multiserver.transform({
      name: 'shse',
      create: () => shse,
      identify,
    })
  },
}
