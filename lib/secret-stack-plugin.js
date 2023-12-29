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
  name: 'shse',
  version: '0.0.1',
  init(/** @type {any} */ api, /** @type {any} */ config) {
    const timeoutHandshake = config.shse?.timeoutHandshake ?? 15e3

    const shseCap = config.shse?.caps
    if (!shseCap) {
      throw new Error('SHSe secret-stack plugin must have caps.shse configured')
    }
    if (!config.global.keypair) {
      throw new Error('SHSe secret-stack plugin needs config.global.keypair')
    }
    const chlorideKeypair = toChlorideKeypair(config.global.keypair)

    const shse = MultiserverSHSe({
      keypair: chlorideKeypair,
      appKey: b4a.from(base58.decode(shseCap)),
      timeout: timeoutHandshake,
      authorize(pubkey, extra, cb) {
        api.auth(
          { pubkey, extra },
          function authorizing(
            /** @type {Error | null} */ err,
            /** @type {boolean | undefined | null} */ auth
          ) {
            if (err) return cb(err)
            // Default to 'always authorize' if no auth implementation exists:
            cb(null, auth ?? true)
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
