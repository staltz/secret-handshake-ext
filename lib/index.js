const { pullEncrypter, pullDecrypter } = require('pull-secret-channel')
const b4a = require('b4a')
const createSHS = require('pull-secret-handshake2')

/**
 * @typedef {Buffer | Uint8Array} B4A
 * @typedef {{ publicKey: B4A, secretKey: B4A }} Keypair
 *
 * @typedef {{
 *   write: (buf: B4A) => void,
 *   read: (
 *     len: Number,
 *     cb: (...args: [Error] | [null, B4A]) => void
 *   ) => void,
 *   abort: (err: Error) => void,
 *   rest: () => any
 * }
 * } Shake
 *
 * @typedef {(
 *   publicKey: B4A,
 *   extra: B4A | null,
 *   cb: (...args: [Error] | [null, boolean]) => void
 * ) => void
 * } Authorize
 */

module.exports = {
  createClient,
  createServer,
  client: createClient,
  server: createServer,
}

const shs = createSHS({
  createEncrypter: (key, nonce) => {
    return pullEncrypter(key, nonce.subarray(0, 12))
  },
  // @ts-ignore
  createDecrypter: (key, nonce) => {
    return pullDecrypter(key, nonce.subarray(0, 12))
  },
})

/**
 * Client is Alice.
 * Create the client stream with the server's public key to connect to.
 *
 * @param {Keypair} alice
 * @param {B4A} app_key
 * @param {number} timeout
 */
function createClient(alice, app_key, timeout) {
  const initiate = shs.createInitiator({
    initiatorStaticSigningEd25519Key: alice.secretKey,
    initiatorStaticVerifyingEd25519Key: alice.publicKey,
    networkKey: app_key,
    timeout,
  })

  /**
   * @param {B4A} bob_pub
   * @param {B4A | null} extra_token
   * @param {(...args: [Error] | [null, any]) => void} cb
   */
  return function createClientBoxStream(bob_pub, extra_token, cb) {
    const { handshake, application } = initiate({
      responderStaticVerifyingEd25519Key: bob_pub,
      initiatorAuthPayload: extra_token,
    })

    application.then(
      ({ stream }) =>
        cb(null, {
          ...stream,
          remote: bob_pub,
        }),
      (err) => cb(err)
    )

    return handshake
  }
}

/**
 * Server is Bob.
 *
 * @param {Keypair} bob
 * @param {Authorize} authorize
 * @param {B4A} app_key
 * @param {number} timeout
 * @returns
 */
function createServer(bob, authorize, app_key, timeout) {
  const respond = shs.createResponder({
    responderStaticSigningEd25519Key: bob.secretKey,
    responderStaticVerifyingEd25519Key: bob.publicKey,
    networkKey: app_key,
    authorize: (initiatorStaticVerifyingEd25519Key, initiatorAuthPayload) => {
      return new Promise((resolve, reject) => {
        authorize(
          initiatorStaticVerifyingEd25519Key,
          initiatorAuthPayload,
          (err, isAuthorized) => {
            if (err) reject(err)
            else resolve(isAuthorized)
          }
        )
      })
    },
    timeout,
  })

  /**
   * @param {(...args: [Error] | [null, any]) => void} cb
   */
  return function createServerBoxStream(cb) {
    const { handshake, application } = respond()

    application.then(
      ({ stream, isAuthorized, initiatorStaticVerifyingEd25519Key }) =>
        cb(null, {
          ...stream,
          auth: isAuthorized,
          remote: initiatorStaticVerifyingEd25519Key,
        }),
      (err) => cb(err)
    )

    return handshake
  }
}
