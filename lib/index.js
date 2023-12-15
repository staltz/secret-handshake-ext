const { pullEncrypter, pullDecrypter } = require('pull-secret-channel')
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
 */

module.exports = {
  createClient,
  createServer,
  client: createClient,
  server: createServer,
}

const shs = createSHS({
  createEncrypterStream: (key, nonce) => {
    return pullEncrypter(key, nonce.subarray(0, 12))
  },
  createDecrypterStream: (key, nonce) => {
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
    const { stream, application } = initiate({
      responderStaticVerifyingEd25519Key: bob_pub,
      initiatorAuthPayload: extra_token,
    })

    application.then(
      ({
        stream,
        responderStaticVerifyingEd25519Key,
        encryptKey,
        encryptNonce,
        decryptKey,
        decryptNonce,
      }) =>
        cb(null, {
          ...stream,
          remote: responderStaticVerifyingEd25519Key,
          crypto: {
            encryptKey,
            encryptNonce,
            decryptKey,
            decryptNonce,
          },
        }),
      (err) => cb(err)
    )

    return stream
  }
}

/**
 * Server is Bob.
 *
 * @template Authorization
 * @param {Keypair} bob
 * @param {(
 *   publicKey: B4A,
 *   extra: B4A | null,
 *   cb: (...args: [Error] | [null, Authorization | false]) => void
 * ) => void} authorize
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
          (err, authorization) => {
            if (err) reject(err)
            else resolve(authorization)
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
    const { stream, application } = respond()

    application.then(
      ({
        stream,
        authorization,
        initiatorStaticVerifyingEd25519Key,
        encryptKey,
        encryptNonce,
        decryptKey,
        decryptNonce,
      }) =>
        cb(null, {
          ...stream,
          auth: authorization,
          remote: initiatorStaticVerifyingEd25519Key,
          crypto: {
            encryptKey,
            encryptNonce,
            decryptKey,
            decryptNonce,
          },
        }),
      (err) => cb(err)
    )

    return stream
  }
}
