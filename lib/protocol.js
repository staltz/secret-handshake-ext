// @ts-ignore
const pull = require('pull-stream') // @ts-ignore
const {
  KEYBYTES: SECRETSTREAM_KEYBYTES,
  createEncryptStream,
  createDecryptStream,
  // @ts-ignore
} = require('pull-secretstream')
// @ts-ignore
const Handshake = require('pull-handshake')
const b4a = require('b4a')
const bs58 = require('bs58')
const debug = require('debug')('shse')
const errors = require('./errors')

/**
 * @typedef {import('./crypto')} Crypto
 * @typedef {import('./chloride').ChlorideKeypair} ChlorideKeypair
 *
 * @typedef {Buffer | Uint8Array} B4A
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
 *
 * @typedef {(
 *   ...args: [Error] | [null, any, any]
 * ) => void
 * } BoxStreamCallback
 */

/**
 * @param {B4A} buf
 * @param {number} len
 * @returns {boolean}
 */
function isB4AWithSize(buf, len) {
  return b4a.isBuffer(buf) && buf.length === len
}

/**
 * @param {Shake} shake
 */
function createAbort(shake) {
  /**
   * @param {Error | true | null} err
   * @param {string} reason
   */
  return function abort(err, reason) {
    if (err && err !== true) {
      // @ts-ignore
      shake.abort(new Error(reason, { cause: err.message ?? err }))
    } else {
      shake.abort(new Error(reason))
    }
  }
}

const zero32 = b4a.alloc(32, 0)

/**
 * @param {Crypto} crypto
 */
function protocol(crypto) {
  /**
   * Client is Alice.
   * Create the client stream with the server's public key to connect to.
   *
   * @param {ChlorideKeypair} alice
   * @param {B4A} app_key
   * @param {number} timeout
   */
  function createClientStream(alice, app_key, timeout) {
    /**
     * @param {B4A} bob_pub
     * @param {B4A | null} extra_token
     * @param {BoxStreamCallback} cb
     */
    return function getClientStream(bob_pub, extra_token, cb) {
      let state0 = crypto.initialize({
        app_key,
        extra: extra_token ?? zero32,
        local: alice,
        remote: { publicKey: bob_pub },
      })

      const stream = Handshake({ timeout }, cb) // cb called only for errors
      const shake = /** @type {Shake} */ (stream.handshake)
      stream.handshake = null
      const abort = createAbort(shake)

      // phase 1: client sends challenge
      const bob_pub_str = bs58.encode(bob_pub)
      debug('client phase 1, send challenge to %s', bob_pub_str)
      shake.write(crypto.createChallenge(state0))

      // phase 2: receiving and verifying server's challenge
      debug('client phase 2, wait for challenge from %s', bob_pub_str)
      shake.read(crypto.challenge_length, (err, msg) => {
        if (err) return abort(err, errors.serverErrorOnChallenge)
        const state1 = crypto.clientVerifyChallenge(state0, msg)
        if (!state1) {
          return abort(null, errors.serverInvalidChallenge)
        }

        // phase 3: client sends hello (including proof they know the server)
        debug('client phase 3, send hello to %s', bob_pub_str)
        shake.write(crypto.clientCreateAuth(state1))

        // phase 4: receiving and verifying server's acceptance
        debug('client phase 4, wait for acceptance from %s', bob_pub_str)
        shake.read(crypto.server_auth_length, (err, boxed_sig) => {
          if (err) return abort(err, errors.serverHungUp)
          const state3 = crypto.clientVerifyAccept(state1, boxed_sig)
          if (!state3) {
            return abort(null, errors.serverAcceptInvalid)
          }

          // Conclude handshake
          debug('client concluded handshake with %s', bob_pub_str)
          cb(null, shake.rest(), (state0 = crypto.clean(state3)))
        })
      })

      return stream
    }
  }

  /**
   * Server is Bob.
   *
   * @param {ChlorideKeypair} bob
   * @param {Authorize} authorize
   * @param {B4A} app_key
   * @param {number} timeout
   * @returns
   */
  function createServerStream(bob, authorize, app_key, timeout) {
    /**
     * @param {BoxStreamCallback} cb
     */
    return function getServerStream(cb) {
      let state0 = crypto.initialize({
        app_key,
        local: bob,
        // remote: unknown until server receives ClientAuth
      })

      const stream = Handshake({ timeout }, cb) // cb called only for errors
      const shake = /** @type {Shake} */ (stream.handshake)
      stream.handshake = null
      const abort = createAbort(shake)

      // phase 1: receiving and verifying client's challenge
      debug('server phase 1, wait for challenge from unknown client')
      shake.read(crypto.challenge_length, (err, challenge) => {
        if (err) return abort(err, errors.clientErrorOnChallenge)
        const state1 = crypto.verifyChallenge(state0, challenge)
        if (!state1) {
          return shake.abort(new Error(errors.clientInvalidChallenge))
        }
        const alice_pub = state1.remote.publicKey

        // phase 2: server sends challenge
        debug('server phase 2, send challenge to unknown')
        shake.write(crypto.createChallenge(state1))

        // phase 3: receiving and verifying client's hello
        debug('server phase 3, waiting for hello from unknown client')
        shake.read(crypto.client_auth_length, (err, hello) => {
          if (err) return abort(err, errors.clientErrorOnHello)
          const state3 = crypto.serverVerifyAuth(state1, hello)
          if (!state3) {
            return abort(null, errors.clientInvalidHello)
          }

          // phase 4: server decides if they want client to connect with them
          const pubkey = state3.remote.publicKey
          const extra = state3.remote.extra
          debug('server phase 4, maybe authorize %s', bs58.encode(pubkey))
          authorize(pubkey, extra, (err, auth) => {
            if (err) return abort(err, errors.serverErrorOnAuthorization)
            if (!auth) return abort(null, errors.clientUnauthorized)
            state3.auth = auth
            shake.write(crypto.serverCreateAccept(state3))

            // Conclude handshake
            debug('server concluded handshake with %s', bs58.encode(pubkey))
            cb(null, shake.rest(), (state0 = crypto.clean(state3)))
          })
        })
      })

      return stream
    }
  }

  // wrap the above into an actual handshake + encrypted session

  /**
   * @param {(...args: [Error] | [null, any]) => void} cb
   * @returns {BoxStreamCallback}
   */
  function wrapInBoxStream(cb) {
    return /** @type {BoxStreamCallback} */ (
      function (err, stream, state) {
        if (err) return cb(err)

        cb(null, {
          remote: state.remote.publicKey,
          // on the server, attach any metadata gathered
          // during `authorize` call
          auth: state.auth,
          crypto: {
            encryptKey: state.encryptKey,
            decryptKey: state.decryptKey,
          },
          source: pull(stream.source, createDecryptStream(state.decryptKey)),
          sink: pull(createEncryptStream(state.encryptKey), stream.sink),
        })
      }
    )
  }

  /**
   * @param {ChlorideKeypair} alice
   * @param {B4A} app_key
   * @param {number} timeout
   */
  function createClient(alice, app_key, timeout) {
    const getBoxStream = createClientStream(alice, app_key, timeout)

    /**
     * @param {B4A} bob_pub
     * @param {B4A | null} extra_token
     * @param {(...args: [Error] | [null, any]) => void} cb
     */
    return function createClientBoxStream(bob_pub, extra_token, cb) {
      if (!isB4AWithSize(bob_pub, 32)) {
        throw new Error('createClient *must* be passed a public key')
      }
      if (extra_token && !isB4AWithSize(extra_token, 32)) {
        throw new Error('createClient extra token *must* have 32 bytes')
      }
      return getBoxStream(bob_pub, extra_token, wrapInBoxStream(cb))
    }
  }

  /**
   * @param {ChlorideKeypair} bob
   * @param {Authorize} authorize
   * @param {B4A} app_key
   * @param {number} timeout
   * @returns
   */
  function createServer(bob, authorize, app_key, timeout) {
    const getBoxStream = createServerStream(bob, authorize, app_key, timeout)

    /**
     * @param {(...args: [Error] | [null, any]) => void} cb
     */
    return function createServerBoxStream(cb) {
      return getBoxStream(wrapInBoxStream(cb))
    }
  }

  return {
    createClient,
    createServer,
    client: createClient,
    server: createServer,
  }
}

module.exports = protocol
