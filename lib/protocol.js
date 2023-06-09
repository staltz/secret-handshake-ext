// @ts-ignore
const pull = require('pull-stream') // @ts-ignore
const boxes = require('pull-box-stream') // @ts-ignore
const Handshake = require('pull-handshake')
const errors = require('./errors')

/**
 * @typedef {import('./crypto')} Crypto
 *
 * @typedef {import('./crypto').ChlorideKeypair} ChlorideKeypair
 *
 * @typedef {{
 *   write: (buf: Buffer) => void,
 *   read: (
 *     len: Number,
 *     cb: (...args: [Error] | [null, Buffer]) => void
 *   ) => void,
 *   abort: (err: Error) => void,
 *   rest: () => any
 * }
 * } Shake
 *
 * @typedef {(
 *   publicKey: Buffer,
 *   extra: Buffer | null,
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
 * @param {Buffer} buf
 * @param {number} len
 * @returns {boolean}
 */
function isBuffer(buf, len) {
  return Buffer.isBuffer(buf) && buf.length === len
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

const zero32 = Buffer.alloc(32, 0)

/**
 * @param {Crypto} crypto
 */
function protocol(crypto) {
  /**
   * Client is Alice.
   * Create the client stream with the server's public key to connect to.
   *
   * @param {ChlorideKeypair} alice
   * @param {Buffer} app_key
   * @param {number} timeout
   */
  function createClientStream(alice, app_key, timeout) {
    /**
     * @param {Buffer} bob_pub
     * @param {Buffer | null} extra_token
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
      shake.write(crypto.createChallenge(state0))

      // phase 2: receiving and verifying server's challenge
      shake.read(crypto.challenge_length, (err, msg) => {
        if (err) return abort(err, errors.serverErrorOnChallenge)
        const state1 = crypto.clientVerifyChallenge(state0, msg)
        if (!state1) {
          return abort(null, errors.serverInvalidChallenge)
        }

        // phase 3: client sends hello (including proof they know the server)
        shake.write(crypto.clientCreateAuth(state1))

        // phase 4: receiving and verifying server's acceptance
        shake.read(crypto.server_auth_length, (err, boxed_sig) => {
          if (err) return abort(err, errors.serverHungUp)
          const state3 = crypto.clientVerifyAccept(state1, boxed_sig)
          if (!state3) {
            return abort(null, errors.serverAcceptInvalid)
          }

          // Conclude handshake
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
   * @param {Buffer} app_key
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
      shake.read(crypto.challenge_length, (err, challenge) => {
        if (err) return abort(err, errors.clientErrorOnChallenge)
        const state1 = crypto.verifyChallenge(state0, challenge)
        if (!state1) {
          return shake.abort(new Error(errors.clientInvalidChallenge))
        }

        // phase 2: server sends challenge
        shake.write(crypto.createChallenge(state1))

        // phase 3: receiving and verifying client's hello
        shake.read(crypto.client_auth_length, (err, hello) => {
          if (err) return abort(err, errors.clientErrorOnHello)
          const state3 = crypto.serverVerifyAuth(state1, hello)
          if (!state3) {
            return abort(null, errors.clientInvalidHello)
          }

          // phase 4: server decides if they want client to connect with them
          const pubkey = state3.remote.publicKey
          const extra = state3.remote.extra
          authorize(pubkey, extra, (err, auth) => {
            if (err) return abort(err, errors.serverErrorOnAuthorization)
            if (!auth) return abort(null, errors.clientUnauthorized)
            state3.auth = auth
            shake.write(crypto.serverCreateAccept(state3))

            // Conclude handshake
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

        const encryptNonce = state.remote.app_mac.slice(0, 24)
        const decryptNonce = state.local.app_mac.slice(0, 24)

        cb(null, {
          remote: state.remote.publicKey,
          // on the server, attach any metadata gathered
          // during `authorize` call
          auth: state.auth,
          crypto: {
            encryptKey: state.encryptKey,
            decryptKey: state.decryptKey,
            encryptNonce,
            decryptNonce,
          },
          source: pull(
            stream.source,
            boxes.createUnboxStream(state.decryptKey, decryptNonce)
          ),
          sink: pull(
            boxes.createBoxStream(state.encryptKey, encryptNonce),
            stream.sink
          ),
        })
      }
    )
  }

  /**
   * @param {ChlorideKeypair} alice
   * @param {Buffer} app_key
   * @param {number} timeout
   */
  function createClient(alice, app_key, timeout) {
    const getBoxStream = createClientStream(alice, app_key, timeout)

    /**
     * @param {Buffer} bob_pub
     * @param {Buffer | null} extra_token
     * @param {(...args: [Error] | [null, any]) => void} cb
     */
    return function createClientBoxStream(bob_pub, extra_token, cb) {
      if (!isBuffer(bob_pub, 32)) {
        throw new Error('createClient *must* be passed a public key')
      }
      if (extra_token && !isBuffer(extra_token, 32)) {
        throw new Error('createClient extra token *must* have 32 bytes')
      }
      return getBoxStream(bob_pub, extra_token, wrapInBoxStream(cb))
    }
  }

  /**
   * @param {ChlorideKeypair} bob
   * @param {Authorize} authorize
   * @param {Buffer} app_key
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
    toKeypair: crypto.toKeypair,
  }
}

module.exports = protocol
