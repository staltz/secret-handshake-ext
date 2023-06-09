const {
  keypairFromBuf,
  curvify_pk,
  curvify_sk,
  hash,
  auth,
  verify_auth,
  shared,
  sign,
  verify,
  box,
  unbox,
  createRandom,
} = require('./chloride')

const concat = Buffer.concat
const isBuffer = Buffer.isBuffer

const nonce = Buffer.alloc(24, 0)
const zero32 = Buffer.alloc(32, 0)

const challenge_length = 64
const client_auth_length = 16 + 32 + 64 + 32
const server_auth_length = 16 + 64
const mac_length = 16

/**
 * @typedef {{
 *   app_key: Buffer,
 *   extra?: Buffer,
 *   local: {
 *     publicKey: Buffer,
 *     secretKey: Buffer,
 *   },
 *   remote?: {
 *     publicKey: Buffer,
 *   },
 * }
 * } InitialState
 */

/**
 * @typedef {{
 *   app_key: Buffer,
 *   random: Buffer,
 *   local: {
 *     kx_pk: Buffer,
 *     kx_sk: Buffer,
 *     extra: Buffer | null,
 *     publicKey: Buffer,
 *     secretKey: Buffer,
 *     app_mac: Buffer
 *   },
 *   remote: {
 *     publicKey?: Buffer,
 *   }
 * }
 * } State0
 */

/**
 * @typedef {State0 & {
 *   remote: {
 *     publicKey: Buffer,
 *     kx_pk: Buffer,
 *     app_mac: Buffer
 *   },
 *   secret: Buffer,
 *   shash: Buffer
 * }
 * } State1
 */

/**
 * @typedef {State1 & {
 *   a_bob: Buffer,
 *   secret2: Buffer,
 *   local: State1['local'] & {
 *     hello: Buffer
 *   }
 * }
 * } State2
 */

/**
 * @typedef {State2 & {
 *   b_alice: Buffer,
 *   secret3: Buffer,
 *   encryptKey: Buffer,
 *   decryptKey: Buffer,
 * }
 * } State3
 */

/**
 * @typedef {State3 &
 * {
 *   remote: State2['remote'] & {
 *     hello: Buffer,
 *     extra: Buffer | null,
 *   },
 *   auth?: boolean,
 * }
 * } State3S
 */

/**
 * @param {Buffer} buf
 * @param {string} name
 * @param {number} length
 * @returns {void}
 */
function assert_length(buf, name, length) {
  if (buf.length !== length) {
    // prettier-ignore
    throw new Error(`expected ${name} to have length ${length}, but was: ${buf.length}`)
  }
}

// both client and server

/**
 * @param {InitialState} initialState
 * @returns {State0}
 */
function initialize(initialState) {
  const kx = keypairFromBuf(createRandom(32))
  const kx_pk = curvify_pk(kx.publicKey)
  const kx_sk = curvify_sk(kx.secretKey)
  if (!kx_pk || !kx_sk) throw new Error('failed to curvify keypair')

  const state0 = /** @type {State0} */ (initialState)

  state0.local = {
    kx_pk: kx_pk,
    kx_sk: kx_sk,
    extra: initialState.extra ?? null,
    publicKey: initialState.local.publicKey,
    secretKey: initialState.local.secretKey,
    app_mac: auth(kx_pk, initialState.app_key),
  }

  state0.remote ??= {}

  return state0
}

/**
 * @param {State0} state0
 * @returns {Buffer}
 */
function createChallenge(state0) {
  return concat([state0.local.app_mac, state0.local.kx_pk])
}

/**
 * @param {State0} state0
 * @param {Buffer} challenge
 * @returns {State1 | null}
 */
function verifyChallenge(state0, challenge) {
  assert_length(challenge, 'challenge', challenge_length)

  const mac = challenge.subarray(0, 32)
  const remote_pk = challenge.subarray(32, challenge_length)

  if (0 !== verify_auth(mac, remote_pk, state0.app_key)) return null

  const state1 = /** @type {State1} */ (/** @type {unknown} */ (state0))

  state1.remote.kx_pk = remote_pk
  state1.remote.app_mac = mac
  state1.secret = shared(state1.local.kx_sk, state1.remote.kx_pk)
  state1.shash = hash(state1.secret)

  return state1
}

/**
 * @param {State3} state3
 * @returns {State0}
 */
function clean(state3) {
  // clean away all the secrets for forward security.
  // use a different secret hash(secret3) in the rest of the session,
  // and so that a sloppy application cannot compromise the handshake.

  state3.shash.fill(0)
  state3.secret.fill(0)
  state3.a_bob.fill(0)
  state3.b_alice.fill(0)

  state3.secret = hash(state3.secret3)
  state3.encryptKey = hash(concat([state3.secret, state3.remote.publicKey]))
  state3.decryptKey = hash(concat([state3.secret, state3.local.publicKey]))

  state3.secret2.fill(0)
  state3.secret3.fill(0)
  state3.local.kx_sk.fill(0)

  const anystate = /** @type {any} */ (state3)
  anystate.shash = null
  anystate.secret2 = null
  anystate.secret3 = null
  anystate.a_bob = null
  anystate.b_alice = null
  anystate.local.kx_sk = null

  return anystate
}

// client side only (Alice)

/**
 * @param {State0} state0
 * @param {Buffer} challenge
 * @returns {State2 | null}
 */
function clientVerifyChallenge(state0, challenge) {
  assert_length(challenge, 'challenge', challenge_length)
  const verified = verifyChallenge(state0, challenge)
  if (!verified) return null
  const state1 = verified

  // now we have agreed on the secret.
  // this can be an encryption secret,
  // or a hmac secret.
  const remote_pk = curvify_pk(state1.remote.publicKey)
  if (!remote_pk) return null

  const state2 = /** @type {State2} */ (/** @type {unknown} */ (state1))
  const a_bob = shared(state1.local.kx_sk, remote_pk)
  state2.a_bob = a_bob
  state2.secret2 = hash(concat([state1.app_key, state1.secret, a_bob]))

  const signed = concat([state1.app_key, state1.remote.publicKey, state1.shash])
  const sig = sign(signed, state1.local.secretKey)

  const extra = state1.local.extra ?? zero32
  state2.local.hello = Buffer.concat([sig, state1.local.publicKey, extra])
  return state2
}

/**
 * @param {State2} state
 * @returns {Buffer}
 */
function clientCreateAuth(state) {
  return box(state.local.hello, nonce, state.secret2)
}

/**
 * @param {State2} state2
 * @param {Buffer} boxed_okay
 * @returns {State3 | null}
 */
function clientVerifyAccept(state2, boxed_okay) {
  assert_length(boxed_okay, 'server_auth', server_auth_length)

  const b_alice = shared(
    curvify_sk(state2.local.secretKey),
    state2.remote.kx_pk
  )

  const state3 = /** @type {State3} */ (/** @type {unknown} */ (state2))
  state3.b_alice = b_alice
  state3.secret3 = hash(
    concat([state2.app_key, state2.secret, state2.a_bob, state3.b_alice])
  )

  const sig = unbox(boxed_okay, nonce, state3.secret3)
  if (!sig) return null
  const signed = concat([state2.app_key, state2.local.hello, state2.shash])
  if (!verify(sig, signed, state2.remote.publicKey)) return null

  return state3
}

// server side only (Bob)

/**
 * @param {State1} state1
 * @param {Buffer} data
 * @returns {State3S | null}
 */
function serverVerifyAuth(state1, data) {
  assert_length(data, 'client_auth', client_auth_length)

  const a_bob = shared(curvify_sk(state1.local.secretKey), state1.remote.kx_pk)

  const state2 = /** @type {State2} */ (/** @type {unknown} */ (state1))
  state2.a_bob = a_bob
  state2.secret2 = hash(concat([state1.app_key, state1.secret, a_bob]))

  const hello = unbox(data, nonce, state2.secret2)
  if (!hello) return null

  const state3 = /** @type {State3S} */ (/** @type {unknown} */ (state2))
  state3.remote.hello = hello

  const sig = state3.remote.hello.subarray(0, 64)
  const publicKey = state3.remote.hello.subarray(64, 96)
  const extra = state3.remote.hello.subarray(96, 128)

  const signed = concat([state1.app_key, state1.local.publicKey, state1.shash])
  if (!verify(sig, signed, publicKey)) return null

  state3.remote.publicKey = publicKey
  state3.remote.extra = extra.equals(zero32) ? null : extra
  // shared key between my local ephemeral key + remote public
  const remote_pk = curvify_pk(state2.remote.publicKey)
  if (!remote_pk) return null
  const b_alice = shared(state2.local.kx_sk, remote_pk)
  state3.b_alice = b_alice
  state3.secret3 = hash(
    concat([state2.app_key, state2.secret, state2.a_bob, state3.b_alice])
  )

  return state3
}

/**
 * @param {State3S} state3
 * @returns {Buffer}
 */
function serverCreateAccept(state3) {
  const signed = concat([state3.app_key, state3.remote.hello, state3.shash])
  const okay = sign(signed, state3.local.secretKey)
  return box(okay, nonce, state3.secret3)
}

/**
 * @typedef {ReturnType<typeof keypairFromBuf>} ChlorideKeypair
 */

/**
 * @param {Buffer | ChlorideKeypair} keys
 * @returns {ChlorideKeypair}
 */
function toKeypair(keys) {
  if (isBuffer(keys)) return keypairFromBuf(keys)
  return keys
}

module.exports = {
  challenge_length,
  client_auth_length,
  server_auth_length,
  mac_length,

  clean,
  initialize,
  createChallenge,
  verifyChallenge,
  clientVerifyChallenge,
  clientCreateAuth,
  clientVerifyAccept,
  serverVerifyAuth,
  serverCreateAccept,
  toKeypair,
}
