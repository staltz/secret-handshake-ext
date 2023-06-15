// @ts-ignore
const sodium = require('sodium-universal')
const b4a = require('b4a')

/**
 * @typedef {Buffer | Uint8Array} B4A
 *
 * @typedef {{ publicKey: B4A, secretKey: B4A }} ChlorideKeypair
 */

/**
 * @param {B4A} seed
 * @returns {ChlorideKeypair}
 */
function keypairFromBuf(seed) {
  const out = {
    publicKey: b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
    secretKey: b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES),
  }
  sodium.crypto_sign_seed_keypair(out.publicKey, out.secretKey, seed)
  return out
}

/**
 * @param {number} numBytes
 * @returns {B4A}
 */
function createRandom(numBytes) {
  const buf = b4a.alloc(numBytes)
  sodium.randombytes_buf(buf)
  return buf
}

/**
 * @param {B4A} ed_pk
 * @returns {B4A | null}
 */
function curvify_pk(ed_pk) {
  const curve_pk = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_pk_to_curve25519(curve_pk, ed_pk)
  } catch {
    return null
  }
  return curve_pk
}

/**
 * @param {B4A} ed_sk
 * @returns {B4A}
 */
function curvify_sk(ed_sk) {
  const curve_sk = b4a.alloc(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_sign_ed25519_sk_to_curve25519(curve_sk, ed_sk)
  return curve_sk
}

/**
 * @param {B4A} input
 * @param {B4A} key
 * @returns {B4A}
 */
function auth(input, key) {
  const output = b4a.alloc(sodium.crypto_auth_BYTES)
  sodium.crypto_auth(output, input, key)
  return output
}

/**
 * @param {B4A} localSecretKey
 * @param {B4A} remotePublicKey
 * @returns {B4A}
 */
function shared(localSecretKey, remotePublicKey) {
  const sharedSecret = b4a.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(sharedSecret, localSecretKey, remotePublicKey)
  return sharedSecret
}

/**
 * @param {B4A} input
 * @returns {B4A}
 */
function hash(input) {
  const output = b4a.alloc(sodium.crypto_hash_sha256_BYTES)
  sodium.crypto_hash_sha256(output, input)
  return output
}

/**
 * @param {B4A} msg
 * @param {B4A} sk
 * @returns {B4A}
 */
function sign(msg, sk) {
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, msg, sk)
  return sig
}

/**
 * @param {B4A} sig
 * @param {B4A} msg
 * @param {B4A} pk
 * @returns {boolean}
 */
function verify(sig, msg, pk) {
  return sodium.crypto_sign_verify_detached(sig, msg, pk)
}

/**
 * @param {B4A} output
 * @param {B4A} input
 * @param {B4A} key
 * @returns {0 | 1}
 */
function verify_auth(output, input, key) {
  return sodium.crypto_auth_verify(output, input, key) ? 0 : 1
}

/**
 * @param {B4A} ptxt
 * @param {B4A} nonce
 * @param {B4A} key
 * @returns {B4A}
 */
function box(ptxt, nonce, key) {
  const ctxt = b4a.alloc(ptxt.length + sodium.crypto_secretbox_MACBYTES)
  sodium.crypto_secretbox_easy(ctxt, ptxt, nonce, key)
  return ctxt
}

/**
 * @param {B4A} ctxt
 * @param {B4A} nonce
 * @param {B4A} key
 * @returns {B4A | null}
 */
function unbox(ctxt, nonce, key) {
  const ptxt = b4a.alloc(ctxt.length - sodium.crypto_secretbox_MACBYTES)
  const unboxed = sodium.crypto_secretbox_open_easy(ptxt, ctxt, nonce, key)
  if (unboxed) return ptxt
  else return null
}

module.exports = {
  keypairFromBuf,
  createRandom,
  curvify_pk,
  curvify_sk,
  auth,
  shared,
  hash,
  sign,
  verify,
  verify_auth,
  box,
  unbox,
}
