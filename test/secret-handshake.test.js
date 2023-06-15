const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const b4a = require('b4a')
const cl = require('chloride')
const deepEqual = require('deep-equal')
const bitflipper = require('pull-bitflipper')
const Hang = require('pull-hang')
const pull = require('pull-stream')
const shs = require('../')

function hash(str) {
  return cl.crypto_hash_sha256(b4a.from(str))
}

const alice = cl.crypto_sign_seed_keypair(hash('alice'))
const bob = cl.crypto_sign_seed_keypair(hash('bob'))
const wally = cl.crypto_sign_seed_keypair(hash('wally'))
const app_key = hash('app_key')

function unauthorized(pubkey, extra, cb) {
  cb(null, false)
}

function authorized(pubkey, extra, cb) {
  cb()
}

test('test handshake and box-stream', (t, done) => {
  const random = Math.random()

  function authenticate(publicKey, extra, cb) {
    assert.deepEqual(publicKey, alice.publicKey)
    if (deepEqual(publicKey, alice.publicKey)) cb(null, { okay: true, random })
    else cb(new Error('unauthorized'))
  }

  const createServerBoxStream = shs.server(bob, authenticate, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(
    bob.publicKey,
    null,
    (err, stream) => {
      assert.ifError(err)

      pull(
        pull.values([b4a.from('hello there')]),
        stream,
        pull.collect((err, payload) => {
          assert.ifError(err)
          assert.equal(payload.toString(), 'hello there')
          done()
        })
      )
    }
  )

  const bobBoxStream = createServerBoxStream((err, stream) => {
    assert.ifError(err)

    assert.deepEqual(stream.auth, { okay: true, random })
    pull(stream, stream) // ECHO
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})

function bitflipTest(done, test) {
  let errs = 0

  function authenticate(publicKey, cb) {
    assert.deepEqual(publicKey, alice.publicKey)

    if (deepEqual(publicKey, alice.publicKey)) cb(null)
    else cb(new Error('unauthorized'))
  }

  const createServerBoxStream = shs.server(bob, authenticate, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(bob.publicKey, null, (err) => {
    assert.ok(err, 'Alice errored')
    if (++errs === 2) done()
  })

  const bobBoxStream = createServerBoxStream((err) => {
    assert.ok(err, 'Bob errored')
    if (++errs === 2) done()
  })

  test(aliceBoxStream, bobBoxStream)
}

test('test auth fails when first packet is flipped', (t, done) => {
  bitflipTest(done, (aliceBoxStream, bobBoxStream) => {
    pull(aliceBoxStream, bitflipper(1), bobBoxStream, aliceBoxStream)
  })
})

test('test auth fails when 2nd packet is flipped', (t, done) => {
  bitflipTest(done, (aliceBoxStream, bobBoxStream) => {
    pull(aliceBoxStream, bobBoxStream, bitflipper(1), aliceBoxStream)
  })
})

test('test auth fails when 3rd packet is flipped', (t, done) => {
  bitflipTest(done, (aliceBoxStream, bobBoxStream) => {
    pull(aliceBoxStream, bitflipper(2), bobBoxStream, aliceBoxStream)
  })
})

test('test auth fails when 4th packet is flipped', (t, done) => {
  bitflipTest(done, (aliceBoxStream, bobBoxStream) => {
    pull(aliceBoxStream, bobBoxStream, bitflipper(2), aliceBoxStream)
  })
})

test('test error cb when client is not authorized', (t, done) => {
  let errs = 0

  const createServerBoxStream = shs.server(bob, unauthorized, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(bob.publicKey, null, (err) => {
    assert.ok(err, 'client connection error')
    assert.match(err.message, /phase 4/, 'client saw phase 4 error')
    if (++errs === 2) done()
  })

  const bobBoxStream = createServerBoxStream((err) => {
    assert.ok(err, 'server connection error')
    assert.match(err.message, /phase 4/, 'server saw phase 4 error')
    if (++errs === 2) done()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})

test('test error cb when client uses wrong server key', (t, done) => {
  let errs = 0

  const createServerBoxStream = shs.server(bob, unauthorized, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(wally.publicKey, null, (err) => {
    assert.ok(err, 'client connection error')
    assert.match(err.message, /phase 3/, 'client saw phase 3 error')
    if (++errs === 2) done()
  })

  const bobBoxStream = createServerBoxStream((err) => {
    assert.ok(err, 'server connection error')
    assert.match(err.message, /phase 3/, 'server saw phase 3 error')
    if (++errs === 2) done()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})

test('test error cb when client uses random server key', (t, done) => {
  let errs = 0

  const createServerBoxStream = shs.server(bob, unauthorized, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const randomKey = crypto.randomBytes(32)
  const aliceBoxStream = createClientBoxStream(randomKey, null, (err) => {
    assert.ok(err, 'client connection error')
    assert.match(err.message, /phase 2/, 'client saw phase 2 error')
    if (++errs === 2) done()
  })

  const bobBoxStream = createServerBoxStream((err) => {
    assert.ok(err, 'server connection error')
    assert.match(err.message, /phase 2/, 'server saw phase 2 error')
    if (++errs === 2) done()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})

test('client timeout error if there is no response', (t, done) => {
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(
    bob.publicKey,
    null,
    (err, stream) => {
      assert.match(
        err.message,
        /shs\.client.+phase 1/,
        'client saw phase 1 error'
      )
      assert.ok(err)
      done()
    }
  )

  pull(Hang(), aliceBoxStream)
  // do nothing, so alice should timeout
})

test('server timeout error if there is no response', (t, done) => {
  const createServerBoxStream = shs.server(bob, authorized, app_key, 100)

  const bobBoxStream = createServerBoxStream((err, stream) => {
    assert.match(
      err.message,
      /shs\.server.+phase 1/,
      'server saw phase 1 error'
    )
    done()
  })

  pull(Hang(), bobBoxStream)
  // do nothing, so bob should timeout
})

test('error if client created without server public key', (t) => {
  const createClientBoxStream = shs.client(alice, app_key, 100)
  assert.throws(() => {
    createClientBoxStream()
  })
})

test('unauthorized connection must cb once', (t, done) => {
  let n = 2

  const createClientBoxStream = shs.client(alice, app_key, 100)
  const createServerBoxStream = shs.server(bob, authorized, app_key, 100)

  const aliceBoxStream = createClientBoxStream(
    bob.publicKey,
    null,
    (err, stream) => {
      assert.ok(err, 'client connect should fail')
      next()
    }
  )

  const bobBoxStream = createServerBoxStream((err, stream) => {
    assert.ok(err, 'server connect should fail')
    next()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)

  function next() {
    if (--n) return
    done()
  }
})

test('test handshake', (t, done) => {
  const random = Math.random()

  function authenticate(publicKey, extra, cb) {
    assert.deepEqual(publicKey, alice.publicKey)
    cb(null, { okay: true, random })
  }

  const createServerBoxStream = shs.server(bob, authenticate, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(
    bob.publicKey,
    null,
    (err, stream) => {
      assert.ifError(err)
    }
  )

  const bobBoxStream = createServerBoxStream((err, stream) => {
    assert.ifError(err)

    assert.deepEqual(stream.auth, { okay: true, random })
    done()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})
