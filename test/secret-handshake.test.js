const tape = require('tape')
const deepEqual = require('deep-equal')
const cl = require('chloride')
const bitflipper = require('pull-bitflipper')
const crypto = require('crypto')
const Hang = require('pull-hang')
const pull = require('pull-stream')
const shs = require('../')

function hash(str) {
  return cl.crypto_hash_sha256(Buffer.from(str))
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

tape('test handshake and box-stream', (t) => {
  const random = Math.random()

  function authenticate(publicKey, extra, cb) {
    t.deepEqual(publicKey, alice.publicKey)
    if (deepEqual(publicKey, alice.publicKey)) cb(null, { okay: true, random })
    else cb(new Error('unauthorized'))
  }

  const createServerBoxStream = shs.server(bob, authenticate, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(
    bob.publicKey,
    null,
    (err, stream) => {
      if (err) t.fail(err.message ?? err)

      pull(
        pull.values([Buffer.from('hello there')]),
        stream,
        pull.collect((err, payload) => {
          if (err) t.fail(err.message ?? err)
          t.equal(payload.toString(), 'hello there')
          t.end()
        })
      )
    }
  )

  const bobBoxStream = createServerBoxStream((err, stream) => {
    if (err) t.fail(err.message ?? err)

    t.deepEqual(stream.auth, { okay: true, random })
    pull(stream, stream) // ECHO
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})

function bitflipTest(t, test) {
  let errs = 0

  function authenticate(publicKey, cb) {
    t.deepEqual(publicKey, alice.publicKey)

    if (deepEqual(publicKey, alice.publicKey)) cb(null)
    else cb(new Error('unauthorized'))
  }

  const createServerBoxStream = shs.server(bob, authenticate, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(bob.publicKey, null, (err) => {
    t.ok(err, 'Alice errored')
    if (++errs === 2) t.end()
  })

  const bobBoxStream = createServerBoxStream((err) => {
    t.ok(err, 'Bob errored')
    if (++errs === 2) t.end()
  })

  test(aliceBoxStream, bobBoxStream)
}

tape('test auth fails when first packet is flipped', (t) => {
  bitflipTest(t, (aliceBoxStream, bobBoxStream) => {
    pull(aliceBoxStream, bitflipper(1), bobBoxStream, aliceBoxStream)
  })
})

tape('test auth fails when 2nd packet is flipped', (t) => {
  bitflipTest(t, (aliceBoxStream, bobBoxStream) => {
    pull(aliceBoxStream, bobBoxStream, bitflipper(1), aliceBoxStream)
  })
})

tape('test auth fails when 3rd packet is flipped', (t) => {
  bitflipTest(t, (aliceBoxStream, bobBoxStream) => {
    pull(aliceBoxStream, bitflipper(2), bobBoxStream, aliceBoxStream)
  })
})

tape('test auth fails when 4th packet is flipped', (t) => {
  bitflipTest(t, (aliceBoxStream, bobBoxStream) => {
    pull(aliceBoxStream, bobBoxStream, bitflipper(2), aliceBoxStream)
  })
})

tape('test error cb when client is not authorized', (t) => {
  let errs = 0

  const createServerBoxStream = shs.server(bob, unauthorized, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(bob.publicKey, null, (err) => {
    t.ok(err, 'client connection error')
    t.match(err.message, /phase 4/, 'client saw phase 4 error')
    if (++errs === 2) t.end()
  })

  const bobBoxStream = createServerBoxStream((err) => {
    t.ok(err, 'server connection error')
    t.match(err.message, /phase 4/, 'server saw phase 4 error')
    if (++errs === 2) t.end()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})

tape('test error cb when client uses wrong server key', (t) => {
  let errs = 0

  const createServerBoxStream = shs.server(bob, unauthorized, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(wally.publicKey, null, (err) => {
    t.ok(err, 'client connection error')
    t.match(err.message, /phase 3/, 'client saw phase 3 error')
    if (++errs === 2) t.end()
  })

  const bobBoxStream = createServerBoxStream((err) => {
    t.ok(err, 'server connection error')
    t.match(err.message, /phase 3/, 'server saw phase 3 error')
    if (++errs === 2) t.end()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})

tape('test error cb when client uses random server key', (t) => {
  let errs = 0

  const createServerBoxStream = shs.server(bob, unauthorized, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const randomKey = crypto.randomBytes(32)
  const aliceBoxStream = createClientBoxStream(randomKey, null, (err) => {
    t.ok(err, 'client connection error')
    t.match(err.message, /phase 2/, 'client saw phase 2 error')
    if (++errs === 2) t.end()
  })

  const bobBoxStream = createServerBoxStream((err) => {
    t.ok(err, 'server connection error')
    t.match(err.message, /phase 2/, 'server saw phase 2 error')
    if (++errs === 2) t.end()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})

tape('client timeout error if there is no response', function (t) {
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(
    bob.publicKey,
    null,
    (err, stream) => {
      t.match(err.message, /shs\.client.+phase 1/, 'client saw phase 1 error')
      t.ok(err)
      t.end()
    }
  )

  pull(Hang(), aliceBoxStream)
  // do nothing, so alice should timeout
})

tape('server timeout error if there is no response', function (t) {
  const createServerBoxStream = shs.server(bob, authorized, app_key, 100)

  const bobBoxStream = createServerBoxStream((err, stream) => {
    t.match(err.message, /shs\.server.+phase 1/, 'server saw phase 1 error')
    t.end()
  })

  pull(Hang(), bobBoxStream)
  // do nothing, so bob should timeout
})

tape('error if client created without server public key', (t) => {
  const createClientBoxStream = shs.client(alice, app_key, 100)
  t.throws(() => {
    createClientBoxStream()
  })
  t.end()
})

tape('unauthorized connection must cb once', (t) => {
  t.plan(2)
  let n = 2

  const createClientBoxStream = shs.client(alice, app_key, 100)
  const createServerBoxStream = shs.server(bob, authorized, app_key, 100)

  const aliceBoxStream = createClientBoxStream(
    bob.publicKey,
    null,
    (err, stream) => {
      t.ok(err, 'client connect should fail')
      next()
    }
  )

  const bobBoxStream = createServerBoxStream((err, stream) => {
    t.ok(err, 'server connect should fail')
    next()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)

  function next() {
    if (--n) return
    t.end()
  }
})

tape('test handshake', (t) => {
  const random = Math.random()

  function authenticate(publicKey, extra, cb) {
    t.deepEqual(publicKey, alice.publicKey)
    cb(null, { okay: true, random })
  }

  const createServerBoxStream = shs.server(bob, authenticate, app_key, 100)
  const createClientBoxStream = shs.client(alice, app_key, 100)

  const aliceBoxStream = createClientBoxStream(
    bob.publicKey,
    null,
    (err, stream) => {
      if (err) t.fail(err.message ?? err)
    }
  )

  const bobBoxStream = createServerBoxStream((err, stream) => {
    if (err) t.fail(err.message ?? err)

    t.deepEqual(stream.auth, { okay: true, random })
    t.end()
  })

  pull(aliceBoxStream, bobBoxStream, aliceBoxStream)
})

tape('toKeys', (t) => {
  t.deepEqual(shs.toKeypair(hash('alice')), alice)
  t.deepEqual(shs.toKeypair(alice), alice)
  t.end()
})
