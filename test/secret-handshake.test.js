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

function unauthorized(_, cb) {
  cb(new Error('unauthorized'))
}

function authorized(_, cb) {
  cb()
}

tape('test handshake', (t) => {
  const aliceHS = shs.client(
    alice,
    app_key,
    100
  )(bob.publicKey, (err, stream) => {
    if (err) t.fail(err.message ?? err)

    pull(
      pull.values([Buffer.from('hello there')]),
      stream,
      pull.collect((err, hello_there) => {
        t.equal(hello_there.toString(), 'hello there')
        console.log('output:', hello_there.join(''))
        t.end()
      })
    )
  })

  const random = Math.random()
  const bobHS = shs.server(
    bob,
    (publicKey, cb) => {
      t.deepEqual(publicKey, alice.publicKey)
      if (deepEqual(publicKey, alice.publicKey)) {
        cb(null, { okay: true, random })
      } else {
        cb(new Error('unauthorized'))
      }
    },
    app_key,
    100
  )((err, stream) => {
    if (err) t.fail(err.message ?? err)

    t.deepEqual(stream.auth, { okay: true, random: random })
    pull(
      stream,
      pull.through((data) => console.log('echo:', data.toString())),
      stream
    ) // ECHO
  })

  pull(
    aliceHS,
    pull.through(console.log.bind(console, 'A->B')),
    bobHS,
    pull.through(console.log.bind(console, 'A<-B')),
    aliceHS
  )
})

function bitflipTest(t, test) {
  let errs = 0

  const aliceHS = shs.client(
    alice,
    app_key,
    100
  )(bob.publicKey, (err) => {
    t.ok(err, 'Alice errored')
    if (++errs === 2) t.end()
  })

  const bobHS = shs.server(
    bob,
    function (publicKey, cb) {
      t.deepEqual(publicKey, alice.publicKey)

      if (deepEqual(publicKey, alice.publicKey)) cb(null)
      else cb(new Error('unauthorized'))
    },
    app_key,
    100
  )((err) => {
    t.ok(err, 'Bob errored')
    if (++errs === 2) t.end()
  })

  test(aliceHS, bobHS)
}

tape('test auth fails when first packet is flipped', (t) => {
  bitflipTest(t, (aliceHS, bobHS) => {
    pull(aliceHS, bitflipper(1), bobHS, aliceHS)
  })
})

tape('test auth fails when 2nd packet is flipped', (t) => {
  bitflipTest(t, (aliceHS, bobHS) => {
    pull(aliceHS, bobHS, bitflipper(1), aliceHS)
  })
})

tape('test auth fails when 3rd packet is flipped', (t) => {
  bitflipTest(t, (aliceHS, bobHS) => {
    pull(aliceHS, bitflipper(2), bobHS, aliceHS)
  })
})

tape('test auth fails when 4th packet is flipped', (t) => {
  bitflipTest(t, (aliceHS, bobHS) => {
    pull(aliceHS, bobHS, bitflipper(2), aliceHS)
  })
})

tape('test error cb when client is not authorized', (t) => {
  let errs = 0

  const aliceHS = shs.client(
    alice,
    app_key,
    100
  )(bob.publicKey, (err) => {
    t.ok(err, 'Bob hungup')
    if (++errs === 2) t.end()
  })

  const bobHS = shs.server(
    bob,
    unauthorized,
    app_key,
    100
  )((err) => {
    t.ok(err, 'client unauthorized')
    if (++errs === 2) t.end()
  })

  pull(aliceHS, bobHS, aliceHS)
})

tape('test error cb when client get wrong number', (t) => {
  let errs = 0

  const aliceHS = shs.client(
    alice,
    app_key,
    100
  )(wally.publicKey, (err) => {
    t.ok(err, 'Bob hungup')
    if (++errs === 2) t.end()
  })

  const bobHS = shs.server(
    bob,
    unauthorized,
    app_key,
    100
  )((err) => {
    t.ok(err, 'client unauthorized')
    if (++errs === 2) t.end()
  })

  pull(aliceHS, bobHS, aliceHS)
})

tape('test error cb when client get wrong number', (t) => {
  let errs = 0

  const aliceHS = shs.client(
    alice,
    app_key,
    100
  )(crypto.randomBytes(32), (err) => {
    t.ok(err, 'connection failed')
    if (++errs === 2) t.end()
  })

  const bobHS = shs.server(
    bob,
    unauthorized,
    app_key,
    100
  )((err) => {
    console.log(err)
    t.ok(err)
    if (++errs === 2) t.end()
  })

  pull(aliceHS, bobHS, aliceHS)
})

tape('error if created without public key', (t) => {
  const aliceHS = shs.client(alice, app_key, 100)
  t.throws(() => {
    aliceHS()
  })
  t.end()
})

tape('unauthorized connection must cb once', (t) => {
  t.plan(2)
  let n = 2

  const aliceHS = shs.client(alice, app_key, 100)
  const bobHS = shs.server(bob, authorized, app_key, 100)

  const aliceStream = aliceHS(bob.publicKey, (err, stream) => {
    console.log('Alice')
    t.ok(err, 'client connect should fail')
    next()
  })

  pull(
    aliceStream,
    bobHS((err, stream) => {
      console.log('Bob')
      t.ok(err, 'server connect should fail')
      next()
    }),
    aliceStream
  )

  function next() {
    if (--n) return
    t.end()
  }
})

tape('client timeout error if there is no response', function (t) {
  const aliceHS = shs.client(
    alice,
    app_key,
    100
  )(bob.publicKey, (err, stream) => {
    t.ok(err)
    t.end()
  })

  pull(Hang(), aliceHS)
  //do nothing, so aliceHS should timeout
})

tape('server timeout error if there is no response', function (t) {
  const bobHS = shs.server(
    alice,
    authorized,
    app_key,
    100
  )((err, stream) => {
    t.ok(err)
    t.end()
  })

  pull(Hang(), bobHS)
  //do nothing, so aliceHS should timeout
})

tape('test handshake', (t) => {
  const aliceHS = shs.client(null, app_key, 100)(
    bob.publicKey,
    hash('alice'),
    (err, stream) => {
      if (err) t.fail(err.message ?? err)
    }
  )

  const random = Math.random()

  const bobHS = shs.server(
    bob,
    (publicKey, cb) => {
      t.deepEqual(publicKey, alice.publicKey)
      cb(null, { okay: true, random })
    },
    app_key,
    100
  )((err, stream) => {
    if (err) t.fail(err.message ?? err)

    t.deepEqual(stream.auth, { okay: true, random })
    t.end()
  })

  pull(aliceHS, bobHS, aliceHS)
})

tape('toKeys', (t) => {
  t.deepEqual(shs.toKeys(hash('alice')), alice)
  t.deepEqual(shs.toKeys(alice), alice)
  t.end()
})
