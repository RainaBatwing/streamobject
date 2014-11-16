slownacl = require 'tweetnacl/nacl'
nacl = require 'tweetnacl/nacl-fast'

keyA = nacl.box.keyPair()
keyB = nacl.box.keyPair()
keyC = nacl.box.keyPair()
testplain = nacl.util.decodeUTF8 "If I could go anywhere it would be outer space"
testnonce = nacl.randomBytes(24)
testcipher = nacl.box(testplain, testnonce, keyB.publicKey, keyA.secretKey)

console.time '10 nacl-fast box'
for i in [0... 10]
  nacl.box(testplain, testnonce, keyA.publicKey, keyC.secretKey)
console.timeEnd '10 nacl-fast box'

console.time '10 nacl box'
for i in [0... 10]
  slownacl.box(testplain, testnonce, keyA.publicKey, keyC.secretKey)
console.timeEnd '10 nacl box'

console.time '100 box.before'
for i in [0... 100]
  nacl.box.before(keyA.publicKey, keyC.secretKey)
console.timeEnd '100 box.before'

sharedKey = nacl.box.before(keyA.publicKey, keyB.secretKey)
console.time '1000 box.after valid'
for i in [0... 1000]
  nacl.box.open.after(testcipher, testnonce, sharedKey)
console.timeEnd '1000 box.after valid'

sharedKey = nacl.box.before(keyA.publicKey, keyC.secretKey)
console.time '1000 box.after fail'
for i in [0... 1000]
  nacl.box.open.after(testcipher, testnonce, sharedKey)
console.timeEnd '1000 box.after fail'
