so = require '../streamobject'
nacl = require 'tweetnacl/nacl-fast'
vows = require 'vows'
assert = require 'assert'
fs = require 'fs'
bs58 = require 'bs58'

suite = vows.describe('Chunk Ciphers, Utilities, and StreamObject abstractions')
suite.addBatch
  # readable stream interface to an in-memory Buffer
  BufferReadStream:
    topic:->
      stream = new so.BufferReadStream("tomato")
      stream.on "readable", =>
        read = stream.read(3)
        @callback(null, read) if read
      stream.on "error", (err)=> @callback(err)
      return
    "reads correctly": (read)->
      assert.equal read.toString(), "tom"
    "reads buffers": (read)->
      assert.instanceOf read, Buffer

  # writable stream which outputs a Buffer of everything written when completed
  BufferWriteStream:
    topic:->
      stream = new so.BufferWriteStream(3)
      stream.on "error", (err)=> @callback(err)
      stream.on "finish", => @callback(null, stream)
      stream.write "pretty"
      stream.end "kitty"
      return
    "buffer is a buffer": (stream)->
      assert.instanceOf stream.getBuffer(), Buffer
    "buffer contains correct data": (stream)->
      assert.equal stream.getBuffer().toString(), "prettykitty"
    "buffer is correct length": (stream)->
      assert.equal stream.getBuffer().length, "prettykitty".length

  # stream which buffers in chunks and encrypts them with nacl.secretbox
  ChunkCipher:
    topic:->
      crypto =
        nonce: nacl.randomBytes(18)
        secret: nacl.randomBytes(nacl.secretbox.keyLength)
      input = new so.BufferReadStream("abc abc ")
      cipher = new so.ChunkCipher(chunkSize: 4, crypto: crypto, fileInfo: {index: 123})
      output = new so.BufferWriteStream
      input.pipe(cipher).pipe(output)
      output.on "finish", => @callback(null, output.getBuffer())
      output.on "error", (err)=> @callback(err)
      return
    "cipher output length is correct":(output)->
      correct = "abc abc ".length + (nacl.secretbox.overheadLength * 2)
      assert.equal output.length, correct
    "cipher isn't reusing nonce":(output)->
      half = output.length / 2
      first = output.slice(0, half)
      second = output.slice(half)
      assert.notEqual nacl.util.encodeBase64(first), nacl.util.encodeBase64(second)

  # stream which buffers in chunks of ciphertext and streams out plaintext
  ChunkDecipher:
    topic:->
      crypto =
        nonce: nacl.randomBytes(18)
        secret: nacl.randomBytes(nacl.secretbox.keyLength)
      input = new so.BufferReadStream("You are wonderful!!")
      cipher = new so.ChunkCipher(chunkSize: 3, crypto: crypto, fileInfo: {index: 1337})
      decipher = new so.ChunkDecipher(chunkSize: 3, crypto: crypto, fileInfo: {index: 1337})
      output = new so.BufferWriteStream
      input.pipe(cipher).pipe(decipher).pipe(output)
      output.on "finish", => @callback(null, output.getBuffer())
      output.on "error", (err)=> @callback(err)
      return
    "output correct":(output)->
      assert.equal output.toString(), "You are wonderful!!"

  # stream which passes through everything it sees, creating a blake2s digest of it
  StreamDigester:
    topic:->
      digester = new so.StreamDigester(digestLength: 16)
      digester.string = ''
      digester.on "finish", => @callback(null, digester)
      digester.on "error", (err)=> @callback(err)
      digester.on "readable", => digester.string += digester.read().toString()
      digester.write "Unikitty "
      digester.end "is the best!"
    hexDigest:(digester)->
      output = digester.hexDigest().toLowerCase()
      assert.equal output, "eb06d018aed2118f4f38428c23a55986"
    digest:(digester)->
      assert.equal digester.digest()[0], 0xEB
      assert.equal digester.digest()[1], 0x06
      assert.equal digester.digest()[2], 0xD0
    "output matches input":(digester)->
      assert.equal digester.string, "Unikitty is the best!"

# generate some random crypto bits for next batch
author =
  curve25519: nacl.box.keyPair()
  ed25519: nacl.sign.keyPair()
bob =
  curve25519: nacl.box.keyPair()
  ed25519: nacl.sign.keyPair()
jessica =
  curve25519: nacl.box.keyPair()
  ed25519: nacl.sign.keyPair()
message = "<p>You guys are wonderful!</p>"

suite.addBatch
  "Writer":
    topic:->
      output = new so.BufferWriteStream
      object = new so.Writer(author: author)
      object.addRecipient jessica.curve25519.publicKey
      object.addFileData "post", message
      object.write output, (err)=> @callback(err, output: output.getBuffer(), object: object)
      return
    "StreamObject.Writer outputs something":(bits)->
      assert.notEqual bits.output.length, 0
    "No nonce reuse in CipherPermits":(bits)->
      nonces = {}
      for hashIndex, permitList of bits.object.header.audience
        continue if hashIndex is "salt"
        for cipherPermitB58 in permitList
          cipherPermit = bs58.decode(cipherPermitB58)
          nonce = bs58.encode(cipherPermit[0...nacl.box.nonceLength])
          assert.equal nonces[nonce], undefined
          nonces[nonce] = true
    "Jessica can unlock with Reader":
      topic:(bits)->
        reader = new so.Reader data: bits.output, callback: (err)=>
          return @callback(err) if err
          # check unlock succeeds
          unlock = reader.unlock(jessica.curve25519.secretKey)
          assert.equal unlock, reader # unlock succeeded if this is correct
          # read out message
          file = new so.BufferWriteStream
          file.on "finish", => @callback(null, file: file.getBuffer(), reader: reader)
          file.on "error", (err)=> @callback(err)
          stream = reader.read("post")
          stream.pipe(file)

        return
      "file read correctly": ({file})->
        assert.equal file.toString(), message


suite.run() # Run tests
