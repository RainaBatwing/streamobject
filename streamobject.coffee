nacl = require 'tweetnacl/nacl-fast'
BLAKE2s = require 'blake2s-js'
stream = require 'stream'
fs = require 'fs'
bs58 = require 'bs58'

FileStart = "StreamOb"
ChunkSize = 1024*1024
HashIndexBytes = 4
NonceFor = (ephemeralNonce, file_idx, chunk_idx)->
  throw new "nonce length incorrect" if ephemeralNonce.length != EphemeralNonceLength
  nonce = new Uint8Array(nacl.secretbox.nonceLength)
  nonce.set ephemeralNonce
  dataview = new DataView(nonce.buffer, EphemeralNonceLength)
  dataview.setInt16(0, file_idx)
  dataview.setUint32(2, chunk_idx)
  return nonce
EphemeralNonceLength = 18 # random prefix component of CipherPermit nonce
FileID =
  PrivateSection: -1


class StreamObjectReader
  # data argument can be a file descriptor, path string, or a Buffer
  constructor: (options={})->
    # select read mode and do any needed prep
    data = options.data
    throw "data must be provided to constructor" unless data
    if typeof data is 'string'
      # if it's a path, we need to abort and try constructing when it opens
      fs.open data, 'r', null, (err, fd)=>
        return options.callback(err) if err
        # change data source to file descriptor
        options.data = fd
        @constructor(options) # retry constructing
      return
    if typeof data is 'number'
      @_data = data
      @_readData = @_readDataFromFilesystem
    else
      @_data = new Buffer(data)
      @_readData = @_readDataFromBuffer

    @_readData 0, FileStart.length + 4, (err, start)=>
      callback(err) if err
      if start.slice(0, FileStart.length).toString() isnt FileStart
        throw "Provided data is not a StreamObject"
      headerLength = start.readUInt32BE(FileStart.length)
      @_readData start.length, headerLength, (err, rawHeader)=>
        @header = JSON.parse(rawHeader)
        @header.author[key] = new Uint8Array(bs58.decode(value)) for key, value of @header.author
        @_headerEnd = start.length + rawHeader.length
        options.callback(err)

  # pass in an array of recipient secret curve25519 keys to attempt
  unlock:(recipientSecretKeys)->
    return true if @permit
    throw new Error("first argument required") unless recipientSecretKeys?
    # make sure argument is an array
    recipientSecretKeys = [recipientSecretKeys] unless recipientSecretKeys.map?

    # decode hashIndex salt bytes
    audienceSalt = bs58.decode @header.audience.salt

    # generate list of possible shared keys
    sharedKeys = for secretKey in recipientSecretKeys
      secretKey = bs58.decode(secretKey) if typeof(secretKey) is 'string'
      nacl.box.before(@header.author.curve25519, secretKey)

    # try each shared key until one works
    for sharedKey in sharedKeys
      # generate hash index
      digest = new BLAKE2s(HashIndexBytes)
      digest.update audienceSalt
      digest.update sharedKey
      hashIndex = bs58.encode digest.digest()

      # for everything matching this hashIndex, try to unlock permit
      for cipherPermitBase58 in @header.audience[hashIndex] or []
        cipherPermit = new Uint8Array bs58.decode cipherPermitBase58
        permitNonce = cipherPermit.subarray(0, nacl.box.nonceLength)
        permitBox = cipherPermit.subarray(nacl.box.nonceLength)
        permit = nacl.box.open.after(permitBox, permitNonce, sharedKey)

        # try next entry if this one failed unbox
        continue unless permit

        # extract nonce and secret ranges
        permit.nonce = permit.subarray(0, EphemeralNonceLength)
        permit.secret = permit.subarray(EphemeralNonceLength)

        # decrypt private section
        privateBox = nacl.util.decodeBase64(@header.private)
        privateNonce = NonceFor(permit.nonce, -1, 0)
        privatePlain = nacl.secretbox.open(privateBox, privateNonce, permit.secret)

        # try next permit if secretbox open failed (probably mac failure)
        continue unless privatePlain

        # if decrypt succeeds, return decoded object to header
        @permit = permit
        @header.private = JSON.parse(nacl.util.encodeUTF8(privatePlain))
        # and unlock was successful!
        return this
    return false

  # get a list of filenames in this
  list:->
    throw new Error("Cannot read files from locked StreamObject") unless @permit
    return @_list if @_list
    @_list = for [name, type, size] in @header.private.files
      item = ""+name
      item.fileType = type
      item.fileSize = size
      item

  # get a readable stream of any file by name or list() entry
  read:(filename)->
    throw new Error("Cannot read files from locked StreamObject") unless @permit
    # get a list of files in this StreamObject
    fileList = @list()
    # find index of file
    fileIndex = fileList.indexOf(filename)
    return null if fileIndex is -1
    file = fileList[fileIndex]
    # setup decipher stream transformer
    decipher = new ChunkDecipher(chunkSize: ChunkSize, crypto: @permit)
    # calculate start of file
    fileStart = @_headerEnd
    for file in fileList[0...fileIndex]
      overhead = Math.floor(file.fileSize / ChunkSize) * nacl.secretbox.overheadLength
      fileStart += file.fileSize + overhead
    fileEnd = fileStart + file.fileSize

    console.log "file start", fileStart, "file end", fileEnd, "size", file.fileSize
    # stream data in to ChunkDecipher as needed
    topUpDecipher = =>
      if fileStart < fileEnd
        @_readData fileStart, Math.min(fileEnd - fileStart, 1024*128), (err, data)=>
          return decipher.emit("error", err) if err
          morePlz = decipher.write(data)
          if morePlz
            topUpDecipher()
          else
            decipher.once "drain", topUpDecipher
      else
        decipher.end()
    topUpDecipher() # load in the first chunk
    return decipher

  # TODO: add 'validate' function which checks ed25519 signature

  # different implementations of _readData for different data sources
  _readData:(start, length, callback)->
    process.nextTick => callback("constructor didn't override _readData correctly")
  _readDataFromFilesystem:(start, length, callback)->
    buffer = new Buffer(length)
    fs.read @_data, buffer, 0, length, start, (err, bytesRead)->
      return callback(err) if err
      callback(null, buffer.slice(0, bytesRead))
  _readDataFromBuffer:(start, length, callback)->
    process.nextTick => callback(null, @_data.slice(start, start + length))



class StreamObjectWriter
  constructor: (options = {})->
    @author = options.author or {
      curve25519: nacl.box.keyPair()
      ed25519: nacl.sign.keyPair()
    }

    @header =
      id: options.id or bs58.encode(nacl.randomBytes(16))
      author:
        ed25519: bs58.encode @author.ed25519.publicKey
        curve25519: bs58.encode @author.curve25519.publicKey
      version: 'A'
      timestamp: Date.now()
      # section encrypted at write time
      private:
        kind: options.kind or 'post'
        files: []

    @_audienceSalt = nacl.randomBytes(8)
    @header.audience =
      salt: bs58.encode(@_audienceSalt)

    # generate ephemeral keys for secretbox crypto
    ephemeralNonce  = nacl.randomBytes EphemeralNonceLength
    ephemeralSecret = nacl.randomBytes nacl.secretbox.keyLength
    # generate permit blob for distribution of ephemeral keys
    # subarrays reference the same buffer, so they update the main permit
    @permit = new Uint8Array(ephemeralNonce.length + ephemeralSecret.length)
    @permit.nonce  = @permit.subarray(0, ephemeralNonce.length)
    @permit.secret = @permit.subarray(ephemeralNonce.length)
    @permit.nonce.set ephemeralNonce
    @permit.secret.set ephemeralSecret

    # add own keys to audience by default
    @addRecipient @author.curve25519.publicKey

    # create digest object for signing
    @hash = new BLAKE2s(32) # 32-byte blake2s digest
    @files = []

  # add another recipient to this StreamObject
  addRecipient: (publicKey)->
    # decode public key if needed
    publicKey = bs58.decode(publicKey) if publicKey instanceof String
    # calculate shared key for box operation
    sharedKey = nacl.box.before(publicKey, @author.curve25519.secretKey)
    # hash shared key with salt in to 4 bytes
    blake = new BLAKE2s(HashIndexBytes)
    blake.update @_audienceSalt
    blake.update sharedKey
    hashIndex = bs58.encode(blake.digest())
    # generate encrypted permit with random nonce prefixed
    cipherPermit = new Uint8Array(nacl.box.nonceLength + @permit.length + nacl.box.overheadLength)
    permitNonce = nacl.randomBytes(nacl.box.nonceLength)
    permitBox = nacl.box.after(@permit, permitNonce, sharedKey)
    cipherPermit.set permitNonce, 0
    cipherPermit.set permitBox, permitNonce.length
    # add encrypted permit to hash table
    @header.audience[hashIndex] ||= []
    @header.audience[hashIndex].push bs58.encode(cipherPermit)

  # add some bytes from memory to the document
  # data can be node Buffer, Uint8Array, utf8 string
  addFileData: (name, data, type = "text/plain")->
    data = new Buffer(data) unless data.constructor is Buffer

    # object representing this file and it's chunks
    fileInfo =
      name: name
      source: new BufferReadStream(data)
      size: data.length
      type: type
    @files.push fileInfo
    @header.private.files.push [fileInfo.name, fileInfo.type, fileInfo.size]

  # add a file from the local filesystem to the stream object
  addFile: (name, path, type = "")->
    # object representing this file and it's chunks
    fileInfo =
      name: name
      source: fs.createReadStream(path)
      size: fs.statSync(path).size
      type: type
    @files.push fileInfo
    @header.private.files.push [fileInfo.name, fileInfo.type, fileInfo.size]

  # pass in a node writable stream or a string filesystem path
  # writes out file/stream asyncronously then calls on_complete
  write: (raw_stream, callback)->
    # ensure this method can only be used once per instance
    return process.nextTick(->callback?('Already written')) if @written
    @written = true

    # open writable stream to specified path
    raw_stream = fs.createWriteStream(raw_stream) if raw_stream instanceof String
    # pipe blake2s digester in to it - to hash bytes as we write
    stream = new StreamDigester()
    stream.pipe(raw_stream)

    # return errors
    stream.on "error", callback

    # encrypt private section
    @header.private = nacl.util.encodeBase64(
      nacl.secretbox(
        nacl.util.decodeUTF8(JSON.stringify(@header.private)),
        NonceFor(@permit.nonce, FileID.PrivateSection, 0),
        @permit.secret
      )
    )

    # write magic bytes
    stream.write FileStart

    # write json header length and json plaintext
    jsonHeader = JSON.stringify(@header)
    jsonHeaderLength = new Buffer(4)
    jsonHeaderLength.writeUInt32BE Buffer.byteLength(jsonHeader), 0
    stream.write jsonHeaderLength
    stream.write jsonHeader

    # add index property to files
    file.index = fileIndex for file, fileIndex in @files

    # write out files ciphered
    @_writeNextFile stream, @files, (err)=>
      if err
        callback(err)
      else
        # write signature to end
        stream.unpipe()
        stream.on "finish", =>
          digest = stream.digest()
          signature_blob = nacl.sign.detached(digest, @author.ed25519.secretKey)
          raw_stream.on "finish", callback
          raw_stream.end(new Buffer(signature_blob))
        stream.end()

  # write out next file in queue through cipher pipe
  _writeNextFile:(output, files, callback)->
    # if all files are processed, run callback
    return callback() unless files[0]
    # next file to process
    thisFile = files[0]
    # setup chunking cipher
    cipher = new ChunkCipher(fileInfo: thisFile, crypto: @permit)
    thisFile.source.pipe(cipher)
    cipher.on 'readable', =>
      output.write cipher.read()
    cipher.on 'finish', =>
      # process remaining files
      @_writeNextFile(output, files.slice(1), callback)
    cipher.on 'error', (err)=>
      callback(err)


# -----------------------------------------------------------------
# -------------------- Chunking Crypto Streams --------------------
# -----------------------------------------------------------------

# stream out the contents of a file contained inside a StreamObject
class GenericChunkCipher extends stream.Transform
  _inputOverhead: 0
  constructor:(options = {})->
    @chunkSize = (options.chunkSize || ChunkSize) + @_inputOverhead
    @fileInfo = options.fileInfo || {index: -1}
    @_chunkIndex = 0 # index used for nonce on next processed chunk
    @crypto = options.crypto # {secret, nonce} Uint8Array
    @_buffer = new Buffer(0)
    options.highWaterMark = @chunk_size
    super options

  # transform incoming plaintext in to chunks of nacl.secretbox
  _transform:(appendbuf, encoding, done)->
    # append new plaintext to incoming chunk buffer
    @_buffer = Buffer.concat([@_buffer, appendbuf])
    # process next chunk, if we have enough data buffered for a full chunk
    err = @_chunkOut() while @_buffer.length >= @chunkSize
    done(err)

  # if there's anything in buffer, encrypt and output that
  _flush:(done)->
    err = @_chunkOut() while @_buffer.length > 0
    done(err)

  # apply crypto _process the next chunk in the buffer, outputting it
  _chunkOut:()->
    # okay, slice off the first chunk's worth
    input = @_buffer.slice(0, @chunkSize)
    # replace incoming plaintext buffer with leftovers
    @_buffer = @_buffer.slice(@chunkSize)
    # apply crypto function to input chunk
    output = @_process(new Uint8Array(input))
    # check crypto succeeded
    return "Crypto Failure" unless output
    # increment chunk index for next time around
    @_chunkIndex += 1
    # send results in to output buffer
    @push(new Buffer(output))
    return null


# Stream Transform converting ciphered chunks in to plaintext bytes
class ChunkDecipher extends GenericChunkCipher
  _inputOverhead: nacl.secretbox.overheadLength
  _process:(ciphertext)->
    plaintext = nacl.secretbox.open(
      new Uint8Array(ciphertext),
      NonceFor(@crypto.nonce, @fileInfo.index, @_chunkIndex),
      @crypto.secret
    )

# Stream Transform converting bytes in to ciphered chunks
class ChunkCipher extends GenericChunkCipher
  _inputOverhead: 0
  _process:(plaintext)->
    ciphertext = nacl.secretbox(
      new Uint8Array(plaintext),
      NonceFor(@crypto.nonce, @fileInfo.index, @_chunkIndex),
      @crypto.secret
    )

# Generate a BLAKE2s hash of a stream
class StreamDigester extends stream.Transform
  constructor:(options = {})->
    @hash = new BLAKE2s(options.digestLength || 32)
    super options
  # pass through bytes without changing anything
  _transform:(buffer, encoding, done)->
    @hash.update(new Uint8Array(buffer))
    done(null, buffer)
  # fetch hash as 32 raw bytes in Uint8Array
  digest:-> @hash.digest()
  hexDigest:-> @hash.hexDigest()

# -----------------------------------------------------------------
# ---------------- Simple Stream Buffer Interfaces ----------------
# -----------------------------------------------------------------

# provides a Readable Stream interface to a buffer
class BufferReadStream extends stream.Readable
  constructor:(buffer, options = {})->
    @buffer = buffer
    @buffer = new Buffer(@buffer) unless @buffer instanceof Buffer
    @index = 0
    super options
  _read:(size)->
    size = @buffer.length - @index if @index + size > @buffer.length
    slice = @buffer.slice(@index, @index + size)
    @push slice
    @index += size
    @push null if @index >= @buffer.length

# a simple writable stream backed by an in memory buffer
class BufferWriteStream extends stream.Writable
  constructor:(options = {})->
    @buffers = [new Buffer(0)]
    @length = 0
    super options
  # add another buffer to the end
  _write:(chunk, encoding, done)->
    @buffers.push chunk
    @length += chunk.length
    done()
  # get a buffer of the stuff written so far
  getBuffer:()->
    @buffers = [Buffer.concat(@buffers, @length)] unless @buffers.length <= 1
    return @buffers[0]

# export everything
module.exports =
  ChunkCipher: ChunkCipher
  ChunkDecipher: ChunkDecipher
  StreamDigester: StreamDigester
  BufferReadStream: BufferReadStream
  BufferWriteStream: BufferWriteStream
  Reader: StreamObjectReader
  Writer: StreamObjectWriter
