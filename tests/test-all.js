// Generated by CoffeeScript 1.8.0
(function() {
  var assert, author, bob, bs58, fs, jessica, message, nacl, so, suite, vows;

  so = require('../streamobject');

  nacl = require('tweetnacl/nacl-fast');

  vows = require('vows');

  assert = require('assert');

  fs = require('fs');

  bs58 = require('bs58');

  suite = vows.describe('Chunk Ciphers, Utilities, and StreamObject abstractions');

  suite.addBatch({
    BufferReadStream: {
      topic: function() {
        var stream;
        stream = new so.BufferReadStream("tomato");
        stream.on("readable", (function(_this) {
          return function() {
            var read;
            read = stream.read(3);
            if (read) {
              return _this.callback(null, read);
            }
          };
        })(this));
        stream.on("error", (function(_this) {
          return function(err) {
            return _this.callback(err);
          };
        })(this));
      },
      "reads correctly": function(read) {
        return assert.equal(read.toString(), "tom");
      },
      "reads buffers": function(read) {
        return assert.instanceOf(read, Buffer);
      }
    },
    BufferWriteStream: {
      topic: function() {
        var stream;
        stream = new so.BufferWriteStream(3);
        stream.on("error", (function(_this) {
          return function(err) {
            return _this.callback(err);
          };
        })(this));
        stream.on("finish", (function(_this) {
          return function() {
            return _this.callback(null, stream);
          };
        })(this));
        stream.write("pretty");
        stream.end("kitty");
      },
      "buffer is a buffer": function(stream) {
        return assert.instanceOf(stream.getBuffer(), Buffer);
      },
      "buffer contains correct data": function(stream) {
        return assert.equal(stream.getBuffer().toString(), "prettykitty");
      },
      "buffer is correct length": function(stream) {
        return assert.equal(stream.getBuffer().length, "prettykitty".length);
      }
    },
    ChunkCipher: {
      topic: function() {
        var cipher, crypto, input, output;
        crypto = {
          nonce: nacl.randomBytes(18),
          secret: nacl.randomBytes(nacl.secretbox.keyLength)
        };
        input = new so.BufferReadStream("abc abc ");
        cipher = new so.ChunkCipher({
          chunkSize: 4,
          crypto: crypto
        });
        output = new so.BufferWriteStream;
        input.pipe(cipher).pipe(output);
        output.on("finish", (function(_this) {
          return function() {
            return _this.callback(null, output.getBuffer());
          };
        })(this));
        output.on("error", (function(_this) {
          return function(err) {
            return _this.callback(err);
          };
        })(this));
      },
      "cipher output length is correct": function(output) {
        var correct;
        correct = "abc abc ".length + (nacl.secretbox.overheadLength * 2);
        return assert.equal(output.length, correct);
      },
      "cipher isn't reusing nonce": function(output) {
        var first, half, second;
        half = output.length / 2;
        first = output.slice(0, half);
        second = output.slice(half);
        return assert.notEqual(nacl.util.encodeBase64(first), nacl.util.encodeBase64(second));
      }
    },
    ChunkDecipher: {
      topic: function() {
        var cipher, crypto, decipher, input, output;
        crypto = {
          nonce: nacl.randomBytes(18),
          secret: nacl.randomBytes(nacl.secretbox.keyLength)
        };
        input = new so.BufferReadStream("You are wonderful!");
        cipher = new so.ChunkCipher({
          chunkSize: 3,
          crypto: crypto
        });
        decipher = new so.ChunkDecipher({
          chunkSize: 3,
          crypto: crypto
        });
        output = new so.BufferWriteStream;
        input.pipe(cipher).pipe(decipher).pipe(output);
        output.on("finish", (function(_this) {
          return function() {
            return _this.callback(null, output.getBuffer());
          };
        })(this));
        output.on("error", (function(_this) {
          return function(err) {
            return _this.callback(err);
          };
        })(this));
      },
      "output correct": function(output) {
        return assert.equal(output.toString(), "You are wonderful!");
      }
    },
    StreamDigester: {
      topic: function() {
        var digester;
        digester = new so.StreamDigester({
          digestLength: 16
        });
        digester.string = '';
        digester.on("finish", (function(_this) {
          return function() {
            return _this.callback(null, digester);
          };
        })(this));
        digester.on("error", (function(_this) {
          return function(err) {
            return _this.callback(err);
          };
        })(this));
        digester.on("readable", (function(_this) {
          return function() {
            return digester.string += digester.read().toString();
          };
        })(this));
        digester.write("Unikitty ");
        return digester.end("is the best!");
      },
      hexDigest: function(digester) {
        var output;
        output = digester.hexDigest().toLowerCase();
        return assert.equal(output, "eb06d018aed2118f4f38428c23a55986");
      },
      digest: function(digester) {
        assert.equal(digester.digest()[0], 0xEB);
        assert.equal(digester.digest()[1], 0x06);
        return assert.equal(digester.digest()[2], 0xD0);
      },
      "output matches input": function(digester) {
        return assert.equal(digester.string, "Unikitty is the best!");
      }
    }
  });

  author = {
    curve25519: nacl.box.keyPair(),
    ed25519: nacl.sign.keyPair()
  };

  bob = {
    curve25519: nacl.box.keyPair(),
    ed25519: nacl.sign.keyPair()
  };

  jessica = {
    curve25519: nacl.box.keyPair(),
    ed25519: nacl.sign.keyPair()
  };

  message = "<p>You guys are wonderful!</p>";

  suite.addBatch({
    "Writer": {
      topic: function() {
        var object, output;
        output = new so.BufferWriteStream;
        object = new so.Writer({
          author: author
        });
        object.addRecipient(jessica.curve25519.publicKey);
        object.addFileData("post", message);
        object.write(output, (function(_this) {
          return function(err) {
            return _this.callback(err, {
              output: output.getBuffer(),
              object: object
            });
          };
        })(this));
      },
      "StreamObject.Writer outputs something": function(bits) {
        return assert.notEqual(bits.output.length, 0);
      },
      "No nonce reuse in CipherPermits": function(bits) {
        var cipherPermit, cipherPermitB58, hashIndex, nonce, nonces, permitList, _ref, _results;
        nonces = {};
        _ref = bits.object.header.audience;
        _results = [];
        for (hashIndex in _ref) {
          permitList = _ref[hashIndex];
          if (hashIndex === "salt") {
            continue;
          }
          _results.push((function() {
            var _i, _len, _results1;
            _results1 = [];
            for (_i = 0, _len = permitList.length; _i < _len; _i++) {
              cipherPermitB58 = permitList[_i];
              cipherPermit = bs58.decode(cipherPermitB58);
              nonce = bs58.encode(cipherPermit.slice(0, nacl.box.nonceLength));
              assert.equal(nonces[nonce], void 0);
              _results1.push(nonces[nonce] = true);
            }
            return _results1;
          })());
        }
        return _results;
      },
      "Jessica can read with Reader": {
        topic: function(bits) {
          var reader;
          reader = new so.Reader({
            data: bits.output,
            callback: (function(_this) {
              return function(err) {
                var file;
                if (err) {
                  return callback(err);
                }
                assert.notEqual(reader.unlock(jessica.curve25519.secretKey), false);
                file = new so.BufferWriteStream;
                file.on("finish", function() {
                  return _this.callback(null, {
                    file: file.getBuffer(),
                    reader: reader
                  });
                });
                file.on("error", function(err) {
                  return _this.callback(err);
                });
                return reader.read("post").pipe(file);
              };
            })(this)
          });
        },
        "file read correctly": function(bits) {
          return assert.equal(bits.file.toString(), message);
        }
      }
    }
  });

  suite.run();

}).call(this);