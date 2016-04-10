# Crypto AES CTR

[![NPM version](http://img.shields.io/npm/v/crypto-aes-ctr.svg)](https://www.npmjs.com/package/crypto-aes-ctr)

A convenience wrapper around node's `aes-256-ctr` cipher stream that allows one to specify the starting `counter` for AES CTR mode.  This gives the option to start reading an AES encrypted file in the middle of the file (i.e. 'seek') vs CBC mode which requires that you start from the beginning.

The `counter` parameter is the AES block index that the file stream is starting at.  The block size of AES is 128 bits or 16 bytes, so you need to start the file steam at a byte location that is a multiple of 16.  See this [wikipedia page](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) for more details on how AES CTR mode works.

## Install

```shell
npm install --save crypto-aes-ctr
```

## Usage

```javascript

var cryptoAesCtr = require("crypto-aes-ctr");
var crypto = require("crypto");

// key is a 32 byte buffer
var key = crypto.pbkdf2Sync(password, salt, iterations, 32);

// iv is an 16 byte buffer (it is important that it is random)
var iv = crypto.randomBytes(16);
var cipherStream = cryptoAesCtr.createStream(key, iv);

// pipe encrypted input stream to cipherStream

```

This example works for both encryption and decryption of an entire file.

If you would like to start decrypting in the middle of a file, you just need to pass in a counter of the AES block you are starting the file stream at (starting from zero).

```javascript

// discard 3 AES blocks
var aesBlockSize = 16;
var counter = 3;

// starting in middle of encrypted file
var fileInStream = fs.createReadStream(myFile, { start: (aesBlockSize * counter) });

// ...

// create cipher stream with correct counter
var cipherStream = cryptoAesCtr.createStream(key, iv, counter);

// pipe encrypted input stream to cipherStream
fileInStream.pipe(cipherStream);

```

## License

[MIT License](http://en.wikipedia.org/wiki/MIT_License)