cryptoAesCtr = require  "../lib"
fs = require "fs"

originFile = "test-origin.mp4"
encryptedFile = "test-encrypted.enc"

key = new Buffer("8fbf35890fc3e0d5bc615cb091f16e8d40cfe3d4223cd68b11e2e7204d890210", "hex")
iv = new Buffer("4395a3ded2f0040835d437cc9fa7a7dc", "hex")

fileInStream = fs.createReadStream(originFile)
fileInStream.once 'readable', () ->

  cipherStream = cryptoAesCtr.createStream key, iv

  fileInStream.pipe(cipherStream)

  cipherStream.once 'readable', () ->

    fileOutStream = fs.createWriteStream(encryptedFile)

    cipherStream.pipe(fileOutStream)

    fileOutStream.on 'finish', () ->
      console.log "file encryption finished"
