cryptoAesCtr = require "../lib"
fs = require "fs"
child_process = require "child_process"

originFile = "test-origin.mp4"
encryptedFile = "test-encrypted.enc"
decryptedFile = "test-decrypted.mp4"

key = new Buffer("8fbf35890fc3e0d5bc615cb091f16e8d40cfe3d4223cd68b11e2e7204d890210", "hex")
iv = new Buffer("4395a3ded2f0040835d437cc9fa7a7dc", "hex")

fileInStream = fs.createReadStream(encryptedFile)
fileInStream.once 'readable', () ->

  cipherStream = cryptoAesCtr.createStream key, iv, 0

  fileInStream.pipe(cipherStream)

  cipherStream.once 'readable', () ->

    fileOutStream = fs.createWriteStream(decryptedFile)

    cipherStream.pipe(fileOutStream)

    fileOutStream.on 'finish', () ->
      console.log "file decryption finished"

      child_process.exec "cmp -q #{originFile} #{decryptedFile}", (err, stdin, stdout) ->
        if err?
          console.log "passed: origin file and decrypted file are the same"
        else
          console.log "failed: origin file and decrypted file are NOT the same"

