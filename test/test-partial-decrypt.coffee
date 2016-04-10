cryptoAesCtr = require  "../lib"
fs = require "fs"
child_process = require "child_process"

originFile = "test-origin.mp4"
partialOriginFile = "test-partial-origin.mp4"
encryptedFile = "test-encrypted.enc"
decryptedFile = "test-partial-decrypted.mp4"

key = new Buffer("8fbf35890fc3e0d5bc615cb091f16e8d40cfe3d4223cd68b11e2e7204d890210", "hex")
iv = new Buffer("4395a3ded2f0040835d437cc9fa7a7dc", "hex")

offset = 3125
byteOffset = (16 * offset)

console.log "creating partial file to compare against"
child_process.execSync "tail -c +#{byteOffset} #{originFile} > #{partialOriginFile}"

fileInStream = fs.createReadStream(encryptedFile, {start: (16 * offset)})
fileInStream.once 'readable', () ->

  cipherStream = cryptoAesCtr.createStream key, iv, offset

  fileInStream.pipe(cipherStream)

  cipherStream.once 'readable', () ->

    fileOutStream = fs.createWriteStream(decryptedFile)

    cipherStream.pipe(fileOutStream)

    fileOutStream.on 'finish', () ->
      console.log "partial decryption finished"

      child_process.exec "cmp -q #{partialOriginFile} #{decryptedFile}", (err, stdin, stdout) ->
        if err?
          console.log "passed: origin file and decrypted file are the same"
        else
          console.log "failed: origin file and decrypted file are NOT the same"

