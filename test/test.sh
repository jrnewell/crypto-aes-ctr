#!/usr/bin/env bash

cd "./test"
coffee "test-encrypt.coffee"
coffee "test-decrypt.coffee"
coffee "test-partial-decrypt.coffee"

echo "removing generated test files"
rm -f "test-encrypted.enc" "test-decrypted.mp4" "test-partial-decrypted.mp4"
