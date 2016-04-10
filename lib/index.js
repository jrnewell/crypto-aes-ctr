var crypto = require('crypto');
var _ = require('lodash');

function incrementBuffer(buf, cnt) {
  var i, len, mod;
  len = buf.length;
  i = len - 1;
  while (cnt !== 0) {
    mod = (cnt + buf[i]) % 256;
    cnt = Math.floor((cnt + buf[i]) / 256);
    buf[i] = mod;
    i -= 1;
    if (i < 0) {
      i = len - 1;
    }
  }
  return buf;
};

module.exports = {
  createStream: function (key, iv, counter) {
    if (_.isString(key)) key = new Buffer(key, 'binary');
    if (_.isString(iv)) iv = new Buffer(iv, 'binary');
    if (!_.isNumber(counter)) counter = 0;
    if (iv.length < 16) {
      throw new Error("IV buffer needs to be of length 16");
    }
    iv = incrementBuffer(iv, counter);

    // decrypt and encrypt are the same for aes-256-ctr
    return crypto.createDecipheriv('aes-256-ctr', key, iv);
  }
};
