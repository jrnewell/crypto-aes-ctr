var util = require('util');
var _ = require('lodash');
var Transform = require('stream').Transform;
var newOpenSSLWrapper = require('./build/Release/addon');

util.inherits(CryptoAesStream, Transform);

function CryptoAesStream(openSSLWrapper, opt) {
  if (!(this instanceof CryptoAesStream)) {
    return new CryptoAesStream(opt);
  }

  if (typeof openSSLWrapper === "undefined" || openSSLWrapper === null) {
    console.error("CryptoAesStream Error: need to pass in openSSLWrapper");
  }

  Transform.call(this, opt);

  this._openSSLWrapper = openSSLWrapper;
  this._counter = 0;
}

CryptoAesStream.prototype._transform = function(chunk, encoding, cb) {
  var _chunk = (_.isString(chunk) ? new Buffer(chunk, encoding) : chunk);

  var outBuff = this._openSSLWrapper.update(_chunk);
  try {
    if (outBuff && outBuff.length > 0) {
      this.push(outBuff);
    }
  }
  catch(err) {
    return cb(err);
  }
  cb();

};

module.exports = {
  createStream: function (key, iv, counter) {
    if (_.isString(key)) key = new Buffer(key, 'binary');
    if (_.isString(iv)) iv = new Buffer(iv, 'binary');
    if (!_.isNumber(counter)) counter = 0;
    if (iv.length < 8) {
      throw new Error("IV buffer needs to be of length 8");
    }
    var openSSLWrapper = newOpenSSLWrapper()
    openSSLWrapper.init(key, iv, counter);
    return new CryptoAesStream(openSSLWrapper, {});
  }
};
