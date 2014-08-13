#define BUILDING_NODE_EXTENSION 1
#include <node.h>
#include <openssl/aes.h>
#include <node_buffer.h>
#include <util.h>
#include "string_bytes.h"
#include "open_ssl_wrapper.h"

#if defined(_WIN32) || defined(_WIN64)
  #define snprintf _snprintf
  #define vsnprintf _vsnprintf
  #define strcasecmp _stricmp
  #define strncasecmp _strnicmp
#endif

using node::encoding;
using node::UTF8;
using node::ASCII;
using node::BASE64;
using node::UCS2;
using node::BINARY;
using node::BUFFER;
using node::HEX;
using node::Buffer;
using node::StringBytes;

#define ASSERT_IS_STRING_OR_BUFFER(val) do {                  \
    if (!Buffer::HasInstance(val) && !val->IsString()) {      \
      return ThrowException(Exception::TypeError(String::New("Not a string or buffer"))); \
    }                                                         \
  } while (0)

#define ASSERT_IS_BUFFER(val) do {                            \
    if (!Buffer::HasInstance(val)) {                          \
      return ThrowException(Exception::TypeError(String::New("Not a buffer"))); \
    }                                                         \
  } while (0)

using namespace v8;

OpenSSLWrapper::OpenSSLWrapper() : initialised_(false)
{};

OpenSSLWrapper::~OpenSSLWrapper() {};

Persistent<Function> OpenSSLWrapper::constructor;

void OpenSSLWrapper::Init() {
  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
  tpl->SetClassName(String::NewSymbol("OpenSSLWrapper"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
  // Prototype
  tpl->PrototypeTemplate()->Set(String::NewSymbol("init"),
      FunctionTemplate::New(InitIv)->GetFunction());
  tpl->PrototypeTemplate()->Set(String::NewSymbol("update"),
      FunctionTemplate::New(Update)->GetFunction());

  constructor = Persistent<Function>::New(tpl->GetFunction());
}

Handle<Value> OpenSSLWrapper::New(const Arguments& args) {
  HandleScope scope;

  OpenSSLWrapper* obj = new OpenSSLWrapper();
  obj->Wrap(args.This());

  return args.This();
}

Handle<Value> OpenSSLWrapper::NewInstance(const Arguments& args) {
  HandleScope scope;

  const unsigned argc = 1;
  Handle<Value> argv[argc] = { args[0] };
  Local<Object> instance = constructor->NewInstance(argc, argv);

  return scope.Close(instance);
}

void OpenSSLWrapper::printHexStr(const unsigned char *str, int len) {
  for (int i = 0; i < len; i++) {
    const unsigned char* p = str + i;
    printf("%02x", *p);
  }
}

void OpenSSLWrapper::incrementCounter() {
  int n=8;
  unsigned char c;

  do {
    --n;
    c = state_.ivec[8 + n];
    ++c;
    state_.ivec[8 + n] = c;
    if (c) return;
  } while (n);
}

bool OpenSSLWrapper::InitIv(const char* key, int key_len, const char* iv, int iv_len, unsigned int counter) {
  HandleScope scope;

  if (AES_set_encrypt_key((const unsigned char *)key, key_len * 8, &key_) < 0) {
    return false;
  }

  // aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the first call.
  state_.num = 0;
  memset(state_.ecount, 0, AES_BLOCK_SIZE);

  // Initialise counter in 'ivec' to 0
  memset(state_.ivec + 8, 0, 8);

  // Copy 8 bytes of IV into 'ivec'
  memcpy(state_.ivec, iv, 8);

  // increment starting counter in 'ivec'
  for(unsigned int i = 0; i < counter; i++) {
    incrementCounter();
  }

  initialised_ = true;
  return true;
}

bool OpenSSLWrapper::Update(const char* data, int len, unsigned char** out, int* out_len) {
  HandleScope scope;

  if (!initialised_)
    return false;

  *out_len = len;
  *out = new unsigned char[*out_len];
  AES_ctr128_encrypt((const unsigned char*)data, *out, len, &key_, state_.ivec, state_.ecount, &state_.num);

  return true;
}

Handle<Value> OpenSSLWrapper::InitIv(const Arguments& args) {
  HandleScope scope;

  OpenSSLWrapper* base = Unwrap<OpenSSLWrapper>(args.Holder());

  if (args.Length() < 3 || !args[2]->IsNumber()) {
    return ThrowException(Exception::TypeError(String::New("Must give key, iv and count as arguments")));
  }

  ASSERT_IS_BUFFER(args[0]);
  ASSERT_IS_BUFFER(args[1]);

  ssize_t key_len = Buffer::Length(args[0]);
  const char* key_buf = Buffer::Data(args[0]);
  ssize_t iv_len = Buffer::Length(args[1]);
  const char* iv_buf = Buffer::Data(args[1]);
  unsigned int counter = args[2]->Uint32Value();

  if (!base->InitIv(key_buf, (int)key_len, iv_buf, (int)iv_len, counter)) {
    return ThrowException(Exception::Error(String::New("Could not set encryption key.")));
  }

  return scope.Close(Undefined());
}

Handle<Value> OpenSSLWrapper::Update(const Arguments& args) {
  HandleScope scope;

  OpenSSLWrapper* base = Unwrap<OpenSSLWrapper>(args.Holder());

  ASSERT_IS_STRING_OR_BUFFER(args[0]);

  unsigned char* out = NULL;
  bool ret_val;
  int out_len = 0;

  // Only copy the data if we have to, because it's a string
  if (args[0]->IsString()) {
    Local<String> string = args[0].As<String>();
    encoding encoding = OpenSSLWrapper::ParseEncoding(args[1], BINARY);
    if (!StringBytes::IsValidString(string, encoding)) {
      return ThrowException(Exception::TypeError(String::New("Bad input string")));
    }
    size_t buflen = StringBytes::StorageSize(string, encoding);
    char* buf = new char[buflen];
    size_t written = StringBytes::Write(buf, buflen, string, encoding);
    ret_val = base->Update(buf, (int)written, &out, &out_len);
    delete[] buf;
  }
  else {
    char* buf = Buffer::Data(args[0]);
    size_t buflen = Buffer::Length(args[0]);
    ret_val = base->Update(buf, (int)buflen, &out, &out_len);
  }

  if (!ret_val) {
    delete[] out;
    return ThrowException(Exception::Error(String::New("Trying to add data in unsupported state")));
  }

  Buffer* buf = Buffer::New(reinterpret_cast<char*>(out), out_len);
  if (out) {
    delete[] out;
  }

  v8::Local<v8::Object> globalObj = v8::Context::GetCurrent()->Global();
  v8::Local<v8::Function> bufferConstructor = v8::Local<v8::Function>::Cast(globalObj->Get(v8::String::New("Buffer")));
  v8::Handle<v8::Value> constructorArgs[3] = { buf->handle_, v8::Integer::New(out_len), v8::Integer::New(0) };
  v8::Local<v8::Object> actualBuffer = bufferConstructor->NewInstance(3, constructorArgs);
  return scope.Close(actualBuffer);
}

int node::WRITE_UTF8_FLAGS = v8::String::HINT_MANY_WRITES_EXPECTED |
                             v8::String::NO_NULL_TERMINATION |
                             v8::String::REPLACE_INVALID_UTF8;

enum encoding OpenSSLWrapper::ParseEncoding(Handle<Value> encoding_v, enum encoding _default) {
  HandleScope scope;

  if (!encoding_v->IsString()) return _default;

  node::Utf8Value encoding(encoding_v);

  if (strcasecmp(*encoding, "utf8") == 0) {
    return UTF8;
  } else if (strcasecmp(*encoding, "utf-8") == 0) {
    return UTF8;
  } else if (strcasecmp(*encoding, "ascii") == 0) {
    return ASCII;
  } else if (strcasecmp(*encoding, "base64") == 0) {
    return BASE64;
  } else if (strcasecmp(*encoding, "ucs2") == 0) {
    return UCS2;
  } else if (strcasecmp(*encoding, "ucs-2") == 0) {
    return UCS2;
  } else if (strcasecmp(*encoding, "utf16le") == 0) {
    return UCS2;
  } else if (strcasecmp(*encoding, "utf-16le") == 0) {
    return UCS2;
  } else if (strcasecmp(*encoding, "binary") == 0) {
    return BINARY;
  } else if (strcasecmp(*encoding, "buffer") == 0) {
    return BUFFER;
  } else if (strcasecmp(*encoding, "hex") == 0) {
    return HEX;
  } else if (strcasecmp(*encoding, "raw") == 0) {
    return BINARY;
  } else if (strcasecmp(*encoding, "raws") == 0) {
    return BINARY;
  } else {
    return _default;
  }
}
