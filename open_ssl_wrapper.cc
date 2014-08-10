#define BUILDING_NODE_EXTENSION 1
#include <node.h>
#include <openssl/aes.h>
#include <node_buffer.h>
#include <string_bytes.h>
#include "open_ssl_wrapper.h"

using node::encoding;
using node::BINARY;
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
  tpl->PrototypeTemplate()->Set(String::NewSymbol("plusOne"),
      FunctionTemplate::New(PlusOne)->GetFunction());

  constructor = Persistent<Function>::New(tpl->GetFunction());
}

Handle<Value> OpenSSLWrapper::New(const Arguments& args) {
  HandleScope scope;

  OpenSSLWrapper* obj = new OpenSSLWrapper();
  obj->counter_ = args[0]->IsUndefined() ? 0 : args[0]->NumberValue();
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

Handle<Value> OpenSSLWrapper::PlusOne(const Arguments& args) {
  HandleScope scope;

  OpenSSLWrapper* obj = ObjectWrap::Unwrap<OpenSSLWrapper>(args.This());
  obj->counter_ += 1;

  return scope.Close(Number::New(obj->counter_));
}

void OpenSSLWrapper::InitIv(const char* key, int key_len, const char* iv, int iv_len, unsigned int counter) {
  HandleScope scope;

  if (AES_set_encrypt_key((const unsigned char *)key, key_len * 8, &key_) < 0) {
    ThrowException(Exception::Error(String::New("Could not set decryption key.")));
    return;
  }

  // aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the first call.
  state_.num = 0;
  memset(state_.ecount, 0, AES_BLOCK_SIZE);

  // Initialise counter in 'ivec' to 0
  memset(state_.ivec + 8, 0, 8);

  // Copy 8 bytes of IV into 'ivec'
  memcpy(state_.ivec, iv, 8);

  initialised_ = true;
}

bool OpenSSLWrapper::Update(const char* data, int len, unsigned char** out, int* out_len) {
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

  ASSERT_IS_BUFFER(args[1]);
  ASSERT_IS_BUFFER(args[2]);

  ssize_t key_len = Buffer::Length(args[0]);
  const char* key_buf = Buffer::Data(args[0]);
  ssize_t iv_len = Buffer::Length(args[1]);
  const char* iv_buf = Buffer::Data(args[1]);
  unsigned int counter = args[0]->Uint32Value();

  base->InitIv(key_buf, key_len, iv_buf, iv_len, counter);

  return scope.Close(Undefined());
}

Handle<Value> OpenSSLWrapper::Update(const Arguments& args) {
  HandleScope scope;

  OpenSSLWrapper* base = Unwrap<OpenSSLWrapper>(args.Holder());

  ASSERT_IS_STRING_OR_BUFFER(args[0]);

  unsigned char* out = NULL;
  bool r;
  int out_len = 0;

  // Only copy the data if we have to, because it's a string
  if (args[0]->IsString()) {
    Local<String> string = args[0].As<String>();
    encoding encoding = ParseEncoding(args[1], BINARY);
    if (!StringBytes::IsValidString(string, encoding)) {
      return ThrowException(Exception::TypeError(String::New("Bad input string")));
      //return;
    }
    size_t buflen = StringBytes::StorageSize(string, encoding);
    char* buf = new char[buflen];
    size_t written = StringBytes::Write(
                                        buf,
                                        buflen,
                                        string,
                                        encoding);
    r = base->Update(buf, written, &out, &out_len);
    delete[] buf;
  } else {
    char* buf = Buffer::Data(args[0]);
    size_t buflen = Buffer::Length(args[0]);
    r = base->Update(buf, buflen, &out, &out_len);
  }

  if (!r) {
    delete[] out;
    return ThrowException(Exception::Error(String::New("Trying to add data in unsupported state")));
    //return;
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
