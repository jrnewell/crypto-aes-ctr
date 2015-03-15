#include <stdlib.h>
#include <string.h>
#include <node.h>
#include <openssl/aes.h>
#include <node_buffer.h>
#include <util.h>
#include "string_bytes.h"
#include "open_ssl_wrapper.h"

using node::encoding;
using node::BINARY;
using node::StringBytes;

#define ASSERT_IS_STRING_OR_BUFFER(val) do {                  \
    if (!node::Buffer::HasInstance(val) && !val->IsString()) {      \
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Not a string or buffer"))); \
      return; \
    }                                                         \
  } while (0)

#define ASSERT_IS_BUFFER(val) do {                            \
    if (!node::Buffer::HasInstance(val)) {                          \
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Not a buffer"))); \
      return; \
    }                                                         \
  } while (0)

using namespace v8;

OpenSSLWrapper::OpenSSLWrapper() : initialised_(false)
{};

OpenSSLWrapper::~OpenSSLWrapper() {};

Persistent<Function> OpenSSLWrapper::constructor;

void OpenSSLWrapper::Init(Handle<Object> exports) {
  Isolate* isolate = Isolate::GetCurrent();

  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
  tpl->SetClassName(String::NewFromUtf8(isolate, "OpenSSLWrapper"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  NODE_SET_PROTOTYPE_METHOD(tpl, "init", InitIv);
  NODE_SET_PROTOTYPE_METHOD(tpl, "update", Update);

  constructor.Reset(isolate, tpl->GetFunction());
  exports->Set(String::NewFromUtf8(isolate, "OpenSSLWrapper"), tpl->GetFunction());
}

void OpenSSLWrapper::New(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  if (args.IsConstructCall()) {
    // Invoked as constructor: `new OpenSSLWrapper(...)`
    OpenSSLWrapper* obj = new OpenSSLWrapper();
    obj->Wrap(args.This());
    args.GetReturnValue().Set(args.This());
  } else {
    // Invoked as plain function `OpenSSLWrapper(...)`, turn into construct call.
    const int argc = 0;
    Local<Value> argv[argc] = {};
    Local<Function> cons = Local<Function>::New(isolate, constructor);
    args.GetReturnValue().Set(cons->NewInstance(argc, argv));
  }
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

  if (!initialised_)
    return false;

  *out_len = len;
  *out = new unsigned char[*out_len];
  AES_ctr128_encrypt((const unsigned char*)data, *out, len, &key_, state_.ivec, state_.ecount, &state_.num);

  return true;
}

void OpenSSLWrapper::InitIv(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  OpenSSLWrapper* base = ObjectWrap::Unwrap<OpenSSLWrapper>(args.Holder());

  if (args.Length() < 3 || !args[2]->IsNumber()) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Must give key, iv and count as arguments")));
    return;
  }

  ASSERT_IS_BUFFER(args[0]);
  ASSERT_IS_BUFFER(args[1]);

  ssize_t key_len = node::Buffer::Length(args[0]);
  const char* key_buf = node::Buffer::Data(args[0]);
  ssize_t iv_len = node::Buffer::Length(args[1]);
  const char* iv_buf = node::Buffer::Data(args[1]);
  unsigned int counter = args[2]->Uint32Value();

  if (!base->InitIv(key_buf, (int)key_len, iv_buf, (int)iv_len, counter)) {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Could not set encryption key.")));
    return;
  }

  return;
}

void OpenSSLWrapper::Update(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  OpenSSLWrapper* base = ObjectWrap::Unwrap<OpenSSLWrapper>(args.Holder());

  ASSERT_IS_STRING_OR_BUFFER(args[0]);

  unsigned char* out = NULL;
  bool ret_val;
  int out_len = 0;

  // Only copy the data if we have to, because it's a string
  if (args[0]->IsString()) {
    Local<String> string = args[0].As<String>();
    encoding encoding = node::ParseEncoding(isolate, args[1], BINARY);
    if (!StringBytes::IsValidString(string, encoding)) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Bad input string")));
      return;
    }
    size_t buflen = StringBytes::StorageSize(string, encoding);
    char* buf = new char[buflen];
    size_t written = StringBytes::Write(buf, buflen, string, encoding);
    ret_val = base->Update(buf, (int)written, &out, &out_len);
    delete[] buf;
  }
  else {
    char* buf = node::Buffer::Data(args[0]);
    size_t buflen = node::Buffer::Length(args[0]);
    ret_val = base->Update(buf, (int)buflen, &out, &out_len);
  }

  if (!ret_val) {
    delete[] out;
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Trying to add data in unsupported state")));
    return;
  }

  v8::Local<v8::Object> buf = node::Buffer::New(isolate, reinterpret_cast<char*>(out), out_len);
  if (out) {
    delete[] out;
  }

  args.GetReturnValue().Set(buf);
  return;
}
