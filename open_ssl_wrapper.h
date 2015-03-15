#ifndef _OPEN_SSL_WRAPPER_H
#define _OPEN_SSL_WRAPPER_H

#include <node.h>
#include <node_object_wrap.h>
#include <openssl/aes.h>

struct ctr_state  {
  unsigned char ivec[AES_BLOCK_SIZE];
  unsigned int num;
  unsigned char ecount[AES_BLOCK_SIZE];
};

class OpenSSLWrapper : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);

 private:
  OpenSSLWrapper();
  ~OpenSSLWrapper();

  static v8::Persistent<v8::Function> constructor;
  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  bool InitIv(const char* key, int key_len, const char* iv, int iv_len, unsigned int counter);
  bool Update(const char* data, int len, unsigned char** out, int* out_len);

  static void InitIv(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Update(const v8::FunctionCallbackInfo<v8::Value>& args);

  void printHexStr(const unsigned char *str, int len);
  void incrementCounter();

  bool initialised_;
  AES_KEY key_;
  struct ctr_state state_;
};

#endif
