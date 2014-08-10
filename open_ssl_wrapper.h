#define BUILDING_NODE_EXTENSION 1
#ifndef _OPEN_SSL_WRAPPER_H
#define _OPEN_SSL_WRAPPER_H

#include <node.h>
#include <openssl/aes.h>

struct ctr_state  {
  unsigned char ivec[AES_BLOCK_SIZE];
  unsigned int num;
  unsigned char ecount[AES_BLOCK_SIZE];
};

class OpenSSLWrapper : public node::ObjectWrap {
 public:
  static void Init();
  static v8::Handle<v8::Value> NewInstance(const v8::Arguments& args);

 private:
  OpenSSLWrapper();
  ~OpenSSLWrapper();

  static v8::Persistent<v8::Function> constructor;
  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  static v8::Handle<v8::Value> PlusOne(const v8::Arguments& args);

  void InitIv(const char* key, int key_len, const char* iv, int iv_len, unsigned int counter);
  bool Update(const char* data, int len, unsigned char** out, int* out_len);

  static v8::Handle<v8::Value> InitIv(const v8::Arguments& args);
  static v8::Handle<v8::Value> Update(const v8::Arguments& args);

  double counter_;
  bool initialised_;
  AES_KEY key_;
  struct ctr_state state_;

};

#endif
