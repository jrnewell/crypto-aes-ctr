#include <node.h>
#include "open_ssl_wrapper.h"

using namespace v8;

void InitAll(Handle<Object> exports) {
  OpenSSLWrapper::Init(exports);
}

NODE_MODULE(addon, InitAll)
