#define BUILDING_NODE_EXTENSION 1
#include <node.h>
#include "open_ssl_wrapper.h"

using namespace v8;

Handle<Value> CreateObject(const Arguments& args) {
  HandleScope scope;
  return scope.Close(OpenSSLWrapper::NewInstance(args));
}

void InitAll(Handle<Object> exports, Handle<Object> module) {
  OpenSSLWrapper::Init();

  module->Set(String::NewSymbol("exports"),
      FunctionTemplate::New(CreateObject)->GetFunction());
}

NODE_MODULE(addon, InitAll)
