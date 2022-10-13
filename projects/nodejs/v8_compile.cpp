// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "libplatform.h"
#include "v8.h"
#include <fstream>
#include <limits>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

__AFL_FUZZ_INIT();
int main(int argc, char *argv[]) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  // Initialize V8.
  v8::V8::InitializeICUDefaultLocation(argv[0]);
  v8::V8::InitializeExternalStartupData(argv[0]);
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();
  // Create a new Isolate and make it the current one.
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate *isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    // Create a stack-allocated handle scope.
    v8::HandleScope handle_scope(isolate);
    // Create a new context.
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    // Enter the context for compiling and running the hello world script.
    v8::Context::Scope context_scope(context);
    unsigned char *buffer = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
      size_t len = __AFL_FUZZ_TESTCASE_LEN;
      char *buf = (char*) calloc(len + 1, sizeof(char));
      memcpy(buf, buffer, len);
      v8::Local<v8::String> source =
          v8::String::NewFromUtf8(isolate, buf).ToLocalChecked();
      v8::Local<v8::Value> result;
      // Compile the source code.
      v8::Local<v8::Script> script;
      v8::Script::Compile(context, source).ToLocal(&script);
      free(buf);
      if (script.IsEmpty())
        goto exit;
      else {
        script->Run(context).ToLocal(&result);
        if (result.IsEmpty())
          goto exit;
      }
    }
  }
// Dispose the isolate and tear down V8.
exit:
  isolate->Dispose();
  v8::V8::Dispose();
  v8::V8::ShutdownPlatform();
  delete create_params.array_buffer_allocator;
  return 0;
}
