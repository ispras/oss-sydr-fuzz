// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "libplatform/libplatform.h"
#include "v8.h"
#include <fstream>
#include <limits>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

std::unique_ptr<v8::Platform> platform;
v8::Isolate::CreateParams create_params;
v8::Isolate *isolate;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  v8::V8::InitializeICUDefaultLocation((*argv)[0]);
  v8::V8::InitializeExternalStartupData((*argv)[0]);
  platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();
  create_params.array_buffer_allocator =
    v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  isolate = v8::Isolate::New(create_params);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope context_scope(context);

  {
    char *buf = (char *) calloc(size + 1, sizeof(*buf));
    memcpy(buf, data, size);
    v8::Local<v8::String> source =
      v8::String::NewFromUtf8(isolate, buf).ToLocalChecked();
    v8::Local<v8::Value> result;
    v8::Local<v8::Script> script;
    v8::Script::Compile(context, source).ToLocal(&script);
    if (!script.IsEmpty()) {
      script->Run(context).ToLocal(&result);
    }
    free(buf);
  }

  return 0;
}
