#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include "libplatform.h"
#include "v8.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const char *data, size_t size)
{	
//	Initialize V8.
	v8::V8::InitializeICUDefaultLocation("/node_sydr");
	v8::V8::InitializeExternalStartupData("/node_sydr");
	std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
	v8::V8::InitializePlatform(platform.get());
	v8::V8::Initialize();
	
	std::string data_string(reinterpret_cast<const char*>(data), size);
	// Create a new Isolate and make it the current one.
	v8::Isolate::CreateParams create_params;
	create_params.array_buffer_allocator =
		v8::ArrayBuffer::Allocator::NewDefaultAllocator();
	v8::Isolate* isolate = v8::Isolate::New(create_params);
	{
		v8::Isolate::Scope isolate_scope(isolate);

		// Create a stack-allocated handle scope.
		v8::HandleScope handle_scope(isolate);

		// Create a new context.
		v8::Local<v8::Context> context = v8::Context::New(isolate);	
		// Enter the context for compiling and running the hello world script.
		v8::Context::Scope context_scope(context);
		{
			v8::Local<v8::String> source = v8::String::NewFromUtf8(isolate, data_string.c_str()).ToLocalChecked();
			v8::Local<v8::Value> result;
			// Compile the source code.
			v8::Local<v8::Script> script;
			v8::Script::Compile(context, source).ToLocal(&script);
			if(script.IsEmpty())
				goto exit;
			else
				script->Run(context).ToLocal(&result);
			//if (result.IsEmpty())
				}
	}
// Dispose the isolate and tear down V8.
//goto exit;
exit:
isolate->Dispose();
v8::V8::Dispose();
v8::V8::ShutdownPlatform();
delete create_params.array_buffer_allocator;
return 0;
}


