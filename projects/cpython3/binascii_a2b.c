// Copyright 2023 ISP RAS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <Python.h>

PyObject* binascii_module=NULL;
PyObject* binascii_method=NULL;

int init_binascii_a2b(void) {
   binascii_module=PyImport_ImportModule("binascii");
   if (binascii_module == NULL) {
        return 0;
   }
   binascii_method = PyObject_GetAttrString(binascii_module, "a2b_base64");
   return binascii_method != NULL;
}

int fuzz_binascii_a2b (const char* data, size_t size) {
    PyObject* input_bytes = PyBytes_FromStringAndSize(data, size);
    if (input_bytes == NULL) {
        return 0;
    }
    PyObject* parsed = PyObject_CallOneArg(binascii_method, input_bytes);
    if (parsed == NULL) {
        PyErr_Clear();
    }
    Py_DECREF(input_bytes);
    Py_XDECREF(parsed);
    return 0;

}

int main(int argc, char** argv)
{
  // Make initialization
  if (!Py_IsInitialized()) {
    Py_InitializeEx(0);
  }

  if (!init_binascii_a2b()) {
    PyErr_Print();
    printf("Failed to initialize binascii_a2b\n");
    return 0;
  }

  // Read symbolic file
  FILE* fd = fopen(argv[1], "rb");
  if (!fd) return 1;
  fseek(fd, 0, SEEK_END);
  long fsize = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  char* buffer = (char*)malloc(fsize);
  fread(buffer, 1, fsize, fd);
  fclose(fd);

  // Run fuzztarget
  fuzz_binascii_a2b(buffer, fsize);

  return 0;
}
