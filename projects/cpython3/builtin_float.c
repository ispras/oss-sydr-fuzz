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

int fuzz_builtin_float(const char* data, size_t size) {
    PyObject* s = PyBytes_FromStringAndSize(data, size);
    if (s == NULL) return 0;
    PyObject* f = PyFloat_FromString(s);
    if (PyErr_Occurred() && PyErr_ExceptionMatches(PyExc_ValueError)) {
        PyErr_Clear();
    }

    Py_XDECREF(f);
    Py_DECREF(s);
    return 0;
}

int main(int argc, char** argv)
{
  // Make initialization
  if (!Py_IsInitialized()) {
    Py_InitializeEx(0);
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
  fuzz_builtin_float(buffer, fsize);

  return 0;
}
