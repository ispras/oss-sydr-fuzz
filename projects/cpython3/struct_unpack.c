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

PyObject* struct_unpack_method = NULL;
PyObject* struct_error = NULL;

int init_struct_unpack(void) {
    /* Import struct.unpack */
    PyObject* struct_module = PyImport_ImportModule("struct");
    if (struct_module == NULL) {
        return 0;
    }
    struct_error = PyObject_GetAttrString(struct_module, "error");
    if (struct_error == NULL) {
        return 0;
    }
    struct_unpack_method = PyObject_GetAttrString(struct_module, "unpack");
    return struct_unpack_method != NULL;
}

int fuzz_struct_unpack(const char* data, size_t size) {
    /* Everything up to the first null byte is considered the
       format. Everything after is the buffer */
    const char* first_null = memchr(data, '\0', size);
    if (first_null == NULL) {
        return 0;
    }

    size_t format_length = first_null - data;
    size_t buffer_length = size - format_length - 1;

    PyObject* pattern = PyBytes_FromStringAndSize(data, format_length);
    if (pattern == NULL) {
        return 0;
    }
    PyObject* buffer = PyBytes_FromStringAndSize(first_null + 1, buffer_length);
    if (buffer == NULL) {
        Py_DECREF(pattern);
        return 0;
    }

    PyObject* unpacked = PyObject_CallFunctionObjArgs(
        struct_unpack_method, pattern, buffer, NULL);
    /* Ignore any overflow errors, these are easily triggered accidentally */
    if (unpacked == NULL && PyErr_ExceptionMatches(PyExc_OverflowError)) {
        PyErr_Clear();
    }
    /* The pascal format string will throw a negative size when passing 0
       like: struct.unpack('0p', b'') */
    if (unpacked == NULL && PyErr_ExceptionMatches(PyExc_SystemError)) {
        PyErr_Clear();
    }
    /* Ignore any struct.error exceptions, these can be caused by invalid
       formats or incomplete buffers both of which are common. */
    if (unpacked == NULL && PyErr_ExceptionMatches(struct_error)) {
        PyErr_Clear();
    }

    Py_XDECREF(unpacked);
    Py_DECREF(pattern);
    Py_DECREF(buffer);
    return 0;
}

int main(int argc, char** argv)
{
  // Make initialization
  if (!Py_IsInitialized()) {
    Py_InitializeEx(0);
  }

  if (!init_struct_unpack()) {
    PyErr_Print();
    printf("Failed to initialize struct_unpack\n");
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
  fuzz_struct_unpack(buffer, fsize);

  return 0;
}
