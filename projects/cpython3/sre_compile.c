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

#define MAX_RE_TEST_SIZE 0x10000

PyObject* sre_compile_method = NULL;
PyObject* sre_error_exception = NULL;
int SRE_FLAG_DEBUG = 0;

int init_sre_compile(void) {
    /* Import sre_compile.compile and sre.error */
    PyObject* sre_compile_module = PyImport_ImportModule("sre_compile");
    if (sre_compile_module == NULL) {
        return 0;
    }
    sre_compile_method = PyObject_GetAttrString(sre_compile_module, "compile");
    if (sre_compile_method == NULL) {
        return 0;
    }

    PyObject* sre_constants = PyImport_ImportModule("sre_constants");
    if (sre_constants == NULL) {
        return 0;
    }
    sre_error_exception = PyObject_GetAttrString(sre_constants, "error");
    if (sre_error_exception == NULL) {
        return 0;
    }
    PyObject* debug_flag = PyObject_GetAttrString(sre_constants, "SRE_FLAG_DEBUG");
    if (debug_flag == NULL) {
        return 0;
    }
    SRE_FLAG_DEBUG = PyLong_AsLong(debug_flag);
    return 1;
}

int fuzz_sre_compile(const char* data, size_t size) {
    /* Ignore really long regex patterns that will timeout the fuzzer */
    if (size > MAX_RE_TEST_SIZE) {
        return 0;
    }
    /* We treat the first 2 bytes of the input as a number for the flags */
    if (size < 2) {
        return 0;
    }
    uint16_t flags = ((uint16_t*) data)[0];
    /* We remove the SRE_FLAG_DEBUG if present. This is because it
       prints to stdout which greatly decreases fuzzing speed */
    flags &= ~SRE_FLAG_DEBUG;

    /* Pull the pattern from the remaining bytes */
    PyObject* pattern_bytes = PyBytes_FromStringAndSize(data + 2, size - 2);
    if (pattern_bytes == NULL) {
        return 0;
    }
    PyObject* flags_obj = PyLong_FromUnsignedLong(flags);
    if (flags_obj == NULL) {
        Py_DECREF(pattern_bytes);
        return 0;
    }

    /* compiled = _sre.compile(data[2:], data[0:2] */
    PyObject* compiled = PyObject_CallFunctionObjArgs(
        sre_compile_method, pattern_bytes, flags_obj, NULL);
    /* Ignore ValueError as the fuzzer will more than likely
       generate some invalid combination of flags */
    if (compiled == NULL && PyErr_ExceptionMatches(PyExc_ValueError)) {
        PyErr_Clear();
    }
    /* Ignore some common errors thrown by sre_parse:
       Overflow, Assertion, Recursion and Index */
    if (compiled == NULL && (PyErr_ExceptionMatches(PyExc_OverflowError) ||
                             PyErr_ExceptionMatches(PyExc_AssertionError) ||
                             PyErr_ExceptionMatches(PyExc_RecursionError) ||
                             PyErr_ExceptionMatches(PyExc_IndexError))
    ) {
        PyErr_Clear();
    }
    /* Ignore re.error */
    if (compiled == NULL && PyErr_ExceptionMatches(sre_error_exception)) {
        PyErr_Clear();
    }

    Py_DECREF(pattern_bytes);
    Py_DECREF(flags_obj);
    Py_XDECREF(compiled);
    return 0;
}

int main(int argc, char** argv)
{
  // Make initialization
  if (!Py_IsInitialized()) {
    Py_InitializeEx(0);
  }

  if (!init_sre_compile()) {
    PyErr_Print();
    printf("Failed to initialize sre_compile\n");
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
  fuzz_sre_compile(buffer, fsize);

  return 0;
}
