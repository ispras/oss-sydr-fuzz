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

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <Python.h>

#define MAX_CSV_TEST_SIZE 0x10000
PyObject* csv_module = NULL;
PyObject* csv_error = NULL;

int init_csv_reader(void) {
    /* Import csv and csv.Error */
    csv_module = PyImport_ImportModule("csv");
    if (csv_module == NULL) {
        return 0;
    }
    csv_error = PyObject_GetAttrString(csv_module, "Error");
    return csv_error != NULL;
}

int fuzz_csv_reader(const char* data, size_t size) {
    if (size < 1 || size > MAX_CSV_TEST_SIZE) {
        return 0;
    }
    /* Ignore non null-terminated strings since _csv can't handle
       embedded nulls */
    if (memchr(data, '\0', size) == NULL) {
        return 0;
    }

    PyObject* s = PyUnicode_FromString(data);
    /* Ignore exceptions until we have a valid string */
    if (s == NULL) {
        PyErr_Clear();
        return 0;
    }

    /* Split on \n so we can test multiple lines */
    PyObject* lines = PyObject_CallMethod(s, "split", "s", "\n");
    if (lines == NULL) {
        Py_DECREF(s);
        return 0;
    }

    PyObject* reader = PyObject_CallMethod(csv_module, "reader", "N", lines);
    if (reader) {
        /* Consume all of the reader as an iterator */
        PyObject* parsed_line;
        while ((parsed_line = PyIter_Next(reader))) {
            Py_DECREF(parsed_line);
        }
    }

    /* Ignore csv.Error because we're probably going to generate
       some bad files (embedded new-lines, unterminated quotes etc) */
    if (PyErr_ExceptionMatches(csv_error)) {
        PyErr_Clear();
    }

    Py_XDECREF(reader);
    Py_DECREF(s);
    return 0;
}

int main(int argc, char** argv)
{
  // Make initialization
  if (!Py_IsInitialized()) {
    Py_InitializeEx(0);
  }

  if (!init_csv_reader()) {
    PyErr_Print();
    printf("Failed to initialize csv_reader\n");
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
  fuzz_csv_reader(buffer, fsize);

  return 0;
}

