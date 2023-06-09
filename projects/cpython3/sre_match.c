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

/* Some random patterns used to test re.match.
   Be careful not to add catostraphically slow regexes here, we want to
   exercise the matching code without causing timeouts.*/
static const char* regex_patterns[] = {
    ".", "^", "abc", "abc|def", "^xxx$", "\\b", "()", "[a-zA-Z0-9]",
    "abc+", "[^A-Z]", "[x]", "(?=)", "a{z}", "a+b", "a*?", "a??", "a+?",
    "{}", "a{,}", "{", "}", "^\\(*\\d{3}\\)*( |-)*\\d{3}( |-)*\\d{4}$",
    "(?:a*)*", "a{1,2}?"
};
const size_t NUM_PATTERNS = sizeof(regex_patterns) / sizeof(regex_patterns[0]);
PyObject** compiled_patterns = NULL;

static int init_sre_match(void) {
    PyObject* re_module = PyImport_ImportModule("re");
    if (re_module == NULL) {
        return 0;
    }
    compiled_patterns = (PyObject**) PyMem_RawMalloc(
        sizeof(PyObject*) * NUM_PATTERNS);
    if (compiled_patterns == NULL) {
        PyErr_NoMemory();
        return 0;
    }

    /* Precompile all the regex patterns on the first run for faster fuzzing */
    for (size_t i = 0; i < NUM_PATTERNS; i++) {
        PyObject* compiled = PyObject_CallMethod(
            re_module, "compile", "y", regex_patterns[i]);
        /* Bail if any of the patterns fail to compile */
        if (compiled == NULL) {
            return 0;
        }
        compiled_patterns[i] = compiled;
    }
    return 1;
}

static int fuzz_sre_match(const char* data, size_t size) {
    if (size < 1 || size > MAX_RE_TEST_SIZE) {
        return 0;
    }
    /* Use the first byte as a uint8_t specifying the index of the
       regex to use */
    unsigned char idx = (unsigned char) data[0];
    idx = idx % NUM_PATTERNS;

    /* Pull the string to match from the remaining bytes */
    PyObject* to_match = PyBytes_FromStringAndSize(data + 1, size - 1);
    if (to_match == NULL) {
        return 0;
    }

    PyObject* pattern = compiled_patterns[idx];
    PyObject* match_callable = PyObject_GetAttrString(pattern, "match");

    PyObject* matches = PyObject_CallOneArg(match_callable, to_match);

    Py_XDECREF(matches);
    Py_DECREF(match_callable);
    Py_DECREF(to_match);
    return 0;
}

int main(int argc, char** argv)
{
  // Make initialization
  if (!Py_IsInitialized()) {
    Py_InitializeEx(0);
  }

  if (!init_sre_match()) {
    PyErr_Print();
    printf("Failed to initialize sre_match\n");
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
  fuzz_sre_match(buffer, fsize);

  return 0;
}
