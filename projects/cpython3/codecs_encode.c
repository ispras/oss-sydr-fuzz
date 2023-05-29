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


const char* encoding[101] = {"ascii","big5","big5hkscs","charmap","cp037","cp1006","cp1026","cp1125","cp1140","cp1250",
                             "cp1251","cp1252","cp1253","cp1254","cp1255","cp1256","cp1257","cp1258","cp424","cp437",
                             "cp500","cp720","cp737","cp775","cp850","cp852","cp855","cp856","cp857","cp858","cp860",
                             "cp861","cp862","cp863","cp864","cp865","cp866","cp869","cp874","cp875","cp932","cp949",
                             "cp950","euc_jis_2004","euc_jisx0213","euc_jp","euc_kr","gb18030","gb2312","gbk","hp_roman8",
                             "hz","idna","iso2022_jp","iso2022_jp_1","iso2022_jp_2","iso2022_jp_2004","iso2022_jp_3",
                             "iso2022_jp_ext","iso2022_kr","iso8859_1","iso8859_10","iso8859_11","iso8859_13","iso8859_14",
                             "iso8859_15","iso8859_16","iso8859_2","iso8859_3","iso8859_4","iso8859_5","iso8859_6",
                             "iso8859_7","iso8859_8","iso8859_9","johab","koi8_r","koi8_t","koi8_u","kz1048","latin_1",
                             "mac_cyrillic","mac_greek","mac_iceland","mac_latin2","mac_roman","mac_turkish","palmos",
                             "ptcp154","punycode","raw_unicode_escape","shift_jis","shift_jis_2004","shift_jisx0213",
                             "tis_620","unicode_escape","utf_16","utf_16_be","utf_16_le","utf_7","utf_8"};
PyObject* codecs_module=NULL;
PyObject* codecs_method=NULL;

int init_codecs_encode(void) {
   codecs_module=PyImport_ImportModule("codecs");
   if (codecs_module == NULL) {
        return 0;
   }
   codecs_method = PyObject_GetAttrString(codecs_module, "encode");
   return codecs_method != NULL;
}

int fuzz_codecs_encode (const char* data, size_t size) {
    if (size < 2){
        return 0;
    }
    char *buf = (char*) calloc(size + 1, sizeof(char));
    memcpy(buf, data, size);
    PyObject *args = Py_BuildValue("(s)", buf);
    free(buf);
    if (args == NULL) {
        PyErr_Clear();
        return 0;
    }
    int index = abs(data[0]%101);
    PyObject *keywords = Py_BuildValue("{s:s,s:s}","encoding", encoding[index], "errors", "strict");
    PyObject* parsed = PyObject_Call(codecs_method, args, keywords);
    if (parsed == NULL) {
        PyErr_Clear();
    }
    Py_DECREF(args);
    Py_DECREF(keywords);
    Py_XDECREF(parsed);
    return 0;
}

int main(int argc, char** argv)
{
  // Make initialization
  if (!Py_IsInitialized()) {
    Py_InitializeEx(0);
  }

  if (!init_codecs_encode()) {
    PyErr_Print();
    printf("Failed to initialize codecs_encode\n");
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
  fuzz_codecs_encode(buffer, fsize);

  return 0;
}
