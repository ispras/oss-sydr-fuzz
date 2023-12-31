/* Copyright (C) 2023 ISP RAS
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "fuzz.h"
#include <libxml/catalog.h>
#include <libxml/debugXML.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
                         char ***argv ATTRIBUTE_UNUSED) {
  xmlInitParser();
#ifdef LIBXML_CATALOG_ENABLED
  xmlInitializeCatalog();
#endif
  xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);

  return 0;
}

char *input(char *prompt) {
  static int counter = 0, MAX_LEN = 100;
  const char *args[] = {
      "base",
      "cat",
      "cat item",
      "cd",
      "cd item",
      "dir",
      "dir item",
      "du",
      "du item",
      "free",
      "ls",
      "ls item",
      "pwd",
      "whereis",
      "grep xml",
      "setrootns",
      "xpath /no/such/path",
      "write",
      "write /dev/null",
      "save",
      "validate",
      "free",
      "help",
      "ls",
      "bye",
  };
  if (counter > 24) {
    return NULL;
  }
  char *ret = (char *)malloc(MAX_LEN * sizeof(*ret));
  strncpy(ret, args[counter++], MAX_LEN);
  return ret;
}

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  static const size_t maxChunkSize = 128;
  xmlDocPtr doc;
  xmlOutputBufferPtr out;
  const char *docBuffer, *docUrl;
  char *filename = "output.txt";
  size_t docSize, consumed, chunkSize;
  int opts = 0;

  xmlFuzzDataInit(data, size);
  opts = xmlFuzzReadInt();
  opts = ~XML_PARSE_XINCLUDE;

  docBuffer = xmlFuzzReadRemaining(&docSize);
  if (docBuffer == NULL) {
    xmlFuzzDataCleanup();
    return (0);
  }

  doc = xmlReadMemory(docBuffer, docSize, docUrl, NULL, opts);
  xmlShell(doc, filename, input, NULL);
  xmlFreeDoc(doc);

  /* Cleanup */

  xmlFuzzDataCleanup();
  xmlResetLastError();

  return (0);
}
