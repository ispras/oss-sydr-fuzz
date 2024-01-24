/* Copyright (C) 2024 ISP RAS
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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PNG_INTERNAL
#define PNG_SIMPLIFIED_WRITE_SUPPORTED
#define PNG_SIMPLIFIED_WRITE_STDIO_SUPPORTED
#include "png.h"

void *limited_malloc(png_alloc_size_t size) {
  if (size > 8000000)
    return nullptr;

  return malloc(size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int formats[] = {
      PNG_FORMAT_GRAY,
      PNG_FORMAT_RGBA,
      PNG_FORMAT_RGBA_COLORMAP,
      PNG_FORMAT_BGR_COLORMAP,
  };
  for (const int &format : formats) {
    png_byte colormap[PNG_IMAGE_MAXIMUM_COLORMAP_COMPONENTS(format)];
    png_image image;
    memset(&image, 0, sizeof image);
    image.version = PNG_IMAGE_VERSION;
    if (png_image_begin_read_from_memory(&image, data, size)) {
      png_bytep buffer;

      image.format = format;

      buffer = (png_bytep)limited_malloc(PNG_IMAGE_SIZE(image));

      if (buffer != NULL) {
        if (png_image_finish_read(&image, NULL, buffer, 0, colormap)) {
          png_image_write_to_file(&image, "/dev/null", 0, buffer, 0, colormap);
        }
        free(buffer);
      }
    }
  }
  return 0;
}
