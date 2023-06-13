#include "io.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    load_audio_file("/a/b/c", 0, -1, true, true);
    return 0;
}
