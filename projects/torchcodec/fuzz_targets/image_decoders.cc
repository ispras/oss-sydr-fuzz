#include <cstddef>
#include <cstdint>

#include <torch/torch.h>
#include "torch/types.h"
#include <torch/csrc/jit/frontend/error_report.h>

#if defined(JPEG)

#include "DecodeJpeg.h"

size_t offset = 0;
const uint8_t header[] = {0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00};

void decode(torch::stable::Tensor input) {
    // ImageReadMode 0-4
    //facebook::torchcodec::decode_jpeg(input, 0);
    facebook::torchcodec::decode_jpeg(input, 1);
    //facebook::torchcodec::decode_jpeg(input, 2);
    facebook::torchcodec::decode_jpeg(input, 3);
    facebook::torchcodec::decode_jpeg(input, 4);
}

#elif defined(PNG)

#include "DecodePng.h"

size_t offset = 0;
const uint8_t header[] = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};

void decode(torch::stable::Tensor input) {
    // ImageReadMode, OutputDType
    //facebook::torchcodec::decode_png(input, 0, 2);
    facebook::torchcodec::decode_png(input, 1, 2);
    //facebook::torchcodec::decode_png(input, 2, 2);
    facebook::torchcodec::decode_png(input, 3, 2);
    facebook::torchcodec::decode_png(input, 4, 2);
}

#elif defined(WEBP)

#include "DecodeWebp.h"

size_t offset = 0;
const uint8_t header[] = {
        0x52, 0x49, 0x46, 0x46,
        0x00, 0x00, 0x00, 0x00,
        0x57, 0x45, 0x42, 0x50,
    };
void decode(torch::stable::Tensor input) {
    // ImageReadMode
    //facebook::torchcodec::decode_webp(input, 0);
    facebook::torchcodec::decode_webp(input, 1);
    //facebook::torchcodec::decode_webp(input, 2);
    facebook::torchcodec::decode_webp(input, 3);
    facebook::torchcodec::decode_webp(input, 4);
}

#elif defined(GIF)

#include "DecodeGif.h"

size_t offset = 0;
const uint8_t header[] = {0x47, 0x49, 0x46, 0x38, 0x39, 0x61};

void decode(torch::stable::Tensor input) {
    // ImageReadMode 0, 3, 4
    //facebook::torchcodec::decode_gif(input, 0);
    facebook::torchcodec::decode_gif(input, 3);
    facebook::torchcodec::decode_gif(input, 4);
}

#elif defined(HEIC)

#include "DecodeHeic.h"

size_t offset = 4;
const uint8_t header[]  = {0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63, 0x00, 0x00, 0x00, 0x00};
const uint8_t header2[] = {0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x78, 0x00, 0x00, 0x00, 0x00};

void decode(torch::stable::Tensor input) {
    // ImageReadMode, OutoutDType
    //facebook::torchcodec::decode_heic(input, 0, 2);
    facebook::torchcodec::decode_heic(input, 1, 2);
    //facebook::torchcodec::decode_heic(input, 2, 2);
    facebook::torchcodec::decode_heic(input, 3, 2);
    facebook::torchcodec::decode_heic(input, 4, 2);
}

#elif defined(AVIF)

#include "DecodeAvif.h"

size_t offset = 4;
const uint8_t header[]  = {0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66, 0x00, 0x00, 0x00, 0x00};
const uint8_t header2[] = {0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x73, 0x00, 0x00, 0x00, 0x00};
const uint8_t header3[] = {0x66, 0x74, 0x79, 0x70, 0x6d, 0x69, 0x66, 0x33, 0x61, 0x76, 0x69, 0x66};

void decode(torch::stable::Tensor input) {
    // ImageReadMode, OutoutDType, NumThreads
    facebook::torchcodec::decode_avif(input, 0, 2, 1);
}

#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Validate input format
    if (size <= sizeof(header) + 5) {
        return 0;
    }
    uint8_t *data_copy = (uint8_t*)malloc(size);
    if (!data_copy) {
        return 0;
    }
    memcpy(data_copy, data, size);

    memcpy(data_copy + offset, header, sizeof(header));
#if defined(WEBP)
    // Count file size and set proper header
    size_t riff_size = size - 8;
    data_copy[4] = static_cast<uint8_t>(riff_size);
    data_copy[5] = static_cast<uint8_t>(riff_size >> 8);
    data_copy[6] = static_cast<uint8_t>(riff_size >> 16);
    data_copy[7] = static_cast<uint8_t>(riff_size >> 24);
#elif defined(HEIC)
    if (data_copy[sizeof(header) + 4] % 2) {
        memcpy(data_copy + offset, header2, sizeof(header2));
    }
#elif defined(AVIF)
    uint8_t flag = data_copy[sizeof(header) + 4];
    if (flag % 3 == 1) {
        memcpy(data_copy + offset, header2, sizeof(header2));
    } else if (flag % 3 == 2) {
        memcpy(data_copy + offset, header3, sizeof(header3));
    }
#endif

    try {
        // Create input tensor
        auto input = torch::stable::from_blob(
            const_cast<uint8_t*>(data_copy),
            {static_cast<int64_t>(size)},
            {1},
            torch::stable::Device(torch::headeronly::DeviceType::CPU),
            torch::headeronly::ScalarType::Byte
        );
	// Decode image
	decode(input);
    } catch (const std::runtime_error &e) {
        std::cout << "Runtime error catched: " << e.what() << std::endl;
    }
    free(data_copy);
    return 0;
}
