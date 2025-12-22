// Copyright Contributors to the OpenImageIO project.
// SPDX-License-Identifier: Apache-2.0
// https://github.com/AcademySoftwareFoundation/OpenImageIO

#include <unistd.h>
#include <regex>

#include <OpenImageIO/argparse.h>
#include <OpenImageIO/deepdata.h>
#include <OpenImageIO/filesystem.h>
#include <OpenImageIO/hash.h>
#include <OpenImageIO/imagebuf.h>
#include <OpenImageIO/imagebufalgo.h>
#include <OpenImageIO/imageio.h>
#include <OpenImageIO/strutil.h>
#include <OpenImageIO/sysutil.h>

#include "imageio_pvt.h"

using namespace OIIO;
using namespace ImageBufAlgo;
using OIIO::Strutil::print;

#if defined(BMP)
const uint8_t header[] = {0x42, 0x4d};
const char ext[4] = "bmp";
#elif defined(GIF)
const uint8_t header[] = {0x47, 0x49, 0x46, 0x38, 0x39, 0x61};
const char ext[4] = "gif";
#elif defined(JPEG)
const uint8_t header[] = {0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00};
const char ext[5] = "jpeg";
#elif defined(PNG)
const uint8_t header[] = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};
const char ext[4] = "png";
#elif defined(WEBP)
const uint8_t header[] = {
        0x52, 0x49, 0x46, 0x46,
        0x00, 0x00, 0x00, 0x00,
        0x57, 0x45, 0x42, 0x50,
        0x56, 0x50, 0x38, 0x58,
        0x0a, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x03, 0x02, 0x00, 0x4d,
        0x01, 0x00, 0x56, 0x50
    };
const char ext[5] = "webp";
#elif defined(TIFF)
const uint8_t header[] = {0x49, 0x49, 0x2a, 0x00};
const uint8_t header2[] = {0x4d, 0x4d, 0x00, 0x2b};
const char ext[5] = "tiff";
#elif defined(ICO)
const uint8_t header[] = {0x00, 0x00, 0x01, 0x00};
const char ext[4] = "ico";
#elif defined(PSD)
const uint8_t header[] = {0x38, 0x42, 0x50, 0x53, 0x00, 0x01,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x03};
const uint8_t header2[] = {0x00, 0x08, 0x00, 0x03};
const char ext[4] = "psd";
#elif defined(PNM)
const uint8_t header[] = {0x50, 0x00, 0x0a, 0x35, 0x31, 0x32,
                          0x20, 0x35, 0x31, 0x32, 0x0a, 0x32,
                          0x35, 0x35, 0x0a};
const char ext[4] = "pbm";
#elif defined(HDR)
const uint8_t header[] = {0x23, 0x3f, 0x52, 0x41, 0x44, 0x49,
                          0x41, 0x4e, 0x43, 0x45, 0x0a};
const char ext[4] = "hdr";
#endif

static bool verbose = true;
static bool sum     = true;
static bool help    = false;
static std::vector<std::string> filenames;
static std::string metamatch;
static bool filenameprefix = false;
static std::regex field_re;
static bool subimages     = false;
static bool compute_stats = true;

///////////////////////////////////////////////////////////////////////////////
// Stats

static bool
read_input(const std::string& filename, ImageBuf& img, int subimage = 0,
           int miplevel = 0)
{
    if (img.read(subimage, miplevel, false, TypeDesc::FLOAT))
        return true;

    std::cerr << "iinfo ERROR: Could not read " << filename << ":\n\t"
              << img.geterror() << "\n";
    return false;
}



static void
print_stats(const std::string& filename, const ImageSpec& originalspec,
            int subimage = 0, int miplevel = 0, bool indentmip = false)
{
    const char* indent = indentmip ? "      " : "    ";

    ImageBuf input(filename);
    if (!read_input(filename, input, subimage, miplevel)) {
        // Note: read_input prints an error message if one occurs
        return;
    }

    std::string err;
    if (!pvt::print_stats(std::cout, indent, input, originalspec, ROI(), err)) {
        //print("{}Stats: (unable to compute)\n", indent);
        if (err.size())
            std::cerr << "Error: " << err << "\n";
        return;
    }
}



static void
print_metadata(const ImageSpec& spec, const std::string& filename)
{
    bool printed = false;
    if (metamatch.empty() || std::regex_search("channels", field_re)
        || std::regex_search("channel list", field_re)) {
        if (filenameprefix)
            print("{} : ", filename);
        print("    channel list: ");
        for (int i = 0; i < spec.nchannels; ++i) {
            if (i < (int)spec.channelnames.size())
                print("{}", spec.channelnames[i]);
            else
                print("unknown");
            if (i < (int)spec.channelformats.size())
                print(" ({})", spec.channelformats[i]);
            if (i < spec.nchannels - 1)
                print(", ");
        }
        print("\n");
        printed = true;
    }
    if (spec.x || spec.y || spec.z) {
        if (metamatch.empty()
            || std::regex_search("pixel data origin", field_re)) {
            if (filenameprefix)
                print("{} : ", filename);
            print("    pixel data origin: x={}, y={}", spec.x, spec.y);
            if (spec.depth > 1)
                print(", z={}", spec.z);
            print("\n");
            printed = true;
        }
    }
    if (spec.full_x || spec.full_y || spec.full_z
        || (spec.full_width != spec.width && spec.full_width != 0)
        || (spec.full_height != spec.height && spec.full_height != 0)
        || (spec.full_depth != spec.depth && spec.full_depth != 0)) {
        if (metamatch.empty()
            || std::regex_search("full/display size", field_re)) {
            if (filenameprefix)
                print("{} : ", filename);
            print("    full/display size: {} x {}", spec.full_width,
                  spec.full_height);
            if (spec.depth > 1)
                print(" x {}", spec.full_depth);
            print("\n");
            printed = true;
        }
        if (metamatch.empty()
            || std::regex_search("full/display origin", field_re)) {
            if (filenameprefix)
                print("{} : ", filename);
            print("    full/display origin: {}, {}", spec.full_x, spec.full_y);
            if (spec.depth > 1)
                print(", {}", spec.full_z);
            print("\n");
            printed = true;
        }
    }
    if (spec.tile_width) {
        if (metamatch.empty() || std::regex_search("tile", field_re)) {
            if (filenameprefix)
                print("{} : ", filename);
            print("    tile size: {} x {}", spec.tile_width, spec.tile_height);
            if (spec.depth > 1)
                print(" x {}", spec.tile_depth);
            print("\n");
            printed = true;
        }
    }

    // Sort the metadata alphabetically, case-insensitive, but making
    // sure that all non-namespaced attribs appear before namespaced
    // attribs.
    ParamValueList attribs = spec.extra_attribs;
    attribs.sort(false /* sort case-insensitively */);
    for (auto&& p : attribs) {
        if (!metamatch.empty()
            && !std::regex_search(p.name().c_str(), field_re))
            continue;
        std::string s = spec.metadata_val(p, true);
        if (filenameprefix)
            print("{} : ", filename);
        print("    {}: ", p.name());
        if (s == "1.#INF")
            print("inf");
        else
            print("{}", s);
        print("\n");
        printed = true;
    }

    if (!printed && !metamatch.empty()) {
        if (filenameprefix)
            print("{} : ", filename);
        print("    {}: <unknown>\n", metamatch);
    }
}



static const char*
extended_format_name(TypeDesc type, int bits)
{
    if (bits && bits < (int)type.size() * 8) {
        // The "oiio:BitsPerSample" betrays a different bit depth in the
        // file than the data type we are passing.
        if (type == TypeDesc::UINT8 || type == TypeDesc::UINT16
            || type == TypeDesc::UINT32 || type == TypeDesc::UINT64)
            return ustring::fmtformat("uint{}", bits).c_str();
        if (type == TypeDesc::INT8 || type == TypeDesc::INT16
            || type == TypeDesc::INT32 || type == TypeDesc::INT64)
            return ustring::fmtformat("int{}", bits).c_str();
    }
    return type.c_str();  // use the name implied by type
}



static const char*
brief_format_name(TypeDesc type, int bits = 0)
{
    if (!bits)
        bits = (int)type.size() * 8;
    if (type.is_floating_point()) {
        if (type.basetype == TypeDesc::FLOAT)
            return "f";
        if (type.basetype == TypeDesc::HALF)
            return "h";
        return ustring::fmtformat("f{}", bits).c_str();
    } else if (type.is_signed()) {
        return ustring::fmtformat("i{}", bits).c_str();
    } else {
        return ustring::fmtformat("u{}", bits).c_str();
    }
    return type.c_str();  // use the name implied by type
}



// prints basic info (resolution, width, height, depth, channels, data format,
// and format name) about given subimage.
static void
print_info_subimage(int current_subimage, int max_subimages, ImageSpec& spec,
                    ImageInput* input, const std::string& filename)
{
    if (!input->seek_subimage(current_subimage, 0))
        return;
    spec = input->spec(current_subimage);

    if (!metamatch.empty()
        && !std::regex_search(
            "resolution, width, height, depth, channels, sha-1, stats",
            field_re)) {
        // nothing to do here
        return;
    }

    int nmip = 1;

    bool printres
        = verbose
          && (metamatch.empty()
              || std::regex_search("resolution, width, height, depth, channels",
                                   field_re));
    if (printres && max_subimages > 1 && subimages) {
        print(" subimage {:2}: ", current_subimage);
        print("{:4} x {:4}", spec.width, spec.height);
        if (spec.depth > 1)
            print(" x {:4}", spec.depth);
        int bits = spec.get_int_attribute("oiio:BitsPerSample", 0);
        print(", {} channel, {}{}{}", spec.nchannels, spec.deep ? "deep " : "",
              spec.depth > 1 ? "volume " : "",
              extended_format_name(spec.format, bits));
        print(" {}", input->format_name());
        print("\n");
    }
    // Count MIP levels
    while (input->seek_subimage(current_subimage, nmip)) {
        if (printres) {
            ImageSpec mipspec = input->spec_dimensions(current_subimage, nmip);
            if (nmip == 1)
                print("    MIP-map levels: {}x{}", spec.width, spec.height);
            print(" {}x{}", mipspec.width, mipspec.height);
        }
        ++nmip;
    }
    if (printres && nmip > 1)
        print("\n");

    if (verbose)
        print_metadata(spec, filename);

    if (compute_stats
        && (metamatch.empty() || std::regex_search("stats", field_re))) {
        for (int m = 0; m < nmip; ++m) {
            ImageSpec mipspec = input->spec_dimensions(current_subimage, m);
            if (filenameprefix)
                print("{} : ", filename);
            if (nmip > 1 && (subimages || m == 0)) {
                print("    MIP {} of {} ({} x {}):\n", m, nmip, mipspec.width,
                      mipspec.height);
            }
            print_stats(filename, spec, current_subimage, m, nmip > 1);
        }
    }

    if (!input->seek_subimage(current_subimage, 0))
        return;
}



static void
print_info(const std::string& filename, size_t namefieldlength,
           ImageInput* input, ImageSpec& spec, bool verbose, bool sum,
           long long& totalsize)
{
    int padlen = std::max(0, (int)namefieldlength - (int)filename.length());
    std::string padding(padlen, ' ');

    // checking how many subimages and mipmap levels are stored in the file
    int num_of_subimages = 1;
    bool any_mipmapping  = false;
    std::vector<int> num_of_miplevels;
    {
        int nmip = 1;
        while (input->seek_subimage(input->current_subimage(), nmip)) {
            ++nmip;
            any_mipmapping = true;
        }
        num_of_miplevels.push_back(nmip);
    }
    while (input->seek_subimage(num_of_subimages, 0)) {
        // maybe we should do this more gently?
        ++num_of_subimages;
        int nmip = 1;
        while (input->seek_subimage(input->current_subimage(), nmip)) {
            ++nmip;
            any_mipmapping = true;
        }
        num_of_miplevels.push_back(nmip);
    }
    // input->seek_subimage(0, 0);  // re-seek to the first
    spec = input->spec(0, 0);

    if (metamatch.empty()
        || std::regex_search("resolution, width, height, depth, channels",
                             field_re)) {
        print("{}{} : {:4} x {:4}", filename, padding, spec.width, spec.height);
        if (spec.depth > 1)
            print(" x {:4}", spec.depth);
        print(", {} channel, {}{}", spec.nchannels, spec.deep ? "deep " : "",
              spec.depth > 1 ? "volume " : "");
        if (spec.channelformats.size()) {
            for (size_t c = 0; c < spec.channelformats.size(); ++c)
                print("{}{}", c ? "/" : "", spec.channelformat(c));
        } else {
            int bits = spec.get_int_attribute("oiio:BitsPerSample", 0);
            print("{}", extended_format_name(spec.format, bits));
        }
        print(" {}", input->format_name());
        if (sum) {
            imagesize_t imagebytes = spec.image_bytes(true);
            totalsize += imagebytes;
            print(" ({:.2f} MB)", (float)imagebytes / (1024.0 * 1024.0));
        }
        // we print info about how many subimages are stored in file
        // only when we have more then one subimage
        if (!verbose && num_of_subimages != 1)
            print(" ({} subimages{})", num_of_subimages,
                  any_mipmapping ? " +mipmap)" : "");
        if (!verbose && num_of_subimages == 1 && any_mipmapping)
            print(" (+mipmap)");
        print("\n");
    }

    int movie = spec.get_int_attribute("oiio:Movie");
    if (verbose && num_of_subimages != 1) {
        // info about num of subimages and their resolutions
        print("    {} subimages: ", num_of_subimages);
        for (int i = 0; i < num_of_subimages; ++i) {
            spec     = input->spec(i, 0);
            int bits = spec.get_int_attribute("oiio:BitsPerSample",
                                              spec.format.size() * 8);
            if (i)
                print(", ");
            if (spec.depth > 1)
                print("{}x{}x{} ", spec.width, spec.height, spec.depth);
            else
                print("{}x{} ", spec.width, spec.height);
            // print("[");
            for (int c = 0; c < spec.nchannels; ++c)
                print("{:c}{}", c ? ',' : '[',
                      brief_format_name(spec.channelformat(c), bits));
            print("]");
            if (movie)
                break;
        }
        print("\n");
    }

    // if the '-a' flag is not set we print info
    // about first subimage only
    if (!subimages)
        num_of_subimages = 1;
    for (int i = 0; i < num_of_subimages; ++i) {
        print_info_subimage(i, num_of_subimages, spec, input, filename);
    }
}


int main(int argc, char **argv) {
  fprintf(stderr, "StandaloneFuzzTargetMain: running %d inputs\n", argc - 1);
  for (int i = 1; i < argc; i++) {
    fprintf(stderr, "Running: %s\n", argv[i]);
    std::string fname = std::string(argv[i]);
    if (fname.length() < 5 || fname.substr(fname.length() - sizeof(ext) + 1) != std::string(ext)) {
        char file_ext[256];
        snprintf(file_ext, sizeof(file_ext), "%s.%s", argv[i], ext);
        if (rename(argv[i], file_ext) == -1) {
            fprintf(stderr, "can't rename %s\n", argv[i]);
            return 0;
        }
        fname = std::string(file_ext);
    }
    // Fix headers.
    FILE* f2 = fopen(fname.c_str(), "r+b");
    if (f2 == NULL) return 0;
#if defined(TIFF)
    unsigned char byte;
    fseek(f2, 4, SEEK_SET);
    fread(&byte, sizeof(byte), 1, f2);
    fseek(f2, 0, SEEK_SET);
    if (byte % 2) {
        fwrite(header2, 1, sizeof(header2), f2);
    } else {
        fwrite(header, 1, sizeof(header), f2);
    }
#elif defined(PSD)
    fwrite(header, 1, sizeof(header), f2);
    fseek(f2, 22, SEEK_SET);
    fwrite(header2, 1, sizeof(header2), f2);
#elif defined(PNM)
    unsigned char byte;
    fseek(f2, 15, SEEK_SET);
    fread(&byte, sizeof(byte), 1, f2);
    fseek(f2, 1, SEEK_SET);
    int flag = 0x30 + (byte % 6 + 1);
    fwrite(&flag, 1, 1, f2);
#endif
    fclose(f2);

    fprintf(stderr, "opening: %s\n", fname.c_str());
    auto in = ImageInput::open(fname);
    if (!in) {
        std::string err = geterror();
        std::cout << "open image error: " << err << std::endl;
    } else {
	long long totalsize = 0;
        std::cout << "opened successfully" << std::endl;
	ImageSpec spec = in->spec();
	print_info(fname, fname.length(), in.get(), spec, verbose, sum, totalsize);
    }
  }
}
