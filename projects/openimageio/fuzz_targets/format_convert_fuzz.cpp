// Copyright Contributors to the OpenImageIO project.
// SPDX-License-Identifier: Apache-2.0
// https://github.com/AcademySoftwareFoundation/OpenImageIO


#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <string>
#include <vector>
#include <unistd.h>

#include <OpenImageIO/filesystem.h>
#include <OpenImageIO/imagebuf.h>
#include <OpenImageIO/imagecache.h>
#include <OpenImageIO/imageio.h>
#include <OpenImageIO/strutil.h>
#include <OpenImageIO/sysutil.h>

using namespace OIIO;
using OIIO::Strutil::print;

static std::string uninitialized  = "uninitialized \001 HHRU dfvAS: efjl";
static std::string dataformatname = "";
static float gammaval             = 1.0f;
//static bool depth = false;
static bool verbose = false;
static std::vector<std::string> filenames;
static int tile[3]   = { 0, 0, 1 };
static bool scanline = false;
//static bool zfile = false;
//static std::string channellist;
static std::string compression;
static bool no_copy_image  = false;
static int quality         = -1;
static bool adjust_time    = false;
static std::string caption = uninitialized;
static std::vector<std::string> keywords;
static bool clear_keywords = false;
static std::vector<std::string> attribnames, attribvals;
static int orientation = 0;
static bool rotcw = false, rotccw = false, rot180 = false;
static bool sRGB     = false;
static bool separate = false, contig = false;
static bool noclobber  = false;
//static ArgParse ap;


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


static bool
DateTime_to_time_t(string_view datetime, time_t& timet)
{
    int year, month, day, hour, min, sec;
    if (!Strutil::scan_datetime(datetime, year, month, day, hour, min, sec))
        return false;
    // print("{}:{}:{} {}:{}:{}\n", year, month, day, hour, min, sec);
    struct tm tmtime;
    time_t now;
    Sysutil::get_local_time(&now, &tmtime);  // fill in defaults
    tmtime.tm_sec  = sec;
    tmtime.tm_min  = min;
    tmtime.tm_hour = hour;
    tmtime.tm_mday = day;
    tmtime.tm_mon  = month - 1;
    tmtime.tm_year = year - 1900;
    timet          = mktime(&tmtime);
    return true;
}



// Adjust the output spec based on the command-line arguments.
// Return whether the specifics preclude using copy_image.
static bool
adjust_spec(ImageInput* in, ImageOutput* out, const ImageSpec& inspec,
            ImageSpec& outspec)
{
    bool nocopy = no_copy_image;

    // Copy the spec, with possible change in format
    outspec.format = inspec.format;
    if (inspec.channelformats.size()) {
        // Input file has mixed channels
        if (out->supports("channelformats")) {
            // Output supports mixed formats -- so request it
            outspec.format = TypeDesc::UNKNOWN;
        } else {
            // Input had mixed formats, output did not, so just use a fixed
            // format and forget the per-channel formats for output.
            outspec.channelformats.clear();
        }
    }
    if (!dataformatname.empty()) {
        // make sure there isn't a stray BPS that will screw us up
        outspec.erase_attribute("oiio:BitsPerSample");
        if (dataformatname == "uint8")
            outspec.set_format(TypeDesc::UINT8);
        else if (dataformatname == "int8")
            outspec.set_format(TypeDesc::INT8);
        else if (dataformatname == "uint10") {
            outspec.attribute("oiio:BitsPerSample", 10);
            outspec.set_format(TypeDesc::UINT16);
        } else if (dataformatname == "uint12") {
            outspec.attribute("oiio:BitsPerSample", 12);
            outspec.set_format(TypeDesc::UINT16);
        } else if (dataformatname == "uint16")
            outspec.set_format(TypeDesc::UINT16);
        else if (dataformatname == "int16")
            outspec.set_format(TypeDesc::INT16);
        else if (dataformatname == "uint32" || dataformatname == "uint")
            outspec.set_format(TypeDesc::UINT32);
        else if (dataformatname == "int32" || dataformatname == "int")
            outspec.set_format(TypeDesc::INT32);
        else if (dataformatname == "half")
            outspec.set_format(TypeDesc::HALF);
        else if (dataformatname == "float")
            outspec.set_format(TypeDesc::FLOAT);
        else if (dataformatname == "double")
            outspec.set_format(TypeDesc::DOUBLE);
        outspec.channelformats.clear();
    }
    if (outspec.format != inspec.format || inspec.channelformats.size())
        nocopy = true;
    if (outspec.nchannels != inspec.nchannels)
        nocopy = true;

    outspec.attribute("oiio:Gamma", gammaval);
    if (sRGB) {
        outspec.set_colorspace("sRGB");
        if (!strcmp(in->format_name(), "jpeg")
            || outspec.find_attribute("Exif:ColorSpace"))
            outspec.attribute("Exif:ColorSpace", 1);
    }

    if (tile[0]) {
        outspec.tile_width  = tile[0];
        outspec.tile_height = tile[1];
        outspec.tile_depth  = tile[2];
    }
    if (scanline) {
        outspec.tile_width  = 0;
        outspec.tile_height = 0;
        outspec.tile_depth  = 0;
    }
    if (outspec.tile_width != inspec.tile_width
        || outspec.tile_height != inspec.tile_height
        || outspec.tile_depth != inspec.tile_depth)
        nocopy = true;

    if (!compression.empty()) {
        outspec.attribute("compression", compression);
        if (compression != inspec.get_string_attribute("compression"))
            nocopy = true;
    }

    if (quality > 0) {
        outspec.attribute("CompressionQuality", quality);
        if (quality != inspec.get_int_attribute("CompressionQuality"))
            nocopy = true;
    }

    if (contig)
        outspec.attribute("planarconfig", "contig");
    if (separate)
        outspec.attribute("planarconfig", "separate");

    if (orientation >= 1)
        outspec.attribute("Orientation", orientation);
    else {
        orientation = outspec.get_int_attribute("Orientation", 1);
        if (orientation >= 1 && orientation <= 8) {
            static int cw[] = { 0, 6, 7, 8, 5, 2, 3, 4, 1 };
            if (rotcw || rotccw || rot180)
                orientation = cw[orientation];
            if (rotccw || rot180)
                orientation = cw[orientation];
            if (rotccw)
                orientation = cw[orientation];
            outspec.attribute("Orientation", orientation);
        }
    }

    if (caption != uninitialized)
        outspec.attribute("ImageDescription", caption);

    if (clear_keywords)
        outspec.attribute("Keywords", "");
    if (keywords.size()) {
        std::string oldkw = outspec.get_string_attribute("Keywords");
        std::vector<std::string> oldkwlist;
        if (!oldkw.empty()) {
            Strutil::split(oldkw, oldkwlist, ";");
            for (auto& kw : oldkwlist)
                kw = Strutil::strip(kw);
        }
        for (auto&& nk : keywords) {
            bool dup = false;
            for (auto&& ok : oldkwlist)
                dup |= (ok == nk);
            if (!dup)
                oldkwlist.push_back(nk);
        }
        outspec.attribute("Keywords", Strutil::join(oldkwlist, "; "));
    }

    for (size_t i = 0; i < attribnames.size(); ++i) {
        outspec.attribute(attribnames[i].c_str(), attribvals[i].c_str());
    }

    return nocopy;
}



static bool
convert_file(const std::string& in_filename, const std::string& fmt)
{
    //printf("Convert from %s -> %s\n", ext, fmt.c_str());
    std::string out_filename = in_filename + "." + fmt;
    std::string tempname = out_filename;

    // Find an ImageIO plugin that can open the input file, and open it.
    auto in = ImageInput::open(in_filename);
    if (!in) {
        std::string err = geterror();
        print(stderr, "iconvert ERROR: {}\n",
              (err.length() ? err
                            : Strutil::fmt::format("Could not open input file \"{}\"",
                                                   in_filename)));
        return false;
    }
    ImageSpec inspec         = in->spec();
    std::string metadatatime = inspec.get_string_attribute("DateTime");

    // Find an ImageIO plugin that can open the output file, and open it
    auto out = ImageOutput::create(tempname);
    if (!out) {
        print(
            stderr,
            "iconvert ERROR: Could not find an ImageIO plugin to write \"{}\": {}\n",
            out_filename, geterror());
        return true;
    }

    // In order to deal with formats that support subimages, but not
    // subimage appending, we gather them all first.
    std::vector<ImageSpec> subimagespecs;
    if (out->supports("multiimage") && !out->supports("appendsubimage")) {
        auto imagecache = ImageCache::create();
        int nsubimages  = 0;
        ustring ufilename(in_filename);
        imagecache->get_image_info(ufilename, 0, 0, ustring("subimages"),
                                   TypeInt, &nsubimages);
        if (nsubimages > 1) {
            subimagespecs.resize(nsubimages);
            for (int i = 0; i < nsubimages; ++i) {
                ImageSpec inspec = *imagecache->imagespec(ufilename, i);
                subimagespecs[i] = inspec;
                adjust_spec(in.get(), out.get(), inspec, subimagespecs[i]);
            }
        }
    }

    bool ok                      = true;
    bool mip_to_subimage_warning = false;
    for (int subimage = 0; ok && in->seek_subimage(subimage, 0); ++subimage) {
        if (subimage > 0 && !out->supports("multiimage")) {
            print(stderr,
                  "iconvert WARNING: {} does not support multiple subimages.\n"
                  "\tOnly the first subimage has been copied.\n",
                  out->format_name());
            break;  // we're done
        }

        int miplevel = 0;
        do {
            // Copy the spec, with possible change in format
            inspec            = in->spec(subimage, miplevel);
            ImageSpec outspec = inspec;
            bool nocopy = adjust_spec(in.get(), out.get(), inspec, outspec);
            if (miplevel > 0) {
                // Moving to next MIP level
                ImageOutput::OpenMode mode;
                if (out->supports("mipmap"))
                    mode = ImageOutput::AppendMIPLevel;
                else if (out->supports("multiimage")
                         && out->supports("appendsubimage")) {
                    mode = ImageOutput::AppendSubimage;  // use if we must
                    if (!mip_to_subimage_warning
                        && strcmp(out->format_name(), "tiff")) {
                        print(stderr,
                              "iconvert WARNING: {} does not support MIPmaps.\n"
                              "\tStoring the MIPmap levels in subimages.\n",
                              out->format_name());
                    }
                    mip_to_subimage_warning = true;
                } else {
                    print(stderr,
                          "iconvert WARNING: {} does not support MIPmaps.\n"
                          "\tOnly the first level has been copied.\n",
                          out->format_name());
                    break;  // on to the next subimage
                }
                ok = out->open(tempname.c_str(), outspec, mode);
            } else if (subimage > 0) {
                // Moving to next subimage
                ok = out->open(tempname.c_str(), outspec,
                               ImageOutput::AppendSubimage);
            } else {
                // First time opening
                if (subimagespecs.size())
                    ok = out->open(tempname.c_str(), int(subimagespecs.size()),
                                   &subimagespecs[0]);
                else
                    ok = out->open(tempname.c_str(), outspec,
                                   ImageOutput::Create);
            }
            if (!ok) {
                std::string err = out->geterror();
                print(stderr, "iconvert ERROR: {}\n",
                      (err.length()
                           ? err
                           : Strutil::fmt::format("Could not open \"{}\"",
                                                  out_filename)));
                ok = false;
                break;
            }

            // Copy thumbnail, if there is one.
            if (miplevel == 0 && in->supports("thumbnail")
                && out->supports("thumbnail")) {
                ImageBuf thumb;
                in->get_thumbnail(thumb, subimage);
                if (thumb.initialized())
                    out->set_thumbnail(thumb);
            }

            if (in->spec().nchannels != out->spec().nchannels)
                nocopy = true;
            if (!nocopy) {
                ok = out->copy_image(in.get());
                if (!ok)
                    print(stderr,
                          "iconvert ERROR copying \"{}\" to \"{}\" :\n\t{}\n",
                          in_filename, out_filename, out->geterror());
            } else {
                // Need to do it by hand for some reason.  Future expansion in which
                // only a subset of channels are copied, or some such.
                std::vector<char> pixels((size_t)outspec.image_bytes(true));
                ok = in->read_image(subimage, miplevel, 0, outspec.nchannels,
                                    outspec.format, &pixels[0]);
                if (!ok) {
                    print(stderr, "iconvert ERROR reading \"{}\": {}\n",
                          in_filename, in->geterror());
                } else {
                    ok = out->write_image(outspec.format, &pixels[0]);
                    if (!ok)
                        print(stderr, "iconvert ERROR writing \"{}\": {}\n",
                              out_filename, out->geterror());
                }
            }

            ++miplevel;
        } while (ok && in->seek_subimage(subimage, miplevel));
    }

    out->close();
    in->close();

    // Figure out a time for the input file -- either one supplied by
    // the metadata, or the actual time stamp of the input file.
    std::time_t in_time;
    if (metadatatime.empty()
        || !DateTime_to_time_t(metadatatime.c_str(), in_time))
        in_time = Filesystem::last_write_time(in_filename);

    Filesystem::remove(out_filename);

    // If user requested, try to adjust the file's modification time to
    // the creation time indicated by the file's DateTime metadata.
    if (ok && adjust_time)
        Filesystem::last_write_time(out_filename, in_time);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
#if defined(TIFF)
    if (size <= sizeof(header) + 5) {
#elif defined(PSD)
    if (size < sizeof(header) + sizeof(header2) + 8 + 5) {
#else
    if (size <= sizeof(header) + 5) {
#endif
        return 0;
    }
    uint8_t *data_copy = (uint8_t*)malloc(size);
    if (!data_copy) {
        return 0;
    }
    memcpy(data_copy, data, size);
    memcpy(data_copy, header, sizeof(header));
#if defined(TIFF)
    if (data[4] % 2) {
        memcpy(data_copy, header2, sizeof(header2));
    }
#elif defined(PSD)
    memcpy(data_copy, header, sizeof(header));
    memcpy(data_copy+22, header2, sizeof(header2));
#elif defined(PNM)
    int flag = 0x30 + (data[15] % 6 + 1);
    memset(data_copy+1, flag, 1);
#endif

    char tmpfile[30] = "/tmp/convert_fuzz-XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd == -1) {
        return 0;
    }
    write(fd, data_copy, size);
    close(fd);
    free(data_copy);
    char file_ext[35];
    snprintf(file_ext, sizeof(file_ext), "%s.%s", tmpfile, ext);
    if (rename(tmpfile, file_ext) == -1) {
        return 0;
    }
    auto fname = std::string(file_ext);

    std::vector<std::string> formats = {"bmp", "jpeg", "png", "webp", "tiff", "ico", "pnm", "hdr"};
    for (size_t it = 0; it < formats.size(); ++it) {
        if (formats[it] == std::string(ext)) {
            //printf("Don't convert from %s -> %s\n", ext, formats[it].c_str());
            continue;
        }
        if (!convert_file(fname, formats[it])) {
            break;
        }
    }
    unlink(file_ext);
    return 0;
}
