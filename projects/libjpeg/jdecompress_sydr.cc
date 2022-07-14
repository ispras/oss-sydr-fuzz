
#include <cdjpeg.h>
#include <cstddef>
#include <jpeglib.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NUMTESTS 7

struct my_error_mgr {
  struct jpeg_error_mgr pub; /* "public" fields */

  jmp_buf setjmp_buffer; /* for return to caller */
};

typedef struct my_error_mgr *my_error_ptr;

/*
 * Here's the routine that will replace the standard error_exit method:
 */

METHODDEF(void)
my_error_exit(j_common_ptr cinfo) {
  /* cinfo->err really points to a my_error_mgr struct, so coerce pointer */
  my_error_ptr myerr = (my_error_ptr)cinfo->err;

  /* Always display the message. */
  /* We could postpone this until after returning, if we chose. */
  (*cinfo->err->output_message)(cinfo);

  /* Return control to the setjmp point */
  longjmp(myerr->setjmp_buffer, 1);
}

typedef enum {
  FMT_BMP,   /* BMP format (Windows flavor) */
  FMT_GIF,   /* GIF format (LZW compressed) */
  FMT_GIF0,  /* GIF format (uncompressed) */
  FMT_OS2,   /* BMP format (OS/2 flavor) */
  FMT_PPM,   /* PPM/PGM (PBMPLUS formats) */
  FMT_RLE,   /* RLE format */
  FMT_TARGA, /* Targa format */
  FMT_TIFF   /* TIFF format */
} IMAGE_FORMATS;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct jpeg_decompress_struct cinfo;
  struct my_error_mgr jerr;
  int ti = 0, i = 0, fd = -1;
  FILE *file;
  djpeg_dest_ptr dest_mgr;
  char filename[FILENAME_MAX] = {0};
  JDIMENSION num_scanlines;
  IMAGE_FORMATS tests[NUMTESTS]{
      FMT_BMP, FMT_GIF, FMT_GIF0, FMT_OS2, FMT_PPM, FMT_RLE, FMT_TARGA,
  };
  if ((file = fopen("/dev/null", "wb")) == NULL)
    goto bailout;

  // <------------------------------------> //
  jerr.pub.error_exit = my_error_exit;
  for (int ti = 0; ti < NUMTESTS; ++ti) {
    fseek(file, 0, SEEK_SET);
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = my_error_exit;

    if (setjmp(jerr.setjmp_buffer)) {
      jpeg_destroy_decompress(&cinfo);
      continue;
    }

    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, data, size);
    (void)jpeg_read_header(&cinfo, TRUE);

    switch (tests[ti]) {
#ifdef BMP_SUPPORTED
    case FMT_BMP:
      dest_mgr = jinit_write_bmp(&cinfo, FALSE);
      break;
    case FMT_OS2:
      dest_mgr = jinit_write_bmp(&cinfo, TRUE);
      break;
#endif
#ifdef GIF_SUPPORTED
    case FMT_GIF:
      dest_mgr = jinit_write_gif(&cinfo, TRUE);
      break;
    case FMT_GIF0:
      dest_mgr = jinit_write_gif(&cinfo, FALSE);
      break;
#endif
#ifdef PPM_SUPPORTED
    case FMT_PPM:
      dest_mgr = jinit_write_ppm(&cinfo);
      break;
#endif
#ifdef RLE_SUPPORTED
    case FMT_RLE:
      dest_mgr = jinit_write_rle(&cinfo);
      break;
#endif
#ifdef TARGA_SUPPORTED
    case FMT_TARGA:
      dest_mgr = jinit_write_targa(&cinfo);
      break;
#endif
    default:
      ERREXIT(&cinfo, JERR_UNSUPPORTED_FORMAT);
    }
    dest_mgr->output_file = file;

    jpeg_start_decompress(&cinfo);
    (*dest_mgr->start_output)(&cinfo, dest_mgr);

    while (cinfo.output_scanline < cinfo.output_height) {
      num_scanlines = jpeg_read_scanlines(&cinfo, dest_mgr->buffer,
                                          dest_mgr->buffer_height);
      (*dest_mgr->put_pixel_rows)(&cinfo, dest_mgr, num_scanlines);
    }

    (*dest_mgr->finish_output)(&cinfo, dest_mgr);
    (void)jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
  }
  // <-----------------------------------> //

bailout:
  fclose(file);
  free((void *)data);
  return 0;
}

int main(int argc, char **argv) {
  FILE *fd = fopen(argv[1], "rb");
  if (!fd)
    return 1;
  fseek(fd, 0, SEEK_END);
  long fsize = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  char *buffer = (char *)malloc(fsize);
  fread(buffer, 1, fsize, fd);
  fclose(fd);
  return LLVMFuzzerTestOneInput((const uint8_t *)buffer, fsize);
}
