
#include <cdjpeg.h>
#include <cstddef>
#include <jpeglib.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NUMTESTS 6

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

LOCAL(cjpeg_source_ptr)
select_file_type(j_compress_ptr cinfo, FILE *infile) {
  int c;

  if ((c = getc(infile)) == EOF)
    ERREXIT(cinfo, JERR_INPUT_EMPTY);
  if (ungetc(c, infile) == EOF)
    ERREXIT(cinfo, JERR_UNGETC_FAILED);

  switch (c) {
#ifdef BMP_SUPPORTED
  case 'B':
    return jinit_read_bmp(cinfo);
#endif
#ifdef GIF_SUPPORTED
  case 'G':
    return jinit_read_gif(cinfo);
#endif
#ifdef PPM_SUPPORTED
  case 'P':
    return jinit_read_ppm(cinfo);
#endif
#ifdef RLE_SUPPORTED
  case 'R':
    return jinit_read_rle(cinfo);
#endif
#ifdef TARGA_SUPPORTED
  case 0x00:
    return jinit_read_targa(cinfo);
#endif
  default:
    ERREXIT(cinfo, JERR_UNKNOWN_FORMAT);
    break;
  }

  return NULL; /* suppress compiler warnings */
}

typedef struct {
  struct jpeg_destination_mgr pub; /* public fields */

  FILE *outfile;  /* target stream */
  JOCTET *buffer; /* start of buffer */
} my_destination_mgr;

typedef struct {
  struct jpeg_destination_mgr pub; /* public fields */

  unsigned char **outbuffer; /* target buffer */
  size_t *outsize;
  unsigned char *newbuffer; /* newly allocated buffer */
  JOCTET *buffer;           /* start of buffer */
  size_t bufsize;
} my_mem_destination_mgr;

struct test {
  J_COLOR_SPACE cs;
  int quality;
};

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  struct jpeg_compress_struct cinfo;
  struct my_error_mgr jerr;
  char input_file[FILENAME_MAX] = {0};
  int fd = -1, ti = 0, i = 0;
  char ff = 0;
  FILE *file;
  unsigned char *dstBuf = NULL;
  cjpeg_source_ptr src_mgr;
  JDIMENSION num_scanlines;
  struct test tests[NUMTESTS]{{JCS_RGB, 95},    {JCS_GRAYSCALE, 90},
                              {JCS_CMYK, 80},   {JCS_BG_RGB, 70},
                              {JCS_BG_YCC, 60}, {JCS_YCCK, 50}};

  snprintf(input_file, FILENAME_MAX, "/tmp/libjpeg_compress_fuzz.XXXXXX");
  if ((fd = mkstemp(input_file)) < 0 || write(fd, data, size) < 0)
    goto bailout;
  if ((file = fdopen(fd, "rb")) == NULL)
    goto bailout;
  // <------------------------------------> //
  jerr.pub.error_exit = my_error_exit;
  for (int ti = 0; ti < NUMTESTS; ++ti) {
    fseek(file, 0, SEEK_SET);
    size_t dstSize = 0;
    unsigned int sum = 0;
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = my_error_exit;

    if (setjmp(jerr.setjmp_buffer)) {
      if (cinfo.dest != NULL)
        free(((my_mem_destination_mgr *)cinfo.dest)->newbuffer);
      jpeg_destroy_compress(&cinfo);
      continue;
    }

    jpeg_create_compress(&cinfo);

    src_mgr = select_file_type(&cinfo, file);
    src_mgr->input_file = file;
    (*src_mgr->start_input)(&cinfo, src_mgr);

    jpeg_mem_dest(&cinfo, &dstBuf, &dstSize);

    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, tests[ti].quality, TRUE);
    jpeg_set_colorspace(&cinfo, tests[ti].cs);

    jpeg_start_compress(&cinfo, TRUE);

    while (cinfo.next_scanline < cinfo.image_height) {
      num_scanlines = (*src_mgr->get_pixel_rows)(&cinfo, src_mgr);
      (void)jpeg_write_scanlines(&cinfo, src_mgr->buffer, num_scanlines);
    }

    (*src_mgr->finish_input)(&cinfo, src_mgr);
    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);

    for (i = 0; i < dstSize; ++i) {
      sum += dstBuf[i];
    }
    free(dstBuf);
    dstBuf = NULL;
    if (sum < 1) {
      goto bailout;
    }
  }
  // <-----------------------------------> //

bailout:
  // free(dstBuf);
  if (fd >= 0 || file == NULL) {
    fclose(file);
    if (strlen(input_file) > 0)
      unlink(input_file);
  }
  return 0;
}
