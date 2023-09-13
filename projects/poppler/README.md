# POPPLER

Poppler is a library for rendering PDF files, and examining or modifying their structure.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-poppler .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/poppler` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-poppler /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * annot
  * doc_attr
  * doc
  * find_text
  * label
  * page_label
  * page_search
  * pdf_draw
  * pdf_file
  * pdf
  * qt_annot
  * qt_label
  * qt_pdf
  * qt_search
  * qt_textbox
  * util

## Fuzzing

### annot

Run hybrid fuzzing:

    # sydr-fuzz -c annot.toml run

Collect and report coverage:

    # sydr-fuzz -c annot.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c annot.toml cov-export -- -format=lcov > annot.lcov
    # genhtml -o annot-html annot.lcov

### doc_attr

Run hybrid fuzzing:

    # sydr-fuzz -c doc_attr.toml run

Collect and report coverage:

    # sydr-fuzz -c doc_attr.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c doc_attr.toml cov-export -- -format=lcov > doc_attr.lcov
    # genhtml -o doc_attr-html doc_attr.lcov

### doc

Run hybrid fuzzing:

    # sydr-fuzz -c doc.toml run

Collect and report coverage:

    # sydr-fuzz -c doc.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c doc.toml cov-export -- -format=lcov > doc.lcov
    # genhtml -o doc-html doc.lcov

### find_text

Run hybrid fuzzing:

    # sydr-fuzz -c find_text.toml run

Collect and report coverage:

    # sydr-fuzz -c find_text.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c find_text.toml cov-export -- -format=lcov > find_text.lcov
    # genhtml -o find_text-html find_text.lcov

### label

Run hybrid fuzzing:

    # sydr-fuzz -c label.toml run

Collect and report coverage:

    # sydr-fuzz -c label.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c label.toml cov-export -- -format=lcov > label.lcov
    # genhtml -o label-html label.lcov

### page_label

Run hybrid fuzzing:

    # sydr-fuzz -c page_label.toml run

Collect and report coverage:

    # sydr-fuzz -c page_label.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c page_label.toml cov-export -- -format=lcov > page_label.lcov
    # genhtml -o page_label-html page_label.lcov

### page_search

Run hybrid fuzzing:

    # sydr-fuzz -c page_search.toml run

Collect and report coverage:

    # sydr-fuzz -c page_search.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c page_search.toml cov-export -- -format=lcov > page_search.lcov
    # genhtml -o page_search-html page_search.lcov

### pdf_draw

Run hybrid fuzzing:

    # sydr-fuzz -c pdf_draw.toml run

Collect and report coverage:

    # sydr-fuzz -c pdf_draw.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c pdf_draw.toml cov-export -- -format=lcov > pdf_draw.lcov
    # genhtml -o pdf_draw-html pdf_draw.lcov

### pdf_file

Run hybrid fuzzing:

    # sydr-fuzz -c pdf_file.toml run

Collect and report coverage:

    # sydr-fuzz -c pdf_file.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c pdf_file.toml cov-export -- -format=lcov > pdf_file.lcov
    # genhtml -o pdf_file-html pdf_file.lcov

### pdf

Run hybrid fuzzing:

    # sydr-fuzz -c pdf.toml run

Collect and report coverage:

    # sydr-fuzz -c pdf.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c pdf.toml cov-export -- -format=lcov > pdf.lcov
    # genhtml -o pdf-html pdf.lcov

### qt_annot

Run hybrid fuzzing:

    # sydr-fuzz -c qt_annot.toml run

Collect and report coverage:

    # sydr-fuzz -c qt_annot.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c qt_annot.toml cov-export -- -format=lcov > qt_annot.lcov
    # genhtml -o qt_annot-html qt_annot.lcov

### qt_label

Run hybrid fuzzing:

    # sydr-fuzz -c qt_label.toml run

Collect and report coverage:

    # sydr-fuzz -c qt_label.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c qt_label.toml cov-export -- -format=lcov > qt_label.lcov
    # genhtml -o qt_label-html qt_label.lcov

### qt_pdf

Run hybrid fuzzing:

    # sydr-fuzz -c qt_pdf.toml run

Collect and report coverage:

    # sydr-fuzz -c qt_pdf.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c qt_pdf.toml cov-export -- -format=lcov > qt_pdf.lcov
    # genhtml -o qt_pdf-html qt_pdf.lcov

### qt_search

Run hybrid fuzzing:

    # sydr-fuzz -c qt_search.toml run

Collect and report coverage:

    # sydr-fuzz -c qt_search.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c qt_search.toml cov-export -- -format=lcov > qt_search.lcov
    # genhtml -o qt_search-html qt_search.lcov

### qt_textbox

Run hybrid fuzzing:

    # sydr-fuzz -c qt_textbox.toml run

Collect and report coverage:

    # sydr-fuzz -c qt_textbox.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c qt_textbox.toml cov-export -- -format=lcov > qt_textbox.lcov
    # genhtml -o qt_textbox-html qt_textbox.lcov

### util

Run hybrid fuzzing:

    # sydr-fuzz -c util.toml run

Collect and report coverage:

    # sydr-fuzz -c util.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c util.toml cov-export -- -format=lcov > util.lcov
    # genhtml -o util-html util.lcov
