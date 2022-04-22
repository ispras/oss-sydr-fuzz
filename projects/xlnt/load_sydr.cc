#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <xlnt/xlnt.hpp>
#include <libstudxml/parser.hxx>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<uint8_t> v_data(data, data + size);
    xlnt::workbook excelWorkbook;
    try
    {
        excelWorkbook.load(v_data);
    }
    catch (const xlnt::exception& e)
    {
        return 0;
    }
    catch (const xml::parsing& e)
    {
        return 0;
    }
    return 0;
}

int main(int argc, char** argv)
{
    FILE *fd = fopen(argv[1], "rb");

    if (fd == NULL) return 1;
    fseek(fd, 0, SEEK_END);
    int fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    char* buffer = (char*) malloc(sizeof(char) * fsize);
    fread(buffer, 1, fsize, fd);
    fclose(fd);

    return LLVMFuzzerTestOneInput((const uint8_t*)buffer, fsize);
}
