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
        return 1;
    }
    catch (const xml::parsing& e)
    {
        return 1;
    }
    return 0;
}
