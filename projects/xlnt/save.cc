#include <xlnt/xlnt.hpp>
#include <libstudxml/parser.hxx>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) {
    	return 0;
    }
    const uint8_t *book_data = data + 2; 
    size_t book_size = size - 2; 
    std::vector<uint8_t> v_data(book_data, book_data + book_size);
    xlnt::workbook excelWorkbook;
    try
    {
        excelWorkbook.load(v_data);

        auto wsheet = excelWorkbook.sheet_by_index(0);
        wsheet.insert_rows(data[0], data[1]);
        wsheet.insert_columns(data[0], data[1]);
        wsheet.delete_rows(data[0], data[1]);
        wsheet.delete_columns(data[0], data[1]);

        std::vector<uint8_t> s_data;
        excelWorkbook.save(s_data);
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
