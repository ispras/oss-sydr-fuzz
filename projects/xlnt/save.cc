/* Copyright (C) 2023 ISP RAS
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
