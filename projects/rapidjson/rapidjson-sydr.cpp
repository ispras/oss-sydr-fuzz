/* By Guido Vranken <guidovranken@gmail.com> */

#include <cstdint>
#include <cstddef>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

#ifdef MSAN
extern "C" {
    void __msan_check_mem_is_initialized(const volatile void *x, size_t size);
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const std::string s(data, data + size);

    /* Parse input to rapidjson::Document */
    rapidjson::Document document;
    rapidjson::ParseResult pr = document.Parse(s.c_str());
    if ( !pr ) {
        return 0;
    }

    /* Convert from rapidjson::Document to string */
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
    document.Accept(writer);
    std::string str = sb.GetString();
#ifdef MSAN
    if ( str.size() ) {
        __msan_check_mem_is_initialized(str.data(), str.size());
    }
#endif

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
