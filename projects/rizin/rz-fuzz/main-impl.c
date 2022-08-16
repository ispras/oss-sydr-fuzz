#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <rz_core.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern int LLVMFuzzerInitialize(int *argc, char ***argv);
extern RzCore *g_rz_core;

int main(int argc, char* argv[])
{
    LLVMFuzzerInitialize(&argc, &argv);

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
