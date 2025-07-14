#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Note: LLVMFuzzerInitialize is optional and may not be provided by all fuzz targets.
extern int  __attribute__((weak)) LLVMFuzzerInitialize(int *argc, char ***argv);
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
  return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [input]\n", argv[0]);
        goto err;
    }

    if (LLVMFuzzerInitialize != NULL && LLVMFuzzerInitialize(&argc, &argv) != 0) {
        perror("LLVMFuzzerInitialize");
        goto err;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        goto err;
    }

    // Determine file size
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        goto err_fp;
    }

    long size = ftell(fp);
    if (size < 0) {
        perror("ftell");
        goto err_fp;
    }

    // Rewind to start of file
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek");
        goto err_fp;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)size);
    if (!data) {
        perror("malloc");
        goto err_fp;
    }

    size_t bytes_read = fread(data, 1, (size_t)size, fp);
    if (bytes_read != (size_t)size) {
        fprintf(stderr, "Failed to read entire file. Expected %ld bytes, got %zu bytes.\n", size, bytes_read);
        goto err_data;
    }

    fclose(fp);

    // Run the fuzzing entrypoint once with the provided input
    LLVMFuzzerTestOneInput(data, (size_t)size);
    free(data);
    return 0;

err_data:
    free(data);
err_fp:
    fclose(fp);

err:
    return 1;
}