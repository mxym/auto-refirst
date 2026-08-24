#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int copy_file(const char *source_name, const char *destination_name) {
    FILE *source = fopen(source_name, "rb");
    FILE *destination = fopen(destination_name, "wb");
    unsigned char buffer[4096];
    size_t count;
    if (source == NULL || destination == NULL) {
        return 1;
    }
    while ((count = fread(buffer, 1, sizeof(buffer), source)) != 0) {
        if (fwrite(buffer, 1, count, destination) != count) {
            return 1;
        }
    }
    return fclose(source) != 0 || fclose(destination) != 0;
}

int main(int argc, char **argv) {
    int detector = 0;
    unsigned char mode = 'N';
    FILE *input;

    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "-d") == 0) {
            detector = 1;
        }
    }

    input = fopen("/input/target.dll", "rb");
    if (input == NULL) {
        fprintf(stderr, "input open failed: %s\n", strerror(errno));
        return 20;
    }
    if (fread(&mode, 1, 1, input) != 1 && ferror(input)) {
        fclose(input);
        return 23;
    }
    fclose(input);

    puts(mode == 'V' ? "de4dotEx v3.8.0.1" : "de4dotEx v3.8.0.0");
    fflush(stdout);
    if (mode == 'T') {
        sleep(5);
    } else if (mode == 'C') {
        raise(SIGSEGV);
    } else if (mode == 'O') {
        for (int index = 0; index < 200000; ++index) {
            putchar('x');
        }
        fflush(stdout);
        sleep(1);
    } else if (mode == 'M') {
        puts("not a detector record");
        return 0;
    }

    if (!detector) {
        if (mode == 'S') {
            if (symlink("/input/target.dll", "/output/cleaned.dll") != 0) {
                return 21;
            }
        } else if (copy_file("/input/target.dll", "/output/cleaned.dll") != 0) {
            return 22;
        }
    }
    puts("Detected Obfuscar (/input/target.dll)");
    return 0;
}
