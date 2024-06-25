#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <stdint.h>

#define BUFFER_SIZE 4096

int get_h(int fd, uint8_t hash[32]) {
    SHA256_CTX context;
    SHA256_Init(&context);

    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        SHA256_Update(&context, buffer, bytes_read);
    }

    if (bytes_read < 0) {
        perror("Ошибка чтения файла");
        return -1;
    }

    SHA256_Final(hash, &context);

    return 0;
}
