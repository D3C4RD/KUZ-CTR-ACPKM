#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 8192

int hashFile(const char *filename, unsigned char *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return 0;
    }

    // Инициализация контекста SHA-256
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);

    // Буфер для чтения файла
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;

    // Чтение файла и обновление хэша
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) != 0) {
        SHA256_Update(&sha256_ctx, buffer, bytes_read);
    }

    // Получение хэша
    SHA256_Final(hash, &sha256_ctx);

    // Закрытие файла
    fclose(file);

    return 1;
}

int main() {
    // Имя файла, для которого нужно вычислить хэш
    const char *filename = "example.txt";

    // Буфер для хранения хэша
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Вычисление хэша файла
    if (hashFile(filename, hash)) {
        // Вывод хэша
        printf("SHA-256 hash of %s:\n", filename);
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    } else {
        printf("Failed to compute hash for file: %s\n", filename);
    }

    return 0;
}