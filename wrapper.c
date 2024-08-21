#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

void encrypt(uint8_t *data, size_t size, uint8_t key);

void decrypt_file(const char *input_file, const char *output_file, uint8_t key) {
    int fd_in, fd_out;
    ssize_t size;
    uint8_t *data;

    // Ouvre le fichier encrypté en lecture
    fd_in = open(input_file, O_RDONLY);
    if (fd_in == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Obtiens la taille du fichier
    size = lseek(fd_in, 0, SEEK_END);
    if (size == -1) {
        perror("lseek");
        close(fd_in);
        exit(EXIT_FAILURE);
    }

    // Alloue la mémoire pour les données
    data = (uint8_t *)malloc(size);
    if (data == NULL) {
        perror("malloc");
        close(fd_in);
        exit(EXIT_FAILURE);
    }

    // Lis les données encryptées
    lseek(fd_in, 0, SEEK_SET);
    if (read(fd_in, data, size) == -1) {
        perror("read");
        free(data);
        close(fd_in);
        exit(EXIT_FAILURE);
    }
    close(fd_in);

    // Déchiffre les données
    encrypt(data, size, key);

    // Ouvre ou crée un fichier de sortie pour stocker les données décryptées
    fd_out = open(output_file, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (fd_out == -1) {
        perror("open");
        free(data);
        exit(EXIT_FAILURE);
    }

    // Écris les données décryptées dans le fichier de sortie
    if (write(fd_out, data, size) == -1) {
        perror("write");
        free(data);
        close(fd_out);
        exit(EXIT_FAILURE);
    }

    // Libère la mémoire et ferme le fichier
    free(data);
    close(fd_out);

    printf("Fichier décrypté avec succès : %s\n", output_file);
}

void encrypt(uint8_t *data, size_t size, uint8_t key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

int main() {
    // Nom du fichier encrypté et du fichier de sortie décrypté
    const char *input_file = "woody";
    const char *output_file = "decrypted_output";
    uint8_t key = 0x42;

    // Déchiffre le fichier
    decrypt_file(input_file, output_file, key);

    return 0;
}

