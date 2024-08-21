#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

// Fonction de chiffrement et déchiffrement avec XOR
void encrypt_decrypt(uint8_t *data, size_t size, uint8_t key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;  // XOR pour chiffrer ou déchiffrer
    }
}

void decrypt_file(const char *filename, uint8_t key) {
    // Ouvrir le fichier en mode lecture
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Obtenir la taille du fichier
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1) {
        perror("lseek");
        close(fd);
        exit(EXIT_FAILURE);
    }
    lseek(fd, 0, SEEK_SET);

    // Lire le contenu du fichier en mémoire
    uint8_t *data = malloc(file_size);
    if (data == NULL) {
        perror("malloc");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if (read(fd, data, file_size) != file_size) {
        perror("read");
        free(data);
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);

    // Déchiffrer les données
    encrypt_decrypt(data, file_size, key);

    // Écrire les données déchiffrées dans un nouveau fichier
    int fd2 = open("decrypted_file", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd2 == -1) {
        perror("open");
        free(data);
        exit(EXIT_FAILURE);
    }
    if (write(fd2, data, file_size) != file_size) {
        perror("write");
        free(data);
        close(fd2);
        exit(EXIT_FAILURE);
    }
    close(fd2);
    free(data);
}

int main(int argc, char **argv) {
    uint8_t key = atol(argv[1]);  // Clé de chiffrement
    decrypt_file("woody", key);  // Nom du fichier chiffré
    return 0;
}
