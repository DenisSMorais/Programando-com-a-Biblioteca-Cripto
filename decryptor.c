#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Função para descriptografar
int decrypt(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    // Inicialize o contexto para decriptação AES-128-CBC
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        printf("Erro ao inicializar decriptação.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Atualize com o texto cifrado
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        printf("Erro durante a decriptação.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finalize a decriptação
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // Retorna erro se a decriptação falhar
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Função para tentar todas as chaves do dicionário
void try_keys(unsigned char *ciphertext, int ciphertext_len, unsigned char *iv) {
    FILE *fp = fopen("wordlist.txt", "r");
    if (fp == NULL) {
        printf("Erro ao abrir o arquivo wordlist.txt.\n");
        return;
    }

    char word[100];
    while (fgets(word, sizeof(word), fp)) {
        // Remova o caractere de nova linha
        word[strcspn(word, "\n")] = 0;

        // Monte a chave com o padding de '#' até 16 bytes
        unsigned char key[16];
        int i;
        for (i = 0; i < 16; i++) {
            if (i < strlen(word)) {
                key[i] = word[i];
            } else {
                key[i] = '#';
            }
        }

        unsigned char decrypted_text[256];
        int decrypted_len = decrypt(key, iv, ciphertext, ciphertext_len, decrypted_text);

        if (decrypted_len > 0) {
            decrypted_text[decrypted_len] = '\0'; // Torne a saída uma string
            if (strcmp((char *)decrypted_text, "This is a top secret.") == 0) {
                printf("Chave encontrada: %s\n", word);
                fclose(fp);
                return;
            }
        }
    }

    printf("Nenhuma chave válida encontrada.\n");
    fclose(fp);
}

int main() {
    // Texto cifrado fornecido (hexadecimal)
    unsigned char ciphertext[] = {
        0x76, 0x4a, 0xa2, 0x6b, 0x55, 0xa4, 0xda, 0x65, 0x4d, 0xf6, 0xb1, 0x9e, 0x4b, 0xce, 0x00, 0xf4,
        0xed, 0x05, 0xe0, 0x93, 0x46, 0xfb, 0x0e, 0x76, 0x25, 0x83, 0xcb, 0x7d, 0xa2, 0xac, 0x93, 0xa2
    };

    // IV fornecido (hexadecimal)
    unsigned char iv[] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
    };

    int ciphertext_len = sizeof(ciphertext);

    // Tente encontrar a chave
    try_keys(ciphertext, ciphertext_len, iv);

    return 0;
}
