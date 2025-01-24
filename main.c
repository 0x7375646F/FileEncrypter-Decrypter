#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SALT_LEN 16
#define ITERATIONS 500000
#define KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16

// PBKDF2 key derivation
void derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, ITERATIONS, EVP_sha512(), KEY_LEN, key)) {
        fprintf(stderr, "Key derivation failed\n");
        exit(1);
    }
    // printf("SALT: ");
    // for(int i = 0; i<SALT_LEN; i++){
    //     printf("%x",salt[i]);
    // }
    // printf("\n");
    // printf("KEY: ");
    // for(int i = 0; i<KEY_LEN; i++){
    //     printf("%x",key[i]);
    // }
    // printf("\n");
}

// AES-256-GCM encryption
void encrypt_file(const char *input_file, const char *output_file, const char *password) {
    unsigned char key[KEY_LEN], salt[SALT_LEN], nonce[NONCE_LEN], tag[TAG_LEN] = {0};

    // Generate random salt and nonce
    if (!RAND_bytes(salt, SALT_LEN) || !RAND_bytes(nonce, NONCE_LEN)) {
        fprintf(stderr, "Random generation failed\n");
        exit(1);
    }

    // printf("Nonce: ");
    // for(int i = 0; i<NONCE_LEN; i++){
    //     printf("%x",nonce[i]);
    // }
    // printf("\n");

    derive_key(password, salt, key);

    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "w+");
    if (!in || !out) {
        perror("File error");
        exit(1);
    }

    // Write salt and nonce to the output file
    fwrite(salt, 1, SALT_LEN, out);
    fwrite(nonce, 1, NONCE_LEN, out);
    fwrite(tag, 1, TAG_LEN, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //create 
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

    unsigned char buffer[4096], ciphertext[4096];
    int len, ciphertext_len = 0;

    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, len);
        fwrite(ciphertext, 1, ciphertext_len, out);
    }

    EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    fseek(out, SALT_LEN + NONCE_LEN, SEEK_SET); // Seek to top of the file
    fwrite(tag, 1, TAG_LEN, out);  // Store authentication tag
    
    // printf("Tag: ");
    // for(int i = 0;i<TAG_LEN;i++){
    //     printf("%x",tag[i]);
    // }
    // printf("\n");
    
    EVP_CIPHER_CTX_free(ctx); //free evp cipher ctx
    fclose(in);
    fclose(out);
}

// AES-256-GCM decryption
int decrypt_file(const char *input_file, const char *output_file, const char *password) {
    unsigned char key[KEY_LEN], salt[SALT_LEN], nonce[NONCE_LEN], tag[TAG_LEN];

    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        perror("File error");
        return 1;
    }

    // Read salt, nonce, and authentication tag
    fread(salt, 1, SALT_LEN, in);
    fread(nonce, 1, NONCE_LEN, in);
    fread(tag, 1, TAG_LEN, in);
    fseek(in, SALT_LEN + NONCE_LEN + TAG_LEN, SEEK_SET);

    // printf("Nonce: ");
    // for(int i = 0; i<NONCE_LEN; i++){
    //     printf("%x",nonce[i]);
    // }
    // printf("\n");

    // printf("Tag: ");
    // for(int i = 0; i<TAG_LEN; i++){
    //     printf("%x",tag[i]);
    // }
    // printf("\n");

    derive_key(password, salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);

    unsigned char buffer[4096], plaintext[4096];
    int len, plaintext_len = 0;

    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buffer, len);
        fwrite(plaintext, 1, plaintext_len, out);
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
    if (EVP_DecryptFinal_ex(ctx, plaintext, &plaintext_len) <= 0) {
        fprintf(stderr, "Decryption failed (possible tampering)\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    fwrite(plaintext, 1, plaintext_len, out);
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s encrypt|decrypt input_file output_file password\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        encrypt_file(argv[2], argv[3], argv[4]);
        printf("File encrypted successfully!\n");
    } else if (strcmp(argv[1], "decrypt") == 0) {
        if (decrypt_file(argv[2], argv[3], argv[4]) == 0) {
            printf("File decrypted successfully!\n");
        }
    } else {
        fprintf(stderr, "Invalid operation\n");
        return 1;
    }

    return 0;
}
