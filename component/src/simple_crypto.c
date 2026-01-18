/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>


/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error


    // Encrypt each block
    for (int i = 0; i < len; i += BLOCK_SIZE) {
        result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    // Decrypt each block
    for (int i = 0; i < len; i += BLOCK_SIZE) {
        result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to encrypt
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(const uint8_t *data, size_t len, uint8_t *hash_out) {
    return wc_Sha256Hash(data, len, hash_out);
}

int hash_sha256(const uint8_t *data, size_t len, uint8_t *hash_out) {
    return wc_Sha256Hash(data, len, hash_out);
}

int hkdf_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                size_t ikm_len, const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
    return wc_HKDF(SHA256, ikm, (word32)ikm_len, salt, (word32)salt_len,
                   info, (word32)info_len, okm, (word32)okm_len);
}

int aead_encrypt_gcm(const uint8_t *key, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len, const uint8_t *plaintext,
                     size_t plaintext_len, uint8_t *ciphertext, uint8_t *tag,
                     size_t tag_len) {
    Aes aes;
    int ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AesGcmSetKey(&aes, key, KEY_SIZE);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }
    ret = wc_AesGcmEncrypt(&aes, ciphertext, plaintext, (word32)plaintext_len,
                           nonce, (word32)nonce_len, tag, (word32)tag_len,
                           aad, (word32)aad_len);
    wc_AesFree(&aes);
    return ret;
}

int aead_decrypt_gcm(const uint8_t *key, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext,
                     size_t ciphertext_len, const uint8_t *tag, size_t tag_len,
                     uint8_t *plaintext) {
    Aes aes;
    int ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AesGcmSetKey(&aes, key, KEY_SIZE);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }
    ret = wc_AesGcmDecrypt(&aes, plaintext, ciphertext, (word32)ciphertext_len,
                           nonce, (word32)nonce_len, tag, (word32)tag_len,
                           aad, (word32)aad_len);
    wc_AesFree(&aes);
    return ret;
}

#endif
