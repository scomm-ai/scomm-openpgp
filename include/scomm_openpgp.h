#ifndef SCOMM_OPENPGP_H
#define SCOMM_OPENPGP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t scomm_openpgp_abi_version(void);
void scomm_openpgp_buffer_free(uint8_t *ptr, size_t len);
int32_t scomm_openpgp_last_error(uint8_t **out, size_t *out_len);

int32_t scomm_openpgp_inspect(
    const uint8_t *key, size_t key_len,
    uint8_t **json_out, size_t *json_len);

int32_t scomm_openpgp_generate(
    const uint8_t *userid, size_t userid_len,
    const uint8_t *passphrase, size_t passphrase_len,
    int32_t profile,
    uint8_t **public_out, size_t *public_len,
    uint8_t **secret_out, size_t *secret_len,
    uint8_t **json_out, size_t *json_len);

int32_t scomm_openpgp_rfc9980_ready(void);

int32_t scomm_openpgp_export_public(
    const uint8_t *key, size_t key_len,
    uint8_t **out, size_t *out_len);

int32_t scomm_openpgp_armor(
    int32_t kind,
    const uint8_t *binary, size_t binary_len,
    uint8_t **out, size_t *out_len);

int32_t scomm_openpgp_encrypt(
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *recipients, size_t recipients_len,
    int32_t armored,
    uint8_t **out, size_t *out_len);

int32_t scomm_openpgp_decrypt(
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len,
    uint8_t **out, size_t *out_len);

int32_t scomm_openpgp_sign(
    const uint8_t *data, size_t data_len,
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len,
    int32_t armored,
    int32_t detached,
    uint8_t **out, size_t *out_len);

int32_t scomm_openpgp_verify(
    const uint8_t *data, size_t data_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key, size_t public_key_len,
    int32_t *valid_out);

int32_t scomm_openpgp_test_passphrase(
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len);

int32_t scomm_openpgp_sign_pop(
    const uint8_t *data, size_t data_len,
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len,
    const uint8_t *notation, size_t notation_len,
    uint8_t **out, size_t *out_len);

/* Primitives. alg: 1 MD5, 2 SHA-1, 3 SHA-256, 4 SHA-384, 5 SHA-512.
 * Outputs are freed with scomm_openpgp_buffer_free. Verify calls return
 * 1 valid, 0 invalid signature, -1 error. */
int32_t scomm_prims_digest(int32_t alg, const uint8_t *data, size_t data_len,
    uint8_t **out, size_t *out_len);
int32_t scomm_prims_hmac(int32_t alg, const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int32_t scomm_prims_pbkdf2(int32_t alg, const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len, size_t iterations, size_t key_len,
    uint8_t **out, size_t *out_len);
int32_t scomm_prims_rsa_pkcs1_sign(int32_t alg,
    const uint8_t *private_key_der, size_t private_key_len,
    const uint8_t *message, size_t message_len, uint8_t **out, size_t *out_len);
int32_t scomm_prims_rsa_pkcs1_verify(int32_t alg,
    const uint8_t *spki_der, size_t spki_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len);
int32_t scomm_prims_ecdsa_verify(int32_t alg,
    const uint8_t *spki_der, size_t spki_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len, int32_t raw);
int32_t scomm_prims_aes_cbc_encrypt(const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len, const uint8_t *plaintext, size_t plaintext_len,
    uint8_t **out, size_t *out_len);
int32_t scomm_prims_aes_cbc_decrypt(const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len, const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t **out, size_t *out_len);

/* Keys. kind: 1 EC P-256, 2 RSA-2048, 3 RSA-3072, 4 Ed25519.
 * scheme: 1 ECDSA-SHA256 (DER), 2 RSASSA-PKCS1-v1_5-SHA256, 3 Ed25519. */
int32_t scomm_prims_pkey_generate(int32_t kind,
    uint8_t **pkcs8_out, size_t *pkcs8_len, uint8_t **spki_out, size_t *spki_len);
int32_t scomm_prims_ec_p256_from_scalar(const uint8_t *scalar, size_t scalar_len,
    uint8_t **pkcs8_out, size_t *pkcs8_len, uint8_t **spki_out, size_t *spki_len);
int32_t scomm_prims_pkey_sign(int32_t scheme,
    const uint8_t *pkcs8, size_t pkcs8_len,
    const uint8_t *message, size_t message_len, uint8_t **out, size_t *out_len);
int32_t scomm_prims_pkcs8_encrypt(const uint8_t *pkcs8, size_t pkcs8_len,
    const uint8_t *passphrase, size_t passphrase_len, uint32_t iterations,
    uint8_t **out, size_t *out_len);
int32_t scomm_prims_pkcs8_decrypt(const uint8_t *encrypted, size_t encrypted_len,
    const uint8_t *passphrase, size_t passphrase_len, uint8_t **out, size_t *out_len);
int32_t scomm_prims_csr_create(const uint8_t *pkcs8, size_t pkcs8_len,
    const uint8_t *subject, size_t subject_len, uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
