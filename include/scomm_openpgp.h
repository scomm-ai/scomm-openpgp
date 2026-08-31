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

int32_t scomm_openpgp_pop_sign_composite(
    const uint8_t *data, size_t data_len,
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len,
    uint8_t **mldsa_out, size_t *mldsa_len,
    uint8_t **ed25519_out, size_t *ed25519_len);

int32_t scomm_openpgp_pop_hybrid_shared(
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len,
    const uint8_t *kem_ciphertext, size_t kem_ciphertext_len,
    const uint8_t *ephemeral_x25519, size_t ephemeral_x25519_len,
    uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
