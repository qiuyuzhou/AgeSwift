/*
 * age_swift_ffi.h — C ABI over the Rust `age` crate for AgeSwift.
 *
 * Ownership rules (also documented per function below):
 *   - All input pointers are borrowed for the duration of the call only.
 *   - Buffers returned via `ageswift_bytes` and strings returned via
 *     `char **` out-params are allocated by Rust and must be released only
 *     with `ageswift_free_bytes` / `ageswift_free_string`. Never `free()`
 *     them from Swift.
 *   - `error_out`, when non-NULL, is set to a Rust-allocated message exactly
 *     when the return code is not AGESWIFT_OK; release it with
 *     `ageswift_free_string`. Messages never contain key material,
 *     passphrases, or plaintext.
 *
 * Every function is panic-safe: Rust panics are caught at the boundary and
 * reported as AGESWIFT_ERR_PANIC.
 */
#ifndef AGE_SWIFT_FFI_H
#define AGE_SWIFT_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ageswift_status {
    AGESWIFT_OK = 0,
    /* NULL pointer where a buffer was required, invalid UTF-8, empty list. */
    AGESWIFT_ERR_INVALID_ARGUMENT = 1,
    /* String is not a valid age secret identity ("AGE-SECRET-KEY-1..."). */
    AGESWIFT_ERR_INVALID_IDENTITY = 2,
    /* String is not a valid age recipient ("age1..."). */
    AGESWIFT_ERR_INVALID_RECIPIENT = 3,
    /* Encryption failed. */
    AGESWIFT_ERR_ENCRYPTION_FAILED = 4,
    /* Decryption failed (e.g. corrupted payload). */
    AGESWIFT_ERR_DECRYPTION_FAILED = 5,
    /* No provided identity/passphrase matched the file header. */
    AGESWIFT_ERR_NO_MATCHING_KEY = 6,
    /* Input is not a valid age file (bad magic / header / MAC). */
    AGESWIFT_ERR_INVALID_FORMAT = 7,
    /* A Rust panic was caught at the FFI boundary. */
    AGESWIFT_ERR_PANIC = 8
} ageswift_status;

/*
 * Rust-allocated byte buffer. Valid only after a call returned AGESWIFT_OK
 * and only until `ageswift_free_bytes` is called. `ptr` may be NULL when
 * `len` is 0.
 */
typedef struct ageswift_bytes {
    uint8_t *ptr;
    uintptr_t len;
    uintptr_t capacity; /* internal: required to reconstruct the Vec */
} ageswift_bytes;

/* Version of this FFI library (not of the age crate), e.g. "0.1.0". */
const char *ageswift_ffi_version(void);

/*
 * Generate a new X25519 identity using the OS CSPRNG.
 * On success sets *identity_out to "AGE-SECRET-KEY-1..." and *recipient_out
 * to the matching public "age1..." string. Free both with
 * ageswift_free_string.
 */
ageswift_status ageswift_generate_identity(char **identity_out,
                                           char **recipient_out,
                                           char **error_out);

/* Validate that `identity` parses as an age secret identity. No allocation. */
ageswift_status ageswift_validate_identity(const char *identity,
                                           char **error_out);

/* Validate that `recipient` parses as an age recipient. No allocation. */
ageswift_status ageswift_validate_recipient(const char *recipient,
                                            char **error_out);

/*
 * Derive the public recipient string for a secret identity.
 * On success sets *recipient_out; free it with ageswift_free_string.
 */
ageswift_status ageswift_identity_recipient(const char *identity,
                                            char **recipient_out,
                                            char **error_out);

/*
 * Output encoding for encryption. Armored output is the age ASCII armor
 * format (PEM-like, canonical base64, 64-column lines); it is pure ASCII
 * and safe to treat as UTF-8 text.
 */
typedef enum ageswift_format {
    AGESWIFT_FORMAT_BINARY = 0,
    AGESWIFT_FORMAT_ASCII_ARMOR = 1
} ageswift_format;

/*
 * Encrypt `plaintext` for one or more age recipients.
 * `recipients` points to an array of NUL-terminated UTF-8 strings;
 * `recipients_len` must be >= 1. On success sets *ciphertext_out to the
 * age v1 file in the requested format.
 */
ageswift_status ageswift_encrypt_to_recipients(
    const uint8_t *plaintext, uintptr_t plaintext_len,
    const char *const *recipients, uintptr_t recipients_len,
    ageswift_format format,
    ageswift_bytes *ciphertext_out, char **error_out);

/*
 * Encrypt `plaintext` with a passphrase using age's standard scrypt
 * recipient and its default (~1 second) work factor, in the requested
 * output format.
 */
ageswift_status ageswift_encrypt_with_passphrase(
    const uint8_t *plaintext, uintptr_t plaintext_len,
    const char *passphrase,
    ageswift_format format,
    ageswift_bytes *ciphertext_out, char **error_out);

/*
 * Decrypt an age file with one or more secret identities.
 * `identities` points to an array of NUL-terminated UTF-8 strings;
 * `identities_len` must be >= 1. Fails with AGESWIFT_ERR_NO_MATCHING_KEY if
 * none of the identities matches.
 */
ageswift_status ageswift_decrypt_with_identities(
    const uint8_t *ciphertext, uintptr_t ciphertext_len,
    const char *const *identities, uintptr_t identities_len,
    ageswift_bytes *plaintext_out, char **error_out);

/*
 * Decrypt a passphrase-protected (scrypt) age file.
 * Fails with AGESWIFT_ERR_NO_MATCHING_KEY on a wrong passphrase.
 */
ageswift_status ageswift_decrypt_with_passphrase(
    const uint8_t *ciphertext, uintptr_t ciphertext_len,
    const char *passphrase,
    ageswift_bytes *plaintext_out, char **error_out);

/*
 * Wrap a binary age file in the age ASCII armor format. The input is
 * structurally validated first (header parse; no keys are needed), so
 * non-age input fails with AGESWIFT_ERR_INVALID_FORMAT. On success sets
 * *armored_out to the armored ASCII text; free it with
 * ageswift_free_string.
 */
ageswift_status ageswift_armor(const uint8_t *binary, uintptr_t binary_len,
                               char **armored_out, char **error_out);

/*
 * Decode an age ASCII armor file back to the binary format. Whitespace
 * around the armored block is tolerated; input that is not armored, or
 * armor that is malformed (invalid base64, missing END marker, ...), fails
 * with AGESWIFT_ERR_INVALID_FORMAT. The decoded output is structurally
 * validated to be an age file before it is returned.
 */
ageswift_status ageswift_dearmor(const char *armored,
                                 ageswift_bytes *binary_out, char **error_out);

/* Release a buffer returned in an `ageswift_bytes` out-param. NULL-safe:
 * ptr==NULL implies len==capacity==0 and the call is a no-op. */
void ageswift_free_bytes(ageswift_bytes buffer);

/* Release a string returned in a `char **` out-param. NULL-safe. */
void ageswift_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* AGE_SWIFT_FFI_H */
