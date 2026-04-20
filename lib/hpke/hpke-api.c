/*
 * Copyright © 2026 David Dudas
 *
 * Author: David Dudas <david.dudas03@e-uvt.ro>
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/* When ENABLE_HPKE, the actual implementation is provided in
 * lib/hpke/hpke.c. Rename the symbols to avoid clash.
 */
#ifdef ENABLE_HPKE
#define gnutls_hpke_init _gnutls_hpke_init
#define gnutls_hpke_deinit _gnutls_hpke_deinit
#define gnutls_hpke_encap _gnutls_hpke_encap
#define gnutls_hpke_seal _gnutls_hpke_seal
#define gnutls_hpke_decap _gnutls_hpke_decap
#define gnutls_hpke_open _gnutls_hpke_open
#define gnutls_hpke_derive_keypair _gnutls_hpke_derive_keypair
#define gnutls_hpke_export _gnutls_hpke_export
#endif

#include <gnutls/hpke.h>
#include "gnutls_int.h"

/**
 * gnutls_hpke_init:
 * @ctx: A pointer to the HPKE context to initialize.
 * @mode: The HPKE mode to use (Base, PSK, Auth, or AuthPSK).
 * @role: The role of the context (Sender or Receiver).
 * @kem: The KEM algorithm to use (e.g., DHKEM(X25519)).
 * @kdf: The KDF algorithm to use (e.g., HKDF-SHA256).
 * @aead: The AEAD algorithm to use (e.g., AES-128-GCM).
 *
 * This function initializes the HPKE context with the specified parameters.
 * It allocates memory for the context and sets the initial values for the fields based on the provided parameters.
 *
 * The context must be deinitialized using gnutls_hpke_deinit() when it
 * is no longer needed to free any allocated resources and securely erase sensitive information.
 *
 * Returns: 0 on success, or a negative error code on failure
 * Since: 3.8.13
 */
int gnutls_hpke_init(gnutls_hpke_context_t *ctx, gnutls_hpke_mode_t mode,
		     gnutls_hpke_role_t role, gnutls_hpke_kem_t kem,
		     gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead)
{
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

/**
 * gnutls_hpke_deinit:
 * @ctx: The HPKE context to deinitialize.
 *
 * This function deinitializes the HPKE context and securely erases any
 * sensitive information contained within it, such as keys and secrets.
 * It is important to call this function when the HPKE context is no longer needed
 * to prevent sensitive data from lingering in memory.
 *
 * Returns: 0 on success, or a negative error code on failure.
 * Since: 3.8.13
 */
int gnutls_hpke_deinit(gnutls_hpke_context_t ctx)
{
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

/**
 * gnutls_hpke_encap:
 * @ctx: The HPKE context to use for encapsulation.
 * @info: The application-specific information to be included in the key schedule (optional).
 * @enc: A pointer to a gnutls_datum_t structure where the encapsulated key will be stored.
 * @receiver_pubkey: The receiver's public key to use for encapsulation.
 * @sender_privkey: The sender's private key needed for AuthEncap operation (optional).
 * @psk: The pre-shared key (optional).
 * @psk_id: The pre-shared key identifier (optional).
 *
 * This function performs the encapsulation operation of HPKE. It
 * generates an encapsulated key (@enc) that can be sent to the
 * receiver, who can then use it to derive the shared secret.
 *
 * The function checks that the context is properly initialized and
 * that the provided parameters are valid. It also checks that the
 * context is in the correct role (%GNUTLS_HPKE_ROLE_SENDER) for
 * encapsulation.
 *
 * This function must be used once per HPKE context and before any
 * calls to gnutls_hpke_seal().
 *
 * The function will allocate memory for @enc, and the caller is
 * responsible for freeing this memory using gnutls_free() when it is
 * no longer needed.
 *
 * @receiver_pubkey must be a valid public key that is compatible with
 * the KEM algorithm specified in the HPKE context.
 *
 * For %GNUTLS_HPKE_MODE_AUTH or %GNUTLS_HPKE_MODE_AUTH_PSK,
 * @sender_privkey must be a valid private key that can be used for
 * authentication. For %GNUTLS_HPKE_MODE_PSK or
 * %GNUTLS_HPKE_MODE_AUTH_PSK, a pre-shared key (@psk) and its
 * identifier (@psk_id) must be supplied.
 *
 * Returns: 0 on success, or a negative error code on failure
 * Since: 3.8.13
 */
int gnutls_hpke_encap(gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
		      gnutls_datum_t *enc,
		      const gnutls_pubkey_t receiver_pubkey,
		      const gnutls_privkey_t sender_privkey,
		      const gnutls_datum_t *psk, const gnutls_datum_t *psk_id)
{
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

/**
 * gnutls_hpke_seal:
 * @ctx: The HPKE context to use for sealing.
 * @aad: The associated data (AAD) to be authenticated but not encrypted.
 * @plaintext: The plaintext data to be encrypted and authenticated.
 * @ciphertext: A pointer to a gnutls_datum_t structure where the resulting ciphertext will be stored.
 *
 * This function performs the sealing operation of HPKE. It encrypts
 * the plaintext and computes an authentication tag using the AEAD
 * algorithm specified in the HPKE context. The resulting ciphertext
 * includes both the encrypted plaintext and the authentication tag.
 *
 * This function can be used multiple times with the same HPKE
 * context, but the encapsulation function (gnutls_hpke_encap()) must
 * be called once before the first call to this function to set up the
 * necessary keys and nonces in the context. Each call to this
 * function will increment the sequence number in the context, which
 * is used to derive unique nonces for each encryption operation.
 *
 * The function will allocate memory for the @ciphertext, and the
 * caller is responsible for freeing this memory using gnutls_free()
 * when it is no longer needed.
 *
 * Returns: 0 on success, or a negative error code on failure
 * Since: 3.8.13
 */
int gnutls_hpke_seal(gnutls_hpke_context_t ctx, const gnutls_datum_t *aad,
		     const gnutls_datum_t *plaintext,
		     gnutls_datum_t *ciphertext)
{
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

/**
 * gnutls_hpke_decap:
 * @ctx: The HPKE context to use for decapsulation.
 * @info: The application-specific information that was included in the key schedule (optional).
 * @enc: A pointer to a gnutls_datum_t structure containing the encapsulated key received from the sender.
 * @receiver_privkey: The receiver's private key to use for decapsulation.
 * @sender_pubkey: The sender's public key for AuthDecap operation (optional).
 * @psk: The pre-shared key (optional).
 * @psk_id: The pre-shared key identifier (optional).
 *
 * This function performs the decapsulation operation of HPKE. It
 * takes the encapsulated key (@enc) received from the sender and uses
 * it along with the receiver's private key to derive the shared
 * secret. It then uses this shared secret along with any provided
 * application-specific information (@info) to set up the necessary
 * keys and nonces in the HPKE context for subsequent sealing and
 * opening operations.
 *
 * This function must be used once per HPKE context and before any
 * calls to gnutls_hpke_open().
 *
 * @enc should be the same encapsulated key that was generated by
 * gnutls_hpke_encap() on the sender's side.
 *
 * @receiver_privkey must be a valid private key that is compatible
 * with the KEM algorithm specified in the HPKE context and that
 * corresponds to the receiver's public key used during encapsulation.
 *
 * For %GNUTLS_HPKE_MODE_AUTH or %GNUTLS_HPKE_MODE_AUTH_PSK,
 * @sender_pubkey must be a valid public key that can be used for
 * authentication. For %GNUTLS_HPKE_MODE_PSK or
 * %GNUTLS_HPKE_MODE_AUTH_PSK, a pre-shared key (@psk) and its
 * identifier (@psk_id) must be supplied.
 *
 * Returns: 0 on success, or a negative error code on failure
 * Since: 3.8.13
 */
int gnutls_hpke_decap(gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
		      const gnutls_datum_t *enc,
		      const gnutls_privkey_t receiver_privkey,
		      const gnutls_pubkey_t sender_pubkey,
		      const gnutls_datum_t *psk, const gnutls_datum_t *psk_id)
{
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

/**
 * gnutls_hpke_open:
 * @ctx: The HPKE context to use for opening.
 * @aad: The associated data (AAD) that was authenticated during sealing.
 * @ciphertext: The ciphertext received from the sender.
 * @plaintext: A pointer to a gnutls_datum_t structure where the resulting plaintext will be stored.
 *
 * This function performs the opening operation of HPKE. It takes the
 * ciphertext received from the sender and uses the keys and nonces
 * set up in the HPKE context (after decapsulation) to decrypt the
 * ciphertext and verify the authentication tag. If the decryption and
 * authentication are successful, the resulting plaintext is stored in
 * @plaintext. If the decryption or authentication fails, the function
 * securely erases any allocated plaintext and returns an error code.
 *
 * This function can be used multiple times with the same HPKE
 * context, but the decapsulation function (gnutls_hpke_decap()) must
 * be called once before the first call to this function.
 *
 * @aad should be the same AAD that was provided to gnutls_hpke_seal()
 * on the sender's side.
 *
 * @ciphertext should be the same ciphertext that was generated by
 * gnutls_hpke_seal() on the sender's side.
 *
 * The function will allocate memory for the @plaintext, and the
 * caller is responsible for freeing this memory using gnutls_free()
 * when it is no longer needed.
 *
 * Returns: 0 on success, or a negative error code on failure
 * Since: 3.8.13
 */
int gnutls_hpke_open(gnutls_hpke_context_t ctx, const gnutls_datum_t *aad,
		     const gnutls_datum_t *ciphertext,
		     gnutls_datum_t *plaintext)
{
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

/**
 * gnutls_hpke_derive_keypair:
 * @kem: The KEM algorithm to use for key pair generation.
 * @ikm: A pointer to a gnutls_datum_t structure containing the input key material (IKM) to be used for key pair
 * generation.
 * @privkey: An initialized private key.
 * @pubkey: An initialized public key.
 *
 * This function derives a key pair (private key and public key) for
 * the specified KEM algorithm from the provided input key material
 * (@ikm).
 *
 * @ikm is used as a seed for the key generation process, allowing for
 * deterministic key pair generation if the same IKM is used. The
 * function checks that the provided parameters are valid and that the
 * KEM algorithm is supported.
 *
 * @ikm should be a non-empty byte string that serves as the seed for
 * key pair generation.
 *
 * Returns: 0 on success, or a negative error code on failure
 * Since: 3.8.13
 */
int gnutls_hpke_derive_keypair(gnutls_hpke_kem_t kem, const gnutls_datum_t *ikm,
			       gnutls_privkey_t privkey, gnutls_pubkey_t pubkey)
{
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

/**
 * gnutls_hpke_export:
 * @ctx: The HPKE context to use for exporting the secret.
 * @exporter_context: The application-specific context to be included in the export.
 * @length: The requested length in bytes of the secret to be exported.
 * @secret: A pointer to a gnutls_datum_t structure where the exported secret will be stored.
 *
 * This function performs the export operation of HPKE. It derives a
 * secret of @length bytes from the exporter secret in the HPKE
 * context, using the provided application-specific context and the
 * KDF specified in the context. The resulting secret is stored in
 * @secret. The function checks that the provided parameters are valid
 * and that the context is properly initialized and that there is an
 * exporter secret available in the context.
 *
 * @length should be a positive integer that does not exceed the
 * maximum allowed size for HPKE exports.
 *
 * The function will allocate memory for @secret, and the caller is
 * responsible for freeing this memory using gnutls_free() when it is
 * no longer needed.
 *
 * Returns: 0 on success, or a negative error code on failure
 * Since: 3.8.13
 */
int gnutls_hpke_export(gnutls_hpke_context_t ctx,
		       const gnutls_datum_t *exporter_context, size_t length,
		       gnutls_datum_t *secret)

{
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}
