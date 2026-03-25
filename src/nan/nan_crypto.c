/*
 * Wi-Fi Aware - NAN Data link cryptography functions
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "utils/common.h"
#include "common/ieee802_11_common.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"
#include "crypto/crypto.h"
#include "nan_i.h"

#define NAN_KCK_MAX_LEN 24
#define NAN_KEK_MAX_LEN 32
#define NAN_TK_MAX_LEN  32

#define NAN_PTK_LABEL       "NAN Pairwise key expansion"
#define NAN_PMKID_LABEL     "NAN PMK Name"

/* NAN ciphers use only SHA-256 and SHA-384, and SHA-384 has a bigger digest */
#define MAX_MAC_LEN SHA384_MAC_LEN


static size_t nan_crypto_cipher_kck_len(enum nan_cipher_suite_id cipher)
{
	switch (cipher) {
	case NAN_CS_SK_CCM_128:
		return 16;
	case NAN_CS_SK_GCM_256:
		return 24;
	default:
		return 0;
	}
}


static size_t nan_crypto_cipher_kek_len(enum nan_cipher_suite_id cipher)
{
	switch (cipher) {
	case NAN_CS_SK_CCM_128:
		return 16;
	case NAN_CS_SK_GCM_256:
		return 32;
	default:
		return 0;
	}
}


static size_t nan_cipher_key_len(enum nan_cipher_suite_id cipher)
{
	switch (cipher) {
	case NAN_CS_SK_CCM_128:
		return 16;
	case NAN_CS_SK_GCM_256:
		return 32;
	default:
		return 0;
	}
}


static int nan_crypto_sha256(const u8 *plaintext, size_t psize, u8 *output)
{
	const u8 *addrs[1];
	size_t lens[1];

	addrs[0] = plaintext;
	lens[0] = psize;

	return sha256_vector(1, addrs, lens, output);
}


static int nan_crypto_sha384(const u8 *plaintext, size_t psize, u8 *output)
{
	const u8 *addrs[1];
	size_t lens[1];

	addrs[0] = plaintext;
	lens[0] = psize;

	return sha384_vector(1, addrs,  lens, output);
}


/**
 * nan_crypto_pmk_to_ptk - Calculate PTK from PMK, addresses, and nonces
 * @pmk: Pairwise master key
 * @iaddr: Initiator address
 * @raddr: Remote address
 * @inonce: Initiator nonce
 * @rnonce: Remote nonce
 * @ptk: Buffer for Pairwise Transient Key
 * @cipher: Negotiated pairwise cipher
 * returns: 0 on success, negative value of failure
 */
int nan_crypto_pmk_to_ptk(const u8 *pmk, const u8 *iaddr, const u8 *raddr,
			  const u8 *inonce, const u8 *rnonce,
			  struct nan_ptk *ptk,
			  enum nan_cipher_suite_id cipher)
{
	u8 data[2 * ETH_ALEN + 2 * WPA_NONCE_LEN];
	u8 tmp[NAN_KCK_MAX_LEN + NAN_KEK_MAX_LEN + NAN_TK_MAX_LEN];
	size_t ptk_len;
	int ret;

	if (cipher != NAN_CS_SK_CCM_128 && cipher != NAN_CS_SK_GCM_256)
		return -1;

	if (!ptk)
		return -1;

	os_memcpy(data, iaddr, ETH_ALEN);
	os_memcpy(data + ETH_ALEN, raddr, ETH_ALEN);
	os_memcpy(data + 2 * ETH_ALEN, inonce, WPA_NONCE_LEN);
	os_memcpy(data + 2 * ETH_ALEN + WPA_NONCE_LEN, rnonce,
		  WPA_NONCE_LEN);

	ptk->kck_len = nan_crypto_cipher_kck_len(cipher);
	ptk->kek_len = nan_crypto_cipher_kek_len(cipher);
	ptk->tk_len = nan_cipher_key_len(cipher);
	ptk_len = ptk->kck_len + ptk->kek_len + ptk->tk_len;

	if (cipher == NAN_CS_SK_CCM_128)
		ret = sha256_prf(pmk, PMK_LEN, NAN_PTK_LABEL, data,
				 sizeof(data), tmp, ptk_len);
	else
		ret = sha384_prf(pmk, PMK_LEN, NAN_PTK_LABEL, data,
				 sizeof(data), tmp, ptk_len);
	if (ret)
		goto out;

	wpa_hexdump_key(MSG_DEBUG, "NAN: PMK", pmk, PMK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: iaddr", iaddr, ETH_ALEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: raddr", raddr, ETH_ALEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: inonce", inonce, WPA_NONCE_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: rnonce", rnonce, WPA_NONCE_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: PTK", tmp, ptk_len);

	os_memcpy(ptk->kck, tmp, ptk->kck_len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: KCK", ptk->kck, ptk->kck_len);

	os_memcpy(ptk->kek, tmp + ptk->kck_len, ptk->kek_len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: KEK", ptk->kek, ptk->kek_len);

	os_memcpy(ptk->tk, tmp + ptk->kck_len + ptk->kek_len, ptk->tk_len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: TK", ptk->tk, ptk->tk_len);

out:
	forced_memzero(data, sizeof(data));
	forced_memzero(tmp, sizeof(tmp));
	return ret;
}


/*
 * nan_crypto_calc_pmkid - Calculate a NAN PMKID
 * @pmk: Pairwise Master Key
 * @iaddr: Initiator address
 * @raddr: Remote address
 * @serv_id: ID of the service providing the PMK
 * @cipher: Negotiated pairwise cipher
 * @pmkid: Buffer to hold the pmkid
 * Returns: 0 on success, negative value of failure
 */
int nan_crypto_calc_pmkid(const u8 *pmk, const u8 *iaddr, const u8 *raddr,
			  const u8 *serv_id,
			  enum nan_cipher_suite_id cipher, u8 *pmkid)
{
	u8 data[sizeof(NAN_PMKID_LABEL) - 1 + 2 * ETH_ALEN +
		NAN_SERVICE_ID_LEN];
	u8 digest[MAX_MAC_LEN];
	int ret;

	os_memset(data, 0, sizeof(data));
	os_memset(digest, 0, sizeof(digest));

	if (cipher != NAN_CS_SK_CCM_128 && cipher != NAN_CS_SK_GCM_256)
		return -1;

	if (!serv_id || is_zero_ether_addr(serv_id))
		return -1;

	os_memcpy(data, NAN_PMKID_LABEL, sizeof(NAN_PMKID_LABEL) - 1);
	os_memcpy(data + sizeof(NAN_PMKID_LABEL) - 1, iaddr, ETH_ALEN);
	os_memcpy(data + sizeof(NAN_PMKID_LABEL) - 1 + ETH_ALEN, raddr,
		  ETH_ALEN);
	os_memcpy(data + sizeof(NAN_PMKID_LABEL) - 1 + 2 * ETH_ALEN, serv_id,
		  NAN_SERVICE_ID_LEN);

	wpa_hexdump_key(MSG_DEBUG, "NAN: PMKID data", data, sizeof(data));

	if (cipher == NAN_CS_SK_CCM_128)
		ret = hmac_sha256(pmk, PMK_LEN, data, sizeof(data), digest);
	else
		ret = hmac_sha384(pmk, PMK_LEN, data, sizeof(data), digest);
	if (ret)
		goto out;

	os_memcpy(pmkid, digest, PMKID_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: PMKID", pmkid, PMKID_LEN);

out:
	forced_memzero(digest, sizeof(digest));
	return ret;
}


/**
 * nan_crypto_calc_auth_token - Calculate authentication token
 * @buf: Buffer on which to calculate the authentication token
 * @len: Length of &buf in octets
 * @cipher: Negotiated NAN cipher
 * @token: Buffer to hold the token (NAN_AUTH_TOKEN_LEN octets)
 * Returns: 0 on success, and a negative error value on failure.
 */
int nan_crypto_calc_auth_token(enum nan_cipher_suite_id cipher,
			       const u8 *buf, size_t len, u8 *token)
{
	u8 hash[MAX_MAC_LEN];
	int ret;

	if (cipher != NAN_CS_SK_CCM_128 && cipher != NAN_CS_SK_GCM_256)
		return -1;

	if (cipher == NAN_CS_SK_CCM_128)
		ret = nan_crypto_sha256(buf, len, hash);
	else
		ret = nan_crypto_sha384(buf, len, hash);
	if (ret)
		return ret;

	os_memcpy(token, hash, NAN_AUTH_TOKEN_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: AUTH_TOKEN_DATA", buf, len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: AUTH TOKEN", token,
			NAN_AUTH_TOKEN_LEN);

	forced_memzero(hash, sizeof(hash));

	return ret;
}


/*
 * nan_crypto_key_mic - Calculate MIC over the given buffer
 * @buf: Buffer on which to calculate the MIC
 * @len: Length of &buf
 * @kck: Key Confirmation Key
 * @kck_len: Length of &kck
 * @cipher: Cipher suite identifier.
 * @mic: On successful return, would hold the MIC.
 * Return: 0 on success, and a negative error value on failure.
 */
int nan_crypto_key_mic(const u8 *buf, size_t len, const u8 *kck,
		       size_t kck_len, u8 cipher, u8 *mic)
{
	u8 digest[MAX_MAC_LEN];
	u8 mic_len;
	int ret;

	os_memset(digest, 0, sizeof(digest));

	if (cipher != NAN_CS_SK_CCM_128 && cipher != NAN_CS_SK_GCM_256)
		return -1;

	wpa_hexdump_key(MSG_DEBUG, "NAN: MIC data", buf, len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: KCK", kck, kck_len);

	if (cipher == NAN_CS_SK_CCM_128) {
		mic_len = NAN_KEY_MIC_LEN;
		ret = hmac_sha256(kck, kck_len, buf, len, digest);
	} else {
		mic_len = NAN_KEY_MIC_24_LEN;
		ret = hmac_sha384(kck, kck_len, buf, len, digest);
	}
	if (ret)
		return ret;

	os_memcpy(mic, digest, mic_len);
	forced_memzero(digest, sizeof(digest));

	wpa_hexdump_key(MSG_DEBUG, "NAN: MIC", mic, mic_len);
	return 0;
}
