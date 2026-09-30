/*
 * Wi-Fi Aware - NAN pairing module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/nan_de.h"
#include "pasn/pasn_common.h"
#include "nan/nan_i.h"

static void nan_pairing_prepare_pasn_elems(struct nan_data *nan_data,
					   struct nan_peer *peer,
					   struct wpabuf *extra_ies,
					   int publish_id, int auth_mode);
static int nan_pairing_pasn_initialize(struct nan_data *nan_data,
				       struct nan_peer *peer, u8 auth_mode,
				       int cipher, const char *password,
				       enum nan_pairing_role self_role);
static int nan_pairing_prepare_data_element(void *ctx, const u8 *peer_addr);
static int nan_pairing_parse_data_element(void *ctx, const u8 *data,
					  size_t len);

/**
 * nan_nira_get_tag_nonce - Generate NIRA nonce and compute NIRA tag
 * @nan: Pointer to NAN configuration structure
 * @nonce: Buffer to store the generated NIRA nonce (output)
 * @tag: Buffer to store the computed NIRA tag (output)
 * Returns: 0 on success, -1 on failure
 *
 * This function generates a random NIRA (NAN Identity Resolution Attribute)
 * nonce and derives the corresponding NIRA tag using the NIK (NAN Identity
 * Key), NMI address, and the generated nonce.
 *
 * The caller must ensure that nonce buffer is at least NAN_NIRA_NONCE_LEN bytes
 * and tag buffer is at least NAN_NIRA_TAG_LEN bytes.
 */
int nan_nira_get_tag_nonce(const struct nan_config *nan, u8 *nonce, u8 *tag)
{
	struct wpabuf *tag_buf;

	if (os_get_random(nonce, NAN_NIRA_NONCE_LEN) < 0) {
		wpa_printf(MSG_INFO, "NAN: Failed to generate NIRA nonce");
		return -1;
	}

	tag_buf = nan_crypto_derive_nira_tag(nan->nik, NAN_NIK_LEN,
					     nan->nmi_addr, nonce);
	if (!tag_buf)
		return -1;

	os_memcpy(tag, wpabuf_head(tag_buf), NAN_NIRA_TAG_LEN);
	wpabuf_free(tag_buf);

	wpa_hexdump_key(MSG_DEBUG, "NAN: NIK", nan->nik, NAN_NIK_LEN);
	wpa_hexdump(MSG_DEBUG, "NAN: NIRA-NONCE", nonce, NAN_NIRA_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "NAN: NIRA-TAG", tag, NAN_NIRA_TAG_LEN);
	return 0;
}


/**
 * nan_pairing_add_attrs - Add NAN pairing attributes to a buffer
 * @nan: Pointer to NAN data structure containing configuration
 * @buf: Pointer to wpabuf where attributes will be added
 * Returns: 0 on success, -1 otherwise
 *
 * This function adds NAN attributes that indicate pairing capabilities
 * to the provided buffer.
 */
int nan_pairing_add_attrs(struct nan_data *nan, struct wpabuf *buf)
{
	if (!nan || !buf)
		return -1;

	nan_add_dev_capa_ext_attr(nan, buf);

	if (nan->cfg->pairing_cfg.pairing_verification) {
		if (nan_add_nira(buf, nan->nira_tag, nan->nira_nonce)) {
			wpa_printf(MSG_INFO, "NAN: Failed to add NIRA");
			return -1;
		}
	}

	return 0;
}


void nan_pairing_deinit_peer(struct nan_data *nan_data, struct nan_peer *peer,
			     bool remove_nm_tk)
{
	wpabuf_free(peer->pairing.pending_auth1);
	peer->pairing.pending_auth1 = NULL;

	os_free(peer->pairing.psi_locale);
	peer->pairing.psi_locale = NULL;
	os_free(peer->pairing.psi_vendor_name);
	peer->pairing.psi_vendor_name = NULL;
	os_free(peer->pairing.psi_model_name);
	peer->pairing.psi_model_name = NULL;
	os_free(peer->pairing.psi_pairing_name);
	peer->pairing.psi_pairing_name = NULL;

	/* Remove the NM-TK from the driver only when the pairing did not
	 * complete successfully. On the success path the key must remain
	 * installed so that subsequent NAN Management frames are protected.
	 * Callers that tear down a failed or aborted session pass true;
	 * callers that clean up after a successful NIK exchange pass false.
	 */
	if (remove_nm_tk && peer->pairing.nm_tk_installed && nan_data &&
	    nan_data->cfg->install_nm_tk)
		nan_data->cfg->install_nm_tk(nan_data->cfg->cb_ctx,
					     peer->nmi_addr, 0, NULL, 0);
	if (remove_nm_tk)
		peer->pairing.nm_tk_installed = false;

	if (!peer->pairing.pasn)
		return;

	wpa_pasn_reset(peer->pairing.pasn);
	pasn_data_deinit(peer->pairing.pasn);
	peer->pairing.pasn = NULL;
	peer->pairing.self_pairing_role = NAN_PAIRING_ROLE_IDLE;
}


int nan_pairing_abort(struct nan_data *nan_data, const u8 *peer_addr)
{
	struct nan_peer *peer;
	int cipher;
	struct wpabuf *extra_ies;
	int ret = -1;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing abort: Peer " MACSTR " not found",
			   MAC2STR(peer_addr));
		return -1;
	}

	if (!peer->pairing.pasn && !peer->pairing.pending_auth1) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing abort: No PASN in progress with peer "
			   MACSTR, MAC2STR(peer_addr));
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NAN: Aborting pairing with peer " MACSTR,
		   MAC2STR(peer_addr));

	if (!peer->pairing.pending_auth1) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing abort: No pending Auth1 frame for peer "
			   MACSTR, MAC2STR(peer_addr));
		ret = 0;
		goto done;
	}

	/* The auth mode and cipher are not important when rejecting.
	 * Just make sure to use a supported cipher so
	 * nan_pairing_pasn_initialize() won't fail.
	 */
	cipher = (nan_data->cfg->pairing_cfg.cipher_suites &
		  NAN_PAIRING_PASN_128) ? WPA_CIPHER_CCMP : WPA_CIPHER_GCMP_256;

	if (nan_pairing_pasn_initialize(nan_data, peer, NAN_PASN_AUTH_MODE_PASN,
					cipher, "",
					NAN_PAIRING_ROLE_RESPONDER)) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Initialize failed");
		goto done;
	}

	extra_ies = wpabuf_alloc(NAN_ELEMENT_MAX_SIZE);
	if (!extra_ies) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Failed to allocate buffer for extra elements");
		goto done;
	}

	nan_pairing_prepare_pasn_elems(nan_data, peer, extra_ies,
				       peer->pairing.handle,
				       NAN_PASN_AUTH_MODE_PASN);
	pasn_set_extra_ies(peer->pairing.pasn, wpabuf_head_u8(extra_ies),
			   wpabuf_len(extra_ies));
	wpabuf_free(extra_ies);

	nan_configure_peer_schedule(nan_data, peer, &nan_data->sched);

	ret = handle_auth_pasn_resp(peer->pairing.pasn, nan_data->cfg->nmi_addr,
				    peer_addr, NULL,
				    WLAN_STATUS_UNSPECIFIED_FAILURE);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing abort: Failed to send response");
		nan_clear_peer_schedule(nan_data, peer);
	}

done:
	nan_pairing_deinit_peer(nan_data, peer, true);
	return ret;
}


static bool nan_pairing_is_supported(struct nan_data *nan_data,
				     struct nan_peer *peer, u8 auth_mode)
{
	if (auth_mode == NAN_PASN_AUTH_MODE_PASN ||
	    auth_mode == NAN_PASN_AUTH_MODE_SAE) {
		if (!nan_data->cfg->pairing_cfg.pairing_setup) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Device doesn't support pairing setup");
			return false;
		}

		if (!peer->pairing.pairing_cfg.pairing_setup) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Peer doesn't support pairing setup");
			return false;
		}
	} else if (auth_mode == NAN_PASN_AUTH_MODE_PMK) {
		if (!nan_data->cfg->pairing_cfg.pairing_verification) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Device doesn't support pairing verification");
			return false;
		}

		if (!peer->pairing.pairing_cfg.pairing_verification) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Peer doesn't support pairing verification");
			return false;
		}

		if (!nan_data->cfg->get_npk_akmp) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: get_npk_akmp callback not set");
			return false;
		}
	}

	return true;
}


static int nan_pairing_set_password(struct pasn_data *pasn,
				    const char *passphrase)
{
#ifdef CONFIG_SAE
	struct sae_pt *pt;

	pt = sae_derive_pt(pasn->pasn_groups, (const u8 *) NAN_PASN_SSID,
			   os_strlen(NAN_PASN_SSID), (const u8 *) passphrase,
			   os_strlen(passphrase), NULL, 0);
	if (pasn_set_pt(pasn, pt) < 0) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Failed to set SAE pt");
		sae_deinit_pt(pt);
		return -1;
	}

	return 0;
#else  /* CONFIG_SAE */
	return -1;
#endif /* CONFIG_SAE */
}


static struct wpabuf * nan_pairing_generate_rsnxe(int akmp, bool non_cluster)
{
	/*
	 * RSNXE capabilities field layout:
	 *   bits 0-3  : Field length (n - 1), where n = number of capability
	 *               octets following the field-length nibble.
	 *   bit  5    : SAE-H2E (WLAN_RSNX_CAPAB_SAE_H2E = 5)
	 *   bit  18   : KEK in PASN (WLAN_RSNX_CAPAB_KEK_IN_PASN = 18)
	 *
	 * For clustered pairing: 2-byte capabilities field (n=2, field_len=1)
	 *   -> IE total = 2 (header) + 2 (capab) = 4 bytes
	 *
	 * For non-cluster pairing: bit 18 requires 3-byte capabilities field
	 *   (n=3, field_len=2) -> IE total = 2 (header) + 3 (capab) = 5 bytes
	 */
	u32 capab;
	size_t capab_len;
	struct wpabuf *buf;

	if (non_cluster) {
		/* KEK_IN_PASN is bit 18 and needs 3 capability bytes
		 * (bits 0-23).
		 * Field length nibble = n - 1 = 3 - 1 = 2.
		 */
		capab_len = 3;
		capab = 2; /* field_length = 2 (n-1 for n=3 bytes) */
	} else {
		capab_len = 2;
		capab = 1; /* field_length = 1 (n-1 for n=2 bytes) */
	}

	if (wpa_key_mgmt_sae(akmp))
		capab |= BIT(WLAN_RSNX_CAPAB_SAE_H2E);

	if (non_cluster)
		capab |= BIT(WLAN_RSNX_CAPAB_KEK_IN_PASN);

	/* Element header (2 octets) + capabilities field (capab_len octets) */
	buf = wpabuf_alloc(2 + capab_len);
	if (!buf)
		return NULL;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: RSNXE capab=0x%06x", capab);

	wpabuf_put_u8(buf, WLAN_EID_RSNX);
	wpabuf_put_u8(buf, capab_len);
	/* Write capabilities little-endian, capab_len bytes */
	wpabuf_put_u8(buf, capab & 0xff);
	wpabuf_put_u8(buf, (capab >> 8) & 0xff);
	if (capab_len == 3)
		wpabuf_put_u8(buf, (capab >> 16) & 0xff);
	return buf;
}


static int nan_pairing_send_cb(void *ctx, const u8 *data, size_t data_len,
			       int noack, unsigned int freq, unsigned int wait)
{
	struct nan_data *nan_data = (struct nan_data *) ctx;

	return nan_data->cfg->send_pasn(nan_data->cfg->cb_ctx, data, data_len,
					freq);
}


/**
 * nan_pasn_verification_init - Initialize PASN data for pairing verification
 * @nan_data: Pointer to NAN data structure containing configuration
 * @peer: Pointer to the NAN peer structure
 * Returns: 0 on success, -1 on failure
 *
 * This function gets the NPK and AKMP for the given peer and sets it as the
 * PASN PMK and AKMP. It also generates the NIRA nonce and tag to be used as the
 * custom PMKID for the PASN verification process.
 */
static int nan_pasn_verification_init(struct nan_data *nan_data,
				      struct nan_peer *peer)
{
	struct nan_pairing_peer_data *pairing_data;
	const struct wpabuf *npk;
	int akmp;
	u8 npkid[NAN_NIRA_NONCE_LEN + NAN_NIRA_TAG_LEN];

	pairing_data = &peer->pairing;

	if (!pairing_data->nonce_tag_valid) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: NIK ID not available for verification");
		return -1;
	}

	npk = nan_data->cfg->get_npk_akmp(nan_data->cfg->cb_ctx, peer->nmi_addr,
					  pairing_data->nonce,
					  pairing_data->tag, &akmp);
	if (!npk) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to get NPK AKMP for verification");
		return -1;
	}

	pasn_set_akmp(pairing_data->pasn, akmp);

	if (pairing_data->self_pairing_role == NAN_PAIRING_ROLE_INITIATOR)
		pasn_initiator_pmksa_cache_add(nan_data->initiator_pmksa,
					       nan_data->cfg->nmi_addr,
					       peer->nmi_addr,
					       wpabuf_head_u8(npk),
					       wpabuf_len(npk), NULL, akmp);
	else
		pasn_responder_pmksa_cache_add(nan_data->responder_pmksa,
					       nan_data->cfg->nmi_addr,
					       peer->nmi_addr,
					       wpabuf_head_u8(npk),
					       wpabuf_len(npk), NULL, akmp);

	/*
	 * According to Wi-Fi Aware Specification v4.0, section 7.6.5, pairing
	 * verification uses NPKID constructed from NIRA nonce and tag. The same
	 * nonce and tag should be used in the NIRA added to PASN first and
	 * second frames.
	 */
	if (nan_nira_get_tag_nonce(nan_data->cfg, npkid,
				   &npkid[NAN_NIRA_NONCE_LEN]) < 0) {
		wpa_printf(MSG_DEBUG, "NAN: Failed to get NIRA tag and nonce");
		return -1;
	}

	pasn_set_custom_pmkid(pairing_data->pasn, npkid);

	os_memcpy(peer->pairing.npkid, npkid, PMKID_LEN);
	peer->pairing.npkid_valid = true;
	wpa_printf(MSG_DEBUG, "NAN: Pairing: Stored NPKID for " MACSTR,
		   MAC2STR(peer->nmi_addr));

	return 0;
}


static int nan_validate_custom_pmkid(void *ctx, const u8 *addr, const u8 *pmkid)
{
	/*
	 * In NAN pairing, custom PMKID is constructed from NIRA nonce and tag.
	 * Matching the tag to a known NIK is done during NIRA validation so
	 * here we just accept any PMKID.
	 */
	return 0;
}


static int nan_pairing_pasn_initialize(struct nan_data *nan_data,
				       struct nan_peer *peer, u8 auth_mode,
				       int cipher, const char *password,
				       enum nan_pairing_role self_role)
{
	struct wpabuf *rsnxe = NULL;
	struct pasn_data *pasn;
	struct nan_pairing_peer_data *pairing;

	pairing = &peer->pairing;
	if (pairing->pasn) {
		wpa_pasn_reset(pairing->pasn);
	} else {
		pairing->pasn = pasn_data_init();
		if (!pairing->pasn) {
			wpa_printf(MSG_INFO,
				   "NAN: Pairing: Failed to initialize PASN data");
			return -1;
		}
	}

	pasn = pairing->pasn;
	pasn_set_own_addr(pasn, nan_data->cfg->nmi_addr);
	pasn_set_peer_addr(pasn, peer->nmi_addr);
	/* For non-cluster (USD) devices the local cluster ID is zero; use
	 * the peer's cluster ID as BSSID so frame validation passes.
	 */
	if (is_zero_ether_addr(nan_data->cluster_id) &&
	    !is_zero_ether_addr(peer->peer_cluster_id))
		pasn_set_bssid(pasn, peer->peer_cluster_id);
	else
		pasn_set_bssid(pasn, nan_data->cluster_id);

	if (self_role == NAN_PAIRING_ROLE_INITIATOR)
		pasn->pmksa = nan_data->initiator_pmksa;
	else
		pasn->pmksa = nan_data->responder_pmksa;

	if (cipher == WPA_CIPHER_GCMP_256 &&
	    (nan_data->cfg->pairing_cfg.cipher_suites & NAN_PAIRING_PASN_256)) {
		pasn->group = 20;
		pasn->cipher = WPA_CIPHER_GCMP_256;
	} else if (cipher == WPA_CIPHER_CCMP &&
		   (nan_data->cfg->pairing_cfg.cipher_suites &
		    NAN_PAIRING_PASN_128)) {
		pasn->group = 19;
		pasn->cipher = WPA_CIPHER_CCMP;
	} else {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Unsupported cipher suite %s",
			   wpa_cipher_txt(cipher));
		goto fail;
	}

	pasn_enable_kdk_derivation(pasn);

	/* Set allowed PASN groups. This is needed for all modes */
	os_free(pasn->pasn_groups);
	pasn->pasn_groups = os_calloc(2, sizeof(*pasn->pasn_groups));
	if (!pasn->pasn_groups) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Failed to allocate PASN groups");
		goto fail;
	}
	pasn->pasn_groups[0] = pasn->group;

	if (auth_mode == NAN_PASN_AUTH_MODE_SAE) {
		pasn_set_akmp(pasn, WPA_KEY_MGMT_SAE);
		if (!password) {
			wpa_printf(MSG_INFO,
				   "NAN: Pairing: Password not available");
			goto fail;
		}

		if (nan_pairing_set_password(pasn, password) < 0) {
			wpa_printf(MSG_INFO,
				   "NAN: Pairing: Failed to set password");
			goto fail;
		}
	} else if (auth_mode == NAN_PASN_AUTH_MODE_PASN) {
		pasn_set_akmp(pasn, WPA_KEY_MGMT_PASN);
		pasn_set_noauth(pasn, true);
	} else if (auth_mode == NAN_PASN_AUTH_MODE_PMK) {
		if (nan_pasn_verification_init(nan_data, peer)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: PASN verification init failed");
			goto fail;
		}
	} else {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Unsupported authentication mode %u",
			   auth_mode);
		goto fail;
	}

	pasn_set_rsn_pairwise(pasn, pasn->cipher);
	pasn_set_wpa_key_mgmt(pasn, pasn->akmp);

	/* Enable KEK derivation when the peer is not in a NAN cluster so
	 * the NIK exchange can be encrypted in the PASN data element.
	 */
	if (peer->non_cluster || !nan_data->nan_started) {
		if (pasn->cipher == WPA_CIPHER_GCMP_256)
			pasn->kek_len = 32;
		else
			pasn->kek_len = 16;
		pasn->derive_kek = true;
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: KEK derivation enabled kek_len=%zu",
			   pasn->kek_len);
	}

	if (auth_mode != NAN_PASN_AUTH_MODE_PASN) {
		rsnxe = nan_pairing_generate_rsnxe(pasn->akmp,
						   peer->non_cluster ||
						   !nan_data->nan_started);
		if (!rsnxe) {
			wpa_printf(MSG_INFO,
				   "NAN: Pairing: Failed to generate RSNXE");
			goto fail;
		}

		pasn_set_rsnxe_ie(pairing->pasn, wpabuf_head_u8(rsnxe));
		wpabuf_free(rsnxe);
	}

	pasn_register_callbacks(pasn, nan_data, nan_pairing_send_cb,
				nan_validate_custom_pmkid, NULL, NULL);

	/* The prepare callback is also used for clustered responder pairing to
	 * install the NM-TK before M2 transmission.
	 */
	pasn->prepare_data_element = nan_pairing_prepare_data_element;

	/* Register encrypted data callbacks to embed and parse the NIK
	 * in PASN Authentication frames when the peer is not in a NAN cluster.
	 */
	if (nan_peer_no_shared_cluster(nan_data, peer->nmi_addr)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Registering encrypted data callbacks");
		pasn->parse_data_element = nan_pairing_parse_data_element;
	}

	return 0;

fail:
	pasn_data_deinit(pasn);
	pairing->pasn = NULL;
	return -1;
}


/*
 * nan_pairing_add_csia - Add the pairing Cipher Suite Information attribute
 * @nan_data: Pointer to NAN data structure
 * @peer: Pointer to NAN peer structure
 * @extra_ies: Buffer to which the CSIA is appended
 * @publish_id: Local service handle; used as the CSIA Publish ID for the
 *              responder and as a fallback for the initiator when
 *              peer_instance_id is not yet known
 *
 * The responder advertises the service's configured cipher suite list, while
 * the initiator indicates the selected NCS-PK-PASN cipher suite (the best
 * NCS-PK-PASN cipher suite supported by both peers, Wi-Fi Aware spec v4.0,
 * section 7.6.4). The CSIA Publish ID always identifies the peer's publish
 * service when acting as initiator.
 */
static void nan_pairing_add_csia(const struct nan_data *nan_data,
				 const struct nan_peer *peer,
				 struct wpabuf *extra_ies, int publish_id)
{
	struct nan_cipher_suite cs_list[NAN_CS_MAX];
	size_t cs_count = 0;
	const int *cs_ids = NULL;
	u8 csia_publish_id;

	if (peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER ||
	    peer->pairing.peer_instance_id <= 0)
		csia_publish_id = (u8) publish_id;
	else
		csia_publish_id = (u8) peer->pairing.peer_instance_id;

	/* The responder advertises the full service cipher suite list. */
	if (nan_data->cfg->get_cipher_suites_list && publish_id > 0 &&
	    peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER)
		cs_ids = nan_data->cfg->get_cipher_suites_list(
			nan_data->cfg->cb_ctx, publish_id);

	/* For the initiator, cs_ids is intentionally left NULL; the selected
	 * cipher suite is derived from the completed PASN handshake below.
	 */
	if (cs_ids) {
		size_t i;

		for (i = 0; cs_ids[i] && cs_count < NAN_CS_MAX; i++) {
			cs_list[cs_count].csid = (u8) cs_ids[i];
			cs_list[cs_count].instance_id = csia_publish_id;
			cs_count++;
		}
	}

	if (cs_count == 0) {
		/* For the pairing initiator, indicate the selected NCS-PK-PASN
		 * cipher suite - the best cipher suite supported by both peers
		 * (Wi-Fi Aware spec v4.0, section 7.6.4).
		 */
		cs_list[0].csid =
			(peer->pairing.pasn->cipher == WPA_CIPHER_GCMP_256) ?
			NAN_CS_PK_PASN_256 : NAN_CS_PK_PASN_128;
		cs_list[0].instance_id = csia_publish_id;
		cs_count = 1;
	}

	nan_add_csia(extra_ies, nan_data->cfg->security_capab,
		     cs_count, cs_list);
}


/*
 * nan_pairing_prepare_pasn_elems - Prepare NAN element for pairing PASN frames
 * @nan_data: Pointer to NAN data structure
 * @peer: Pointer to NAN peer structure
 * @extra_ies: Buffer to which the NAN element is appended
 * @publish_id: Publish ID to use in the CSIA
 * @auth_mode: Pairing authentication mode
 *
 * This function adds a NAN element containing the NAN attributes that shall be
 * included in the first and second PASN frames for NAN pairing.
 * The added attributes are:
 * - Device Capability Extension attribute (DCEA)
 * - Cipher Suite Information attribute (CSIA) with the service's configured
 *   cipher suite list (responder) or the selected NCS-PK-PASN cipher suite
 *   (initiator, Wi-Fi Aware spec v4.0, section 7.6.4)
 * - NAN Pairing Bootstrapping attribute (NPBA), if available
 * - Pairing Bootstrapping Extended attribute (PBEA), if available
 */
static void nan_pairing_prepare_pasn_elems(struct nan_data *nan_data,
					   struct nan_peer *peer,
					   struct wpabuf *extra_ies,
					   int publish_id, int auth_mode)
{
	u8 *len_ptr;
	size_t initial_len = wpabuf_len(extra_ies);

	wpabuf_put_u8(extra_ies, WLAN_EID_VENDOR_SPECIFIC);

	/* placeholder for length - to be filled later */
	len_ptr = wpabuf_put(extra_ies, 1);

	/* OUI + OUI Type */
	wpabuf_put_be32(extra_ies, NAN_IE_VENDOR_TYPE);

	nan_pairing_add_csia(nan_data, peer, extra_ies, publish_id);
	nan_add_dev_capa_ext_attr(nan_data, extra_ies);

	if (auth_mode == NAN_PASN_AUTH_MODE_SAE ||
	    auth_mode == NAN_PASN_AUTH_MODE_PASN) {
		if (peer->bootstrap.npba)
			wpabuf_put_buf(extra_ies, peer->bootstrap.npba);

		if (peer->bootstrap.extended_pbm ||
		    peer->bootstrap.pairing_setup_info) {
			u16 extended_pbm = 0;
			const u8 *pairing_setup_info = NULL;
			u16 pairing_setup_info_len = 0;
			struct wpabuf *pbea;

			if (nan_data->cfg->get_pbea_info)
				nan_data->cfg->get_pbea_info(
						nan_data->cfg->cb_ctx,
						publish_id, &extended_pbm,
						&pairing_setup_info,
						&pairing_setup_info_len);

			pbea = nan_build_pbea(extended_pbm, pairing_setup_info,
					      pairing_setup_info_len);
			if (pbea) {
				wpabuf_put_buf(extra_ies, pbea);
				wpabuf_free(pbea);
			}
		}
	} else {
		const u8 *npkid = peer->pairing.pasn->custom_pmkid;

		/*
		 * Add NIRA with the same nonce and tag as in the NPKID.
		 * NPKID is: NONCE || TAG.
		 */
		if (nan_add_nira(extra_ies, &npkid[NAN_NIRA_NONCE_LEN],
				 npkid)) {
			wpa_printf(MSG_DEBUG, "NAN: Failed to add NIRA");
		}
	}

	*len_ptr = wpabuf_len(extra_ies) - initial_len - 2;
}


/**
 * nan_pairing_initiate_pasn_auth - Initiate PASN authentication for NAN pairing
 * @nan_data: NAN data context
 * @addr: MAC address of the peer device
 * @auth_mode: Authentication mode to be used (PASN, SAE, or PMK)
 * @cipher: Cipher suite to be used for the pairing
 * @handle: Handle of the service instance for which pairing is requested
 * @peer_instance_id: Instance ID of the peer service for which pairing is
 *	requested
 * @responder: Whether this device is acting as PASN responder
 * @password: Password to be used for authentication (if applicable)
 * Returns: 0 on success, -1 on failure
 */
int nan_pairing_initiate_pasn_auth(struct nan_data *nan_data, const u8 *addr,
				   u8 auth_mode, int cipher, int handle,
				   u8 peer_instance_id, bool responder,
				   const char *password,
				   const struct nan_schedule *sched,
				   bool auto_nik_exchange)
{
	int ret = 0;
	struct pasn_data *pasn;
	struct nan_peer *peer;
	struct wpabuf *extra_ies;

	if (!addr) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Peer address missing");
		return -1;
	}

	peer = nan_get_peer(nan_data, addr);
	if (!peer) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Peer not known");
		return -1;
	}

	if (peer->bootstrap.in_progress) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Bootstrap in progress with peer");
		return -1;
	}

	if (!nan_pairing_is_supported(nan_data, peer, auth_mode)) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Invalid params to initiate authentication");
		return -1;
	}

	peer->pairing.self_pairing_role = responder ?
		NAN_PAIRING_ROLE_RESPONDER : NAN_PAIRING_ROLE_INITIATOR;

	if (nan_pairing_pasn_initialize(nan_data, peer, auth_mode, cipher,
					password,
					peer->pairing.self_pairing_role)) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Initialize failed");
		return -1;
	}

	pasn = peer->pairing.pasn;

	extra_ies = wpabuf_alloc(NAN_ELEMENT_MAX_SIZE);
	if (!extra_ies)
		return -1;

	/* Record service instance IDs before building the NAN element so that
	 * nan_pairing_prepare_pasn_elems() can read peer_instance_id when
	 * selecting the CSIA Publish ID for the subscriber role.
	 */
	peer->pairing.handle = handle;
	peer->pairing.peer_instance_id = peer_instance_id;
	peer->pairing.flags = 0;
	peer->pairing.auto_nik_exchange = auto_nik_exchange;

	/* TODO: Add support for NAN element fragmentation if it's larger than
	 * 255 octets, as defined in Wi-Fi Aware Specification v4.0 section 9.1.
	 */
	nan_pairing_prepare_pasn_elems(nan_data, peer, extra_ies, handle,
				       auth_mode);
	pasn_set_extra_ies(pasn, wpabuf_head_u8(extra_ies),
			   wpabuf_len(extra_ies));
	wpabuf_free(extra_ies);

	/* Skip DW schedule negotiation for non-cluster (USD) peers. */
	if (!nan_peer_no_shared_cluster(nan_data, peer->nmi_addr) &&
	    nan_configure_peer_schedule(nan_data, peer, sched))
		wpa_printf(MSG_DEBUG, "NAN: Could not configure peer schedule");
	if (responder) {
		if (peer->pairing.pending_auth1) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Responder - process pending Auth1");
			ret = nan_pairing_auth_rx(
				nan_data,
				wpabuf_head(peer->pairing.pending_auth1),
				wpabuf_len(peer->pairing.pending_auth1),
				(int) peer->freq);
			wpabuf_free(peer->pairing.pending_auth1);
			peer->pairing.pending_auth1 = NULL;

			return ret;
		}
		return 0;
	}

	if (auth_mode == NAN_PASN_AUTH_MODE_PMK) {
		peer->pairing.flags |= NAN_PAIRING_FLAG_NPK_VERIFICATION;
		ret = wpa_pasn_verify(pasn, pasn->own_addr, pasn->peer_addr,
				      pasn->bssid, pasn->akmp, pasn->cipher,
				      pasn->group, peer->freq,
				      NULL, 0, NULL, 0, NULL);
	} else {
		ret = wpas_pasn_start(pasn, pasn->own_addr, pasn->peer_addr,
				      pasn->bssid, pasn->akmp, pasn->cipher,
				      pasn->group, peer->freq,
				      NULL, 0, NULL, 0, NULL);
	}

	if (ret) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Failed to start PASN");
		nan_pairing_deinit_peer(nan_data, peer, true);
	}

	return ret;
}


/**
 * nan_pairing_done - Derive NPK caching related keys after successful pairing
 * @nan_data: NAN interface data
 * @peer: NAN peer with which pairing is being completed
 *
 * This function completes the NAN pairing process by deriving the necessary
 * cryptographic keys (KEK and NPK for opportunistic pairing) when NPK caching
 * is enabled.
 */
static void nan_pairing_done(struct nan_data *nan_data, struct nan_peer *peer)
{
	u8 npk[NAN_NPK_LEN];
	struct pasn_data *pasn = peer->pairing.pasn;
	int cipher = pasn_get_cipher(pasn);
	u8 *initiator_nmi, *responder_nmi;
	int ret;

	peer->pairing.flags |= NAN_PAIRING_FLAG_PAIRED;

	peer->pairing.pairing_csid = cipher == WPA_CIPHER_GCMP_256 ?
		NAN_CS_PK_PASN_256 : NAN_CS_PK_PASN_128;
	peer->pairing.pairing_akmp = pasn_get_akmp(pasn);

	if (!nan_data->cfg->pairing_cfg.npk_caching ||
	    !peer->pairing.pairing_cfg.npk_caching ||
	    (peer->pairing.flags & NAN_PAIRING_FLAG_NPK_VERIFICATION))
		return;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: Derive KEK after PASN pairing");

	if (peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_INITIATOR) {
		initiator_nmi = nan_data->cfg->nmi_addr;
		responder_nmi = peer->nmi_addr;
	} else {
		initiator_nmi = peer->nmi_addr;
		responder_nmi = nan_data->cfg->nmi_addr;
	}

	ret = nan_crypto_derive_kek(pasn->ptk.kdk, pasn->ptk.kdk_len,
				    peer->pairing.pairing_csid,
				    initiator_nmi, responder_nmi,
				    &pasn->ptk);
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Failed to derive KEK");
		return;
	}

	/* Store the peer NIK received in the PASN Encrypted Data element. */
	if (nan_peer_no_shared_cluster(nan_data, peer->nmi_addr) &&
	    peer->pairing.peer_nik_valid) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Storing peer NIK received during PASN");
		nan_data->cfg->update_pairing_credentials(
			nan_data->cfg->cb_ctx, peer->pairing.peer_nik,
			NAN_NIK_LEN, NAN_NIRA_CIPHER_VER_128,
			peer->pairing.peer_nik_lifetime, pasn_get_akmp(pasn),
			pasn->pmk, pasn->pmk_len);
	}

	/* For SAE AKMP, NPK was already derived inside the PASN module and
	 * stored in pasn->pmk. For PASN AKMP, derive NPK here and configure it
	 * to the PASN module. The NPK will be stored alongside the peer's NIK
	 * when the NIK is received from the peer.
	 */
	if (pasn_get_akmp(pasn) != WPA_KEY_MGMT_PASN)
		return;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: Derive NPK after PASN pairing");

	ret = nan_crypto_derive_npk(pasn->ptk.kdk, pasn->ptk.kdk_len,
				    peer->pairing.pairing_csid,
				    initiator_nmi, responder_nmi, npk,
				    sizeof(npk));
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Failed to derive NPK");
		return;
	}

	os_memcpy(pasn->pmk, npk, NAN_NPK_LEN);
	pasn->pmk_len = NAN_NPK_LEN;
}


/**
 * nan_nik_build_key_data - Build NAN Identity Key (NIK) key data buffer
 * @nan_data: Pointer to NAN data structure containing configuration
 * Returns: Pointer to allocated wpabuf containing the key data, or NULL
 *	on failure.
 *
 * This function constructs a buffer containing NAN key data elements including:
 * - NIK KDE (Key Data Encapsulation) with cipher version and NIK value
 * - Key Lifetime KDE indicating the NIK key lifetime
 *
 * Note: Caller is responsible for freeing the returned buffer.
 */
static struct wpabuf * nan_nik_build_key_data(struct nan_data *nan_data)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(KDE_HDR_LEN + sizeof(struct nan_nik_kde) +
			   KDE_HDR_LEN + sizeof(struct nan_key_lifetime_kde));
	if (!buf)
		return NULL;

	nan_add_kde_hdr(buf, NAN_KEY_DATA_NIK, sizeof(struct nan_nik_kde));
	wpabuf_put_u8(buf, NAN_NIRA_CIPHER_VER_128);
	wpabuf_put_data(buf, nan_data->cfg->nik, sizeof(nan_data->cfg->nik));

	nan_add_kde_hdr(buf, NAN_KEY_DATA_LIFETIME,
			sizeof(struct nan_key_lifetime_kde));
	wpabuf_put_le16(buf, NAN_KEY_LIFETIME_NIK);
	wpabuf_put_be32(buf, nan_data->cfg->nik_lifetime);

	return buf;
}


/**
 * nan_send_nik - Send NAN Identity Key (NIK) to a peer
 * @nan_data: Pointer to NAN data structure containing configuration and state
 * @peer: Pointer to the NAN peer structure to send the NIK to
 * Returns: 0 on success, -1 in case of an error
 *
 * This function sends the NAN Identity Key (NIK) and the NIK lifetime to a peer
 * device as part of the NAN pairing process. The NIK is encrypted using the KEK
 * (Key Encryption Key) derived from PASN and sent in a Shared Key Descriptor
 * Attribute (SKDA) within a follow-up message.
 */
static int nan_send_nik(struct nan_data *nan_data, struct nan_peer *peer)
{
	struct wpabuf *skda, *key_data;
	struct wpa_eapol_key *key_desc;
	u16 info, key_len;
	int ret;
	struct wpabuf *encrypted_key_data = NULL;
	size_t skda_len;
	u8 mic[16] = { 0 };

	/* NIK was already exchanged in the PASN Encrypted Data element. */
	if (nan_peer_no_shared_cluster(nan_data, peer->nmi_addr)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Skipping post-PASN NIK send");
		return 0;
	}

	if (!nan_data->cfg->pairing_cfg.npk_caching) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Local NPK caching not enabled, don't send NIK");
		return 0;
	}

	if (!peer->pairing.pairing_cfg.npk_caching) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Peer NPK caching not enabled, don't send NIK");
		return 0;
	}

	if (peer->pairing.flags & NAN_PAIRING_FLAG_NPK_VERIFICATION)
		return 0;

	if (!peer->pairing.pasn || !peer->pairing.pasn->ptk.kek_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: KEK not available for NIK encryption");
		return -1;
	}

	key_data = nan_nik_build_key_data(nan_data);
	if (!key_data) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to build NIK key data");
		return -1;
	}

	/* Encrypt the key data using the KEK from the PASN data */
	encrypted_key_data = nan_crypto_encrypt_key_data(
		key_data, peer->pairing.pasn->ptk.kek,
		peer->pairing.pasn->ptk.kek_len);
	wpabuf_clear_free(key_data);
	if (!encrypted_key_data) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to encrypt NIK key data");
		return -1;
	}

	skda_len = sizeof(struct nan_shared_key) +
		sizeof(struct wpa_eapol_key) + 2 + sizeof(mic) +
		wpabuf_len(encrypted_key_data);

	skda = wpabuf_alloc(NAN_ATTR_HDR_LEN + skda_len);
	if (!skda) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Failed to allocate SKDA buffer");
		wpabuf_free(encrypted_key_data);
		return -1;
	}

	wpabuf_put_u8(skda, NAN_ATTR_SHARED_KEY_DESCR);
	wpabuf_put_le16(skda, skda_len);
	wpabuf_put_u8(skda, peer->pairing.handle);

	key_desc = wpabuf_put(skda, sizeof(*key_desc));
	os_memset(key_desc, 0, sizeof(*key_desc));

	key_desc->type = NAN_KEY_DESC;
	info = WPA_KEY_INFO_TYPE_AKM_DEFINED | WPA_KEY_INFO_KEY_TYPE |
		WPA_KEY_INFO_ACK | WPA_KEY_INFO_ENCR_KEY_DATA |
		WPA_KEY_INFO_MIC;
	WPA_PUT_BE16(key_desc->key_info, info);

	key_len = wpa_cipher_key_len(peer->pairing.pasn->cipher);
	WPA_PUT_BE16(key_desc->key_length, key_len);

	wpabuf_put_data(skda, mic, sizeof(mic));
	wpabuf_put_be16(skda, wpabuf_len(encrypted_key_data));
	wpabuf_put_buf(skda, encrypted_key_data);
	wpa_printf(MSG_DEBUG, "NAN: Pairing: Sending NIK");

	ret = nan_data->cfg->transmit_followup(nan_data->cfg->cb_ctx,
					       peer->nmi_addr, skda,
					       peer->pairing.handle,
					       peer->pairing.peer_instance_id,
					       peer->freq);

	wpabuf_free(encrypted_key_data);
	wpabuf_free(skda);

	return ret;
}


/**
 * nan_send_nik_for_peer - Send the NIK follow-up to a peer by address
 * @nan_data: NAN module context
 * @peer_addr: Peer NMI address
 * Returns: 0 on success, -1 on failure
 */
int nan_send_nik_for_peer(struct nan_data *nan_data, const u8 *peer_addr)
{
	struct nan_peer *peer;

	if (!nan_data || !peer_addr)
		return -1;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: send_nik_for_peer: Peer " MACSTR
			   " not known", MAC2STR(peer_addr));
		return -1;
	}

	return nan_send_nik(nan_data, peer);
}


static int nan_pairing_derive_nd_pmk(struct nan_data *nan_data,
				     struct nan_peer *peer, u8 *nd_pmk)
{
	struct pasn_data *pasn = peer->pairing.pasn;
	int cipher = pasn_get_cipher(pasn);
	enum nan_cipher_suite_id csid;
	const u8 *initiator_nmi, *responder_nmi;
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: Derive ND-PMK after PASN pairing");

	if (peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_INITIATOR) {
		initiator_nmi = nan_data->cfg->nmi_addr;
		responder_nmi = peer->nmi_addr;
	} else {
		initiator_nmi = peer->nmi_addr;
		responder_nmi = nan_data->cfg->nmi_addr;
	}

	csid = cipher == WPA_CIPHER_GCMP_256 ? NAN_CS_PK_PASN_256 :
		NAN_CS_PK_PASN_128;

	ret = nan_crypto_derive_nd_pmk_from_kdk(pasn->ptk.kdk,
						pasn->ptk.kdk_len, csid,
						initiator_nmi, responder_nmi,
						nd_pmk);
	if (ret)
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Failed to derive ND PMK");
	return ret;
}


/**
 * nan_pairing_pasn_auth_tx_status - Handle PASN Authentication frame TX status
 * @nan: Pointer to NAN data structure
 * @data: Pointer to the transmitted frame data
 * @data_len: Length of the transmitted frame data in bytes
 * @acked: Whether the frame was acknowledged
 * Returns: 0 on success, -1 on error
 *
 * This function processes the transmission status of a PASN Authentication
 * frame used in NAN pairing and triggers the pairing result callback in case
 * PASN is done.
 */
int nan_pairing_pasn_auth_tx_status(struct nan_data *nan, const u8 *data,
				    size_t data_len, bool acked)
{
	int ret;
	struct nan_peer *peer;
	struct pasn_data *pasn;
	const struct ieee80211_mgmt *mgmt =
		(const struct ieee80211_mgmt *) data;

	if (!nan || !data ||
	    data_len < offsetof(struct ieee80211_mgmt, u.auth.variable))
		return -1;

	peer = nan_get_peer(nan, mgmt->da);
	if (!peer) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Peer not found " MACSTR,
			   MAC2STR(mgmt->da));
		return -1;
	}

	/* Pairing was rejected. Clear peer schedule if no active NDPs */
	if (!peer->pairing.pasn) {
		if (dl_list_empty(&peer->ndps) && !peer->ndp_setup.ndp)
			nan_clear_peer_schedule(nan, peer);

		return 0;
	}

	pasn = peer->pairing.pasn;

	ret = wpa_pasn_auth_tx_status(pasn, data, data_len, acked);
	if (ret == 1) {
		u8 nd_pmk[PMK_LEN];

		if (pasn->status == WLAN_STATUS_SUCCESS &&
		    nan_pairing_derive_nd_pmk(nan, peer, nd_pmk)) {
			pasn->status = WLAN_STATUS_UNSPECIFIED_FAILURE;
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Failed to derive ND PMK");
		}

		os_free(peer->pairing.psi_locale);
		os_free(peer->pairing.psi_vendor_name);
		os_free(peer->pairing.psi_model_name);
		os_free(peer->pairing.psi_pairing_name);

		nan_pairing_parse_setup_info(
			peer->bootstrap.pairing_setup_info,
			peer->bootstrap.pairing_setup_info_len,
			&peer->pairing.psi_locale,
			&peer->pairing.psi_vendor_name,
			&peer->pairing.psi_model_name,
			&peer->pairing.psi_pairing_name);

		ret = nan->cfg->pairing_result_cb(nan->cfg->cb_ctx,
						  peer->nmi_addr, pasn->akmp,
						  pasn->cipher, pasn->status,
						  &pasn->ptk,
						  pasn->status ==
						  WLAN_STATUS_SUCCESS ? nd_pmk :
						  NULL,
						  peer->pairing.psi_locale,
						  peer->pairing.psi_vendor_name,
						  peer->pairing.psi_model_name,
						  peer->pairing.psi_pairing_name);
		forced_memzero(nd_pmk, PMK_LEN);
		if (pasn->status != WLAN_STATUS_SUCCESS || ret < 0) {
			nan_pairing_deinit_peer(nan, peer, true);
			return -1;
		}

		nan_pairing_done(nan, peer);

		/*
		 * Allow the peer to install the keys before transmitting the
		 * follow-up.
		 */
		/* FIX: A blocking sleep should not really be used here, i.e.,
		 * this needs to be removed or replace with a registered eloop
		 * timeout to avoid blocking the process. */
		os_sleep(0, 30000);

		/* Only send the NIK follow-up automatically when
		 * auto_nik_exchange is enabled. When disabled, the upper layer
		 * controls the NIK exchange.
		 */
		if (peer->pairing.auto_nik_exchange) {
			if (nan_send_nik(nan, peer) < 0) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Pairing: Failed to send NIK");
				nan_pairing_deinit_peer(nan, peer, true);
				return -1;
			}
		} else {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: NIK send deferred to upper layer");
		}
	}

	wpabuf_free(pasn->frame);
	pasn->frame = NULL;

	return 0;
}


/**
 * nan_parse_csia - Parse NAN Cipher Suite Info Attribute
 * @csia: Pointer to the CSIA data buffer
 * @len: Length of the CSIA data buffer
 * @cs: Pointer to nan_cipher_suite structure to store parsed information
 * Returns: 0 on success, -1 on failure
 *
 * Parses the NAN Cipher Suite Info attribute (CSIA) and extracts the first
 * PASN-capable cipher suite entry. The CSIA may contain multiple entries;
 * non-PASN entries are skipped and the first PASN-capable entry is selected.
 */
static int nan_parse_csia(const u8 *csia, size_t len,
			  struct nan_cipher_suite *cs)
{
	size_t offset;

	/* Capabilities (1) + at least one Cipher Suite entry (2) */
	if (len < sizeof(struct nan_cipher_suite_info) +
	    sizeof(struct nan_cipher_suite)) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: CSIA too short");
		return -1;
	}

	/* Iterate cipher suite entries and select the first PASN-capable
	 * one.
	 */
	for (offset = sizeof(struct nan_cipher_suite_info);
	     offset + sizeof(struct nan_cipher_suite) <= len;
	     offset += sizeof(struct nan_cipher_suite)) {
		u8 csid = csia[offset];

		if (csid == NAN_CS_PK_PASN_128 || csid == NAN_CS_PK_PASN_256) {
			cs->csid = csid;
			cs->instance_id = csia[offset + 1];
			return 0;
		}
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Unsupported cipher suite in CSIA: %u",
			   csid);
	}

	wpa_printf(MSG_DEBUG, "NAN: Pairing: CSIA missing or invalid");
	return -1;
}


/**
 * nan_pairing_process_elems - Process NAN pairing information elements
 * @nan_data: NAN state data
 * @peer: NAN peer information structure
 * @mgmt: PASN Authentication frame
 * @len: Length of the PASN Authentication frame
 * @cs: Output cipher suite structure to be filled
 * Returns: 0 on success, -1 on failure
 *
 * This function processes NAN pairing information elements from a PASN
 * Authentication frame. It extracts the selected cipher suite and intance ID.
 */
static int nan_pairing_process_elems(struct nan_data *nan_data,
				     struct nan_peer *peer,
				     const struct ieee80211_mgmt *mgmt,
				     size_t len, struct nan_cipher_suite *cs)
{
	const u8 *ies;
	size_t ies_len;
	const u8 *buf;
	struct wpabuf *ie_buf;
	struct nan_attrs attrs;
	int ret;

	if (len < offsetof(struct ieee80211_mgmt, u.auth.variable)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: PASN frame too short for NAN elements");
		return -1;
	}

	ies = mgmt->u.auth.variable;
	ies_len = len - offsetof(struct ieee80211_mgmt, u.auth.variable);

	buf = get_vendor_ie(ies, ies_len, NAN_IE_VENDOR_TYPE);
	if (!buf)
		return -1;

	ie_buf = ieee802_11_defrag(buf + 2, buf[1], false);
	if (!ie_buf)
		return -1;

	buf = wpabuf_head(ie_buf);
	ret = nan_parse_attrs(nan_data, &buf[4], wpabuf_len(ie_buf) - 4,
			      &attrs);
	if (ret)
		goto fail;

	nan_parse_peer_dev_capa_ext(nan_data, peer, &attrs);
	nan_parse_pbea(nan_data, peer, &attrs);

	if (!attrs.cipher_suite_info || !attrs.cipher_suite_info_len ||
	    nan_parse_csia(attrs.cipher_suite_info, attrs.cipher_suite_info_len,
			   cs) < 0) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: CSIA missing or invalid");
		ret = -1;
	}


	nan_attrs_clear(nan_data, &attrs);
fail:
	wpabuf_free(ie_buf);
	return ret;
}


/**
 * nan_pairing_handle_auth_1 - Handle the first PASN frame in NAN pairing
 * @nan_data: Pointer to NAN data structure
 * @own_addr: Own MAC address
 * @peer: Pointer to NAN peer structure
 * @mgmt: Pointer to the received PASN frame
 * @len: Length of the PASN frame
 * Returns: 0 on success, -1 on failure
 *
 * This function processes the first PASN Authentication frame during NAN
 * pairing as a responder. It initializes the PASN data structure, prepares
 * the necessary information elements, and delegates to the PASN module to
 * handle the authentication.
 */
static int nan_pairing_handle_auth_1(struct nan_data *nan_data,
				     const u8 *own_addr,
				     struct nan_peer *peer,
				     const struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	struct nan_cipher_suite cs;
	struct pasn_data *pasn;
	int cipher;

	if (peer->pairing.self_pairing_role != NAN_PAIRING_ROLE_RESPONDER) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Unexpected Auth1 frame");
		return -1;
	}

	/* Re-arm the early TK install for each M1 (including retransmissions)
	 * so that a new PTK derived from a fresh M1 is always pushed to the
	 * driver before the corresponding M2 is sent.
	 */
	peer->pairing.nm_tk_installed = false;

	pasn = peer->pairing.pasn;

	if (nan_pairing_process_elems(nan_data, peer, mgmt, len, &cs)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Handle Auth1 NAN attributes failed");
		return -1;
	}

	cipher = cs.csid == NAN_CS_PK_PASN_256 ? WPA_CIPHER_GCMP_256 :
		WPA_CIPHER_CCMP;

	if (cipher != pasn->cipher) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Cipher suite mismatch (CSIA: %s, PASN: %s)",
			   wpa_cipher_txt(cipher),
			   wpa_cipher_txt(pasn->cipher));
		return -1;
	}

	if (handle_auth_pasn_1(pasn, own_addr, peer->nmi_addr, mgmt, len,
			       false) < 0) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Handle Auth1 failed");
		return -1;
	}

	return 0;
}


static int nan_pairing_handle_auth_2(struct nan_data *nan_data,
				     struct nan_peer *peer,
				     const struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	struct wpa_pasn_params_data pasn_data;
	struct pasn_data *pasn = peer->pairing.pasn;

	if (wpa_pasn_auth_rx(peer->pairing.pasn, (const u8 *)mgmt, len,
			     &pasn_data) < 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: wpa_pasn_auth_rx() failed");
		nan_data->cfg->pairing_result_cb(
			nan_data->cfg->cb_ctx, peer->nmi_addr, pasn->akmp,
			pasn->cipher, WLAN_STATUS_UNSPECIFIED_FAILURE, NULL,
			NULL, NULL, NULL, NULL, NULL);
		nan_pairing_deinit_peer(nan_data, peer, true);
		return -1;
	}

	return 0;
}


static int nan_pairing_handle_auth_3(struct nan_data *nan_data,
				     struct nan_peer *peer,
				     const struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	struct pasn_data *pasn = peer->pairing.pasn;
	int ret;
	u16 status = WLAN_STATUS_SUCCESS;
	u8 nd_pmk[PMK_LEN];

	ret = handle_auth_pasn_3(pasn, nan_data->cfg->nmi_addr, peer->nmi_addr,
				 mgmt, len);
	if (ret < 0) {
		status = WLAN_STATUS_UNSPECIFIED_FAILURE;
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Handle Auth3 failed");
	} else {
		if (nan_pairing_derive_nd_pmk(nan_data, peer, nd_pmk)) {
			status = WLAN_STATUS_UNSPECIFIED_FAILURE;
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Failed to derive ND PMK");
		}
	}

	nan_pairing_parse_setup_info(peer->bootstrap.pairing_setup_info,
				     peer->bootstrap.pairing_setup_info_len,
				     &peer->pairing.psi_locale,
				     &peer->pairing.psi_vendor_name,
				     &peer->pairing.psi_model_name,
				     &peer->pairing.psi_pairing_name);

	ret = nan_data->cfg->pairing_result_cb(nan_data->cfg->cb_ctx,
					       peer->nmi_addr, pasn->akmp,
					       pasn->cipher, status,
					       &pasn->ptk,
					       status == WLAN_STATUS_SUCCESS ?
					       nd_pmk : NULL,
					       peer->pairing.psi_locale,
					       peer->pairing.psi_vendor_name,
					       peer->pairing.psi_model_name,
					       peer->pairing.psi_pairing_name);
	forced_memzero(nd_pmk, PMK_LEN);
	if (ret < 0 || status != WLAN_STATUS_SUCCESS)
		nan_pairing_deinit_peer(nan_data, peer, true);
	else if (status == WLAN_STATUS_SUCCESS)
		nan_pairing_done(nan_data, peer);

	/* Don't clear PASN data if pairing is successful. If caching is
	 * enabled, it will still be needed when the NIK is received from
	 * the peer.
	 */
	return status == WLAN_STATUS_SUCCESS ? ret : -1;
}


/**
 * nan_pairing_auth_rx - Handle received NAN pairing Authentication frames
 * @nan_data: Pointer to NAN data structure
 * @mgmt: Pointer to the PASN Authentication frame
 * @len: Length of the PASN Authentication frame in bytes
 * @freq: Frequency on which the frame was received (MHz)
 * Returns: 0 on success, -1 on failure
 */
int nan_pairing_auth_rx(struct nan_data *nan_data,
			const struct ieee80211_mgmt *mgmt, size_t len,
			int freq)
{
	struct nan_peer *peer;
	u16 auth_alg, auth_transaction, status_code;
	int ret;
	struct wpabuf *nan_ie;
	const u8 *buf;

	if (len < offsetof(struct ieee80211_mgmt, u.auth.variable))
		return -1;

	if (!ether_addr_equal(mgmt->da, nan_data->cfg->nmi_addr)) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Not our frame");
		return -1;
	}

	auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
	auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
	status_code = le_to_host16(mgmt->u.auth.status_code);

	if (auth_alg != WLAN_AUTH_PASN) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Not a PASN frame, auth_alg=%d",
			   auth_alg);
		return -1;
	}

	/* For Authentication frames 2 and 3, the peer already has an active
	 * PASN session; look up by source address directly since the NAN
	 * element is not present in the clear in these frames.
	 */
	if (auth_transaction == 2 || auth_transaction == 3) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Authentication frame %u received",
			   auth_transaction);

		peer = nan_get_peer(nan_data, mgmt->sa);
		if (!peer) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: No peer found for " MACSTR,
				   MAC2STR(mgmt->sa));
			return -1;
		}

		if (!peer->pairing.pasn) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: No active PASN session for "
				   MACSTR,
				   MAC2STR(mgmt->sa));
			return -1;
		}

		if (status_code != WLAN_STATUS_SUCCESS) {
			struct pasn_data *pasn = peer->pairing.pasn;

			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Authentication frame %u rejected - status=%u",
				   auth_transaction, status_code);
			if (nan_data->cfg->pairing_result_cb)
				nan_data->cfg->pairing_result_cb(
					nan_data->cfg->cb_ctx,
					peer->nmi_addr,
					pasn ? pasn->akmp : 0,
					pasn ? pasn->cipher : 0,
					status_code, NULL, NULL,
					NULL, NULL, NULL, NULL);
			nan_pairing_deinit_peer(nan_data, peer, true);
			return -1;
		}

		if (auth_transaction == 2)
			return nan_pairing_handle_auth_2(nan_data, peer, mgmt,
							 len);
		return nan_pairing_handle_auth_3(nan_data, peer, mgmt, len);
	}

	buf = get_vendor_ie(mgmt->u.auth.variable,
			    len - offsetof(struct ieee80211_mgmt,
					   u.auth.variable),
			    NAN_IE_VENDOR_TYPE);
	if (!buf) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: NAN pairing element not found in Authentication frame 1");
		return -1;
	}

	nan_ie = ieee802_11_defrag(buf + 2, buf[1], false);
	if (!nan_ie) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: No NAN element in PASN Authentication frame");
		return -1;
	}

	ret = nan_add_peer(nan_data, mgmt->sa, NULL, 0,
			   wpabuf_head_u8(nan_ie) + 4,
			   wpabuf_len(nan_ie) - 4);
	wpabuf_free(nan_ie);
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to add peer from PASN");
		return -1;
	}

	peer = nan_get_peer(nan_data, mgmt->sa);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to get a peer that was just added");
		return -1;
	}

	if (!peer->pairing.pasn) {
		if (status_code == WLAN_STATUS_SUCCESS &&
		    auth_transaction == 1) {
			struct nan_cipher_suite cs;
			const u8 *rsne;
			struct wpa_ie_data rsn_data;

			if (nan_pairing_process_elems(nan_data, peer, mgmt, len,
						      &cs)) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Pairing: Handle Auth1 NAN attributes failed");
				return -1;
			}

			rsne = get_ie(mgmt->u.auth.variable,
				      len - offsetof(struct ieee80211_mgmt,
						     u.auth.variable),
				      WLAN_EID_RSN);
			if (!rsne) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Pairing: RSNE missing in Auth1");
				return -1;
			}

			if (wpa_parse_wpa_ie_rsn(rsne, rsne[1] + 2,
						 &rsn_data)) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Pairing: Failed to parse RSNE in Auth1");
				return -1;
			}

			wpabuf_free(peer->pairing.pending_auth1);
			peer->pairing.pending_auth1 =
				wpabuf_alloc_copy(mgmt, len);
			if (!peer->pairing.pending_auth1)
				return -1;

			nan_data->cfg->pairing_request(nan_data->cfg->cb_ctx,
						       peer->nmi_addr, cs.csid,
						       cs.instance_id,
						       &rsn_data);
			return 0;
		}

		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: PASN data not initialized for peer");
		return -1;
	}

	if (status_code != WLAN_STATUS_SUCCESS) {
		struct pasn_data *pasn = peer->pairing.pasn;

		nan_data->cfg->pairing_result_cb(nan_data->cfg->cb_ctx,
						 peer->nmi_addr, pasn->akmp,
						 pasn->cipher, status_code,
						 NULL, NULL,
						 NULL, NULL, NULL, NULL);
		nan_pairing_deinit_peer(nan_data, peer, true);
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Authentication rejected - status=%u",
			   status_code);
		return -1;
	}

	if (auth_transaction == 1) {
		struct pasn_data *pasn = peer->pairing.pasn;

		/* Set the reception frequency so the response is sent on
		 * the correct channel; needed for non-cluster (USD) devices
		 * where the radio is not locked to a fixed channel.
		 */
		if (pasn && freq)
			pasn->freq = freq;

		/* For non-cluster (USD) devices the BSSID is zero until the
		 * first PASN M1 is received; update it from the frame so
		 * subsequent checks pass.
		 */
		if (pasn && is_zero_ether_addr(pasn->bssid) &&
		    !is_zero_ether_addr(mgmt->bssid)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Setting BSSID from PASN M1: "
				   MACSTR, MAC2STR(mgmt->bssid));
			pasn_set_bssid(pasn, mgmt->bssid);
		}

		return nan_pairing_handle_auth_1(nan_data,
						 nan_data->cfg->nmi_addr, peer,
						 mgmt, len);
	}

	return -1;
}


/**
 * nan_pairing_followup_rx - Process received NAN pairing follow-up frame
 * @nan_data: NAN data context
 * @peer_addr: MAC address of the peer device
 * @shared_key_descr: Pointer to the shared key descriptor attribute
 * @attr_len: Length of the shared key descriptor attribute
 * Returns: true if the follow-up frame was processed, false otherwise.
 *
 * This function processes a received NAN pairing follow-up frame. It extracts
 * the NIK (NAN Identity Key) from the frame and notifies about the received
 * NIK.
 *
 * If the local device acted as the responder in the pairing process, it also
 * sends the local NIK to the peer.
 */
bool nan_pairing_followup_rx(struct nan_data *nan_data, const u8 *peer_addr,
			     const struct nan_shared_key *shared_key_descr,
			     size_t attr_len)
{
	struct nan_peer *peer;
	struct pasn_data *pasn;
	const struct wpa_eapol_key *key_desc;
	struct wpa_eapol_ie_parse ie;
	const struct nan_nik_kde *nik_kde;
	const struct nan_key_lifetime_kde *lifetime_kde;
	const u8 *pos;
	struct wpabuf *key_data = NULL;
	u16 key_data_len, key_info;
	bool ret = false;
	u16 lifetime_bitmap;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: Follow-up frame received");
	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame from unknown peer");
		return false;
	}

	pasn = peer->pairing.pasn;
	if (!pasn || !pasn->ptk.kek_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: No PASN data for follow-up frame");
		return false;
	}

	if (!nan_data->cfg->pairing_cfg.npk_caching) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: NPK caching not enabled, ignore follow-up frame");
		return false;
	}

	key_desc = (const struct wpa_eapol_key *) shared_key_descr->key;
	key_info = WPA_GET_BE16(key_desc->key_info);

	if (!(key_info & WPA_KEY_INFO_KEY_TYPE)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame does not contain pairwise key");
		return false;
	}

	if (!(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame does not contain encrypted key data");
		return false;
	}

	if (attr_len < sizeof(*shared_key_descr) + sizeof(*key_desc) + 16 + 2) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame too short for Key Data Length field");
		return false;
	}

	pos = shared_key_descr->key + sizeof(*key_desc) + 16;
	key_data_len = WPA_GET_BE16(pos);

	if (attr_len < sizeof(*shared_key_descr) + sizeof(*key_desc) + 16 + 2 +
	    key_data_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame too short for Key Data field");
		return false;
	}

	pos += 2;

	key_data = nan_crypto_decrypt_key_data(pasn->ptk.kek, pasn->ptk.kek_len,
					       pos, key_data_len);
	if (!key_data) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to decrypt key data in follow-up frame");
		goto fail;
	}

	if (wpa_parse_kde_ies(wpabuf_head(key_data), wpabuf_len(key_data),
			      &ie) < 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to parse decrypted key data in follow-up frame");
		goto fail;
	}

	if (!ie.nan_nik) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: NIK KDE missing in decrypted key data");
		goto fail;
	}

	nik_kde = (const struct nan_nik_kde *) ie.nan_nik;
	if (nik_kde->cipher_ver != NAN_NIRA_CIPHER_VER_128) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Unsupported NIK cipher version: %u",
			   nik_kde->cipher_ver);
		goto fail;
	}

	if (!ie.nan_key_lifetime) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Key Lifetime KDE missing in decrypted key data");
		goto fail;
	}

	lifetime_kde = (const struct nan_key_lifetime_kde *)
		ie.nan_key_lifetime;
	lifetime_bitmap = le_to_host16(lifetime_kde->key_bitmap);
	if (!(lifetime_bitmap & NAN_KEY_LIFETIME_NIK)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Unexpected key bitmap in Key "
			   "Lifetime KDE: 0x%02x",
			   lifetime_bitmap);
		goto fail;
	}

	nan_data->cfg->update_pairing_credentials(
		nan_data->cfg->cb_ctx, nik_kde->nik, NAN_NIK_LEN,
		nik_kde->cipher_ver, be_to_host32(lifetime_kde->lifetime_sec),
		pasn_get_akmp(pasn),
		pasn_get_pmk(pasn), pasn_get_pmk_len(pasn));

	if (peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER)
		nan_send_nik(nan_data, peer);

	ret = true;
fail:
	nan_pairing_deinit_peer(nan_data, peer, !ret);
	wpabuf_free(key_data);
	return ret;
}


int nan_pairing_set_pairing_setup(struct nan_data *nan, bool value)
{
	wpa_printf(MSG_DEBUG, "NAN: SET: Pairing setup: %d -> %d",
		   nan->cfg->pairing_cfg.pairing_setup, value);
	nan->cfg->pairing_cfg.pairing_setup = value;
	return 0;
}


int nan_pairing_set_npk_caching(struct nan_data *nan, bool value)
{
	wpa_printf(MSG_DEBUG, "NAN: SET: NPK caching: %d -> %d",
		   nan->cfg->pairing_cfg.npk_caching, value);
	nan->cfg->pairing_cfg.npk_caching = value;
	return 0;
}


int nan_pairing_set_pairing_verification(struct nan_data *nan, bool value)
{
	wpa_printf(MSG_DEBUG, "NAN: SET: Pairing verification: %d -> %d",
		   nan->cfg->pairing_cfg.pairing_verification, value);

	if (!nan->cfg->pairing_cfg.pairing_verification && value &&
	    nan_nira_get_tag_nonce(nan->cfg, nan->nira_nonce,
				   nan->nira_tag) < 0) {
		wpa_printf(MSG_INFO,
			   "NAN: Failed to enable pairing verification");
		return -1;
	}

	nan->cfg->pairing_cfg.pairing_verification = value;

	return 0;
}


int nan_pairing_set_cipher_suites(struct nan_data *nan, u32 value)
{
	if (value & ~(NAN_PAIRING_PASN_128 | NAN_PAIRING_PASN_256)) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Invalid cipher suites 0x%08x", value);
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN: SET: Pairing cipher suites: 0x%08x -> 0x%08x",
		   nan->cfg->pairing_cfg.cipher_suites, value);

	nan->cfg->pairing_cfg.cipher_suites = value;
	return 0;
}


int nan_pairing_set_nik(struct nan_data *nan, const u8 *nik, size_t nik_len)
{
	u8 nonce[NAN_NIRA_NONCE_LEN];
	u8 tag[NAN_NIRA_TAG_LEN];

	if (!nik || nik_len != NAN_NIK_LEN) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Invalid NIK (len=%zu)",
			   nik_len);
		return -1;
	}

	os_memcpy(nan->cfg->nik, nik, NAN_NIK_LEN);

	if (nan->cfg->pairing_cfg.pairing_verification) {
		if (nan_nira_get_tag_nonce(nan->cfg, nonce, tag) < 0) {
			wpa_printf(MSG_INFO,
				   "NAN: Failed to set NIRA for new NIK");
			return -1;
		}
		os_memcpy(nan->nira_nonce, nonce, NAN_NIRA_NONCE_LEN);
		wpa_hexdump_key(MSG_DEBUG, "NAN: NIRA nonce",
				nan->nira_nonce, NAN_NIRA_NONCE_LEN);
		os_memcpy(nan->nira_tag, tag, NAN_NIRA_TAG_LEN);
		wpa_hexdump_key(MSG_DEBUG, "NAN: NIRA tag",
				nan->nira_tag, NAN_NIRA_TAG_LEN);
	} else {
		os_memset(nan->nira_nonce, 0, NAN_NIRA_NONCE_LEN);
		os_memset(nan->nira_tag, 0, NAN_NIRA_TAG_LEN);
	}

	wpa_hexdump_key(MSG_DEBUG, "NAN: New NIK", nan->cfg->nik, NAN_NIK_LEN);

	return 0;
}


int nan_pairing_set_nik_lifetime(struct nan_data *nan, u32 lifetime)
{
	if (!lifetime) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Invalid NIK lifetime (%u)",
			   lifetime);
		return -1;
	}

	nan->cfg->nik_lifetime = lifetime;
	wpa_printf(MSG_DEBUG, "NAN: SET: NIK lifetime: %u seconds",
		   lifetime);
	return 0;
}


bool nan_pairing_is_peer_paired(struct nan_data *nan_data, const u8 *peer_addr)
{
	struct nan_peer *peer;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer)
		return false;

	return !!(peer->pairing.flags & NAN_PAIRING_FLAG_PAIRED);
}


void nan_pairing_unpair_peer(struct nan_data *nan_data, const u8 *peer_addr)
{
	struct nan_peer *peer;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer)
		return;

	wpa_printf(MSG_DEBUG, "NAN: Unpair peer " MACSTR,
		   MAC2STR(peer->nmi_addr));

	peer->pairing.flags &= ~NAN_PAIRING_FLAG_PAIRED;
	nan_pairing_deinit_peer(nan_data, peer, true);
}


/*
 * nan_add_nika_attr - Add NIKA (NAN Identity Key attribute) to a buffer
 *
 * NIKA format: attr_id(1) + attr_len(2) + cipher_ver(1) + NIK(16) + lifetime(4)
 */
static int nan_add_nika_attr(struct wpabuf *buf, const u8 *nik, size_t nik_len,
			     u32 nik_lifetime)
{
	size_t attr_len;

	if (!buf || !nik || nik_len != NAN_NIK_LEN) {
		wpa_printf(MSG_INFO, "NAN: Invalid parameters for NIKA");
		return -1;
	}

	/* NIKA format: Cipher Version (1) + NIK (16) + Lifetime (4) */
	attr_len = 1 + nik_len + 4;

	if (wpabuf_tailroom(buf) < NAN_ATTR_HDR_LEN + attr_len) {
		wpa_printf(MSG_INFO, "NAN: Not enough room for NIKA");
		return -1;
	}

	wpabuf_put_u8(buf, NAN_ATTR_NIKA);
	wpabuf_put_le16(buf, attr_len);
	wpabuf_put_u8(buf, NAN_NIRA_CIPHER_VER_128);
	wpabuf_put_data(buf, nik, nik_len);
	wpabuf_put_be32(buf, nik_lifetime);

	wpa_hexdump_key(MSG_DEBUG, "NAN: NIKA - NIK", nik, nik_len);
	wpa_printf(MSG_DEBUG, "NAN: NIKA - Lifetime: %u seconds", nik_lifetime);

	return 0;
}


/*
 * nan_pairing_build_nika - Build NIKA-containing wrapped data for
 * PASN M2 (responder) or M3 (initiator).
 *
 * M2 (include_pairing_attrs=true): DCEA + CSIA + NIKA
 * M3 (include_pairing_attrs=false): NIKA only
 */
static struct wpabuf *
nan_pairing_build_nika(struct nan_data *nan_data, const struct nan_peer *peer,
		       bool include_pairing_attrs)
{
	struct wpabuf *buf;
	u8 *len_ptr;
	size_t initial_len;
	struct nan_cipher_suite cs;

	buf = wpabuf_alloc(512);
	if (!buf)
		return NULL;

	/* Start NAN element */
	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	len_ptr = wpabuf_put(buf, 1); /* placeholder for length */
	initial_len = wpabuf_len(buf);

	/* OUI + OUI Type for NAN */
	wpabuf_put_be32(buf, NAN_IE_VENDOR_TYPE);

	if (include_pairing_attrs) {
		/* M2 (responder): DCEA + CSIA + NIKA */
		nan_add_dev_capa_ext_attr(nan_data, buf);

		if (peer->pairing.pasn->cipher == WPA_CIPHER_GCMP_256)
			cs.csid = NAN_CS_PK_PASN_256;
		else
			cs.csid = NAN_CS_PK_PASN_128;
		cs.instance_id = peer->pairing.handle;
		nan_add_csia(buf, 0, 1, &cs);
	}

	/* NIKA (both M2 and M3) */
	if (nan_add_nika_attr(buf, nan_data->cfg->nik, NAN_NIK_LEN,
			      nan_data->cfg->nik_lifetime) < 0) {
		wpa_printf(MSG_INFO, "NAN: Failed to add NIKA");
		wpabuf_free(buf);
		return NULL;
	}

	/* Length covers the bytes written after the length byte itself. */
	*len_ptr = wpabuf_len(buf) - initial_len;

	wpa_hexdump_buf(MSG_DEBUG, "NAN: NIKA wrapped data (before encryption)",
			buf);
	return buf;
}


/*
 * nan_pairing_prepare_data_element - PASN callback for pairing data
 *
 * For clustered responder pairing, install the NM-TK after PTK derivation and
 * before M2 transmission. For non-cluster pairing, prepare the encrypted NIKA
 * data element for M2 or M3.
 */
static int nan_pairing_prepare_data_element(void *ctx, const u8 *peer_addr)
{
	struct nan_data *nan_data = ctx;
	struct nan_peer *peer;
	struct pasn_data *pasn;
	struct wpabuf *wrapped_data = NULL;
	struct wpabuf *extra_ies = NULL;
	bool include_pairing_attrs, is_non_cluster;
	int ret = -1;

	if (!nan_data || !peer_addr)
		return -1;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer || !peer->pairing.pasn)
		return -1;

	pasn = peer->pairing.pasn;
	is_non_cluster =
		nan_peer_no_shared_cluster(nan_data, peer->nmi_addr);
	include_pairing_attrs =
		peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER;

	wpa_printf(MSG_DEBUG,
		   "NAN: prepare_data_element for peer " MACSTR
		   " (role: %s)",
		   MAC2STR(peer_addr),
		   include_pairing_attrs ? "responder" : "initiator");

	/* The NM-TK is not needed for non-cluster pairing. */
	if (!is_non_cluster &&
	    peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER &&
	    !peer->pairing.nm_tk_installed && pasn->ptk.tk_len &&
	    nan_data->cfg->install_nm_tk) {
		if (nan_data->cfg->install_nm_tk(nan_data->cfg->cb_ctx,
						 peer->nmi_addr, pasn->cipher,
						 pasn->ptk.tk,
						 pasn->ptk.tk_len) == 0)
			peer->pairing.nm_tk_installed = true;
	}

	if (!is_non_cluster)
		return 0;

	/* Responder (M2): DCEA+CSIA+NIKA; Initiator (M3): NIKA only */
	wrapped_data = nan_pairing_build_nika(nan_data, peer,
					      include_pairing_attrs);
	if (!wrapped_data)
		goto out;

	extra_ies = wpabuf_alloc(wpabuf_len(wrapped_data) + 100);
	if (!extra_ies)
		goto out;

	/* Prepend any existing extra IEs so they are not lost when the
	 * encrypted data element is appended.
	 */
	if (pasn->extra_ies && pasn->extra_ies_len) {
		struct wpabuf *combined;

		combined = wpabuf_alloc(pasn->extra_ies_len +
					wpabuf_len(wrapped_data) + 100);
		if (!combined)
			goto out;

		wpabuf_put_data(combined, pasn->extra_ies, pasn->extra_ies_len);
		wpabuf_free(extra_ies);
		extra_ies = combined;
	}

	ret = pasn_add_encrypted_data(pasn, extra_ies,
				      wpabuf_head(wrapped_data),
				      wpabuf_len(wrapped_data));
	if (ret < 0)
		goto out;

	ret = pasn_set_extra_ies(pasn, wpabuf_head(extra_ies),
				 wpabuf_len(extra_ies));
	if (ret < 0)
		goto out;

	wpa_printf(MSG_DEBUG,
		   "NAN: Successfully prepared encrypted NIKA data for %s",
		   include_pairing_attrs ? "M2 (responder)" : "M3 (initiator)");
	ret = 0;

out:
	wpabuf_clear_free(wrapped_data);
	wpabuf_free(extra_ies);
	return ret;
}


/*
 * nan_pairing_parse_nika - Parse NIKA from NAN element body
 * (after OUI+type, i.e., the NAN attributes area).
 */
static int nan_pairing_parse_nika(const u8 *data, size_t len, u8 *nik,
				  u32 *nik_lifetime)
{
	const u8 *pos = data;
	const u8 *end = data + len;

	while (pos + NAN_ATTR_HDR_LEN <= end) {
		u8 attr_id = *pos++;
		u16 attr_len = WPA_GET_LE16(pos);

		pos += 2;

		if (attr_len > end - pos) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Invalid attribute length in NIKA parsing");
			return -1;
		}

		if (attr_id == NAN_ATTR_NIKA) {
			/* NIKA: Cipher Version (1) + NIK (16) + Lifetime (4)
			 */
			if (attr_len < 1 + NAN_NIK_LEN + 4) {
				wpa_printf(MSG_DEBUG,
					   "NAN: NIKA too short: %u",
					   attr_len);
				return -1;
			}
			pos++; /* Skip cipher version */
			os_memcpy(nik, pos, NAN_NIK_LEN);
			pos += NAN_NIK_LEN;
			*nik_lifetime = WPA_GET_BE32(pos);

			wpa_hexdump_key(MSG_DEBUG, "NAN: Parsed NIKA - NIK",
					nik, NAN_NIK_LEN);
			wpa_printf(MSG_DEBUG,
				   "NAN: Parsed NIKA - Lifetime: %u seconds",
				   *nik_lifetime);
			return 0;
		}

		pos += attr_len;
	}

	wpa_printf(MSG_DEBUG, "NAN: NIKA not found");
	return -1;
}


/*
 * nan_pairing_parse_data_element - PASN callback to parse decrypted data
 * from M2 (initiator receives) or M3 (responder receives).
 * Only called for non-cluster peers.
 */
static int nan_pairing_parse_data_element(void *ctx, const u8 *data,
					  size_t len)
{
	struct nan_data *nan_data = ctx;
	struct nan_peer *peer = NULL;
	const u8 *pos = data;
	const u8 *end = data + len;
	u8 peer_nik[NAN_NIK_LEN];
	u32 nik_lifetime;
	bool found = false;

	if (!nan_data || !data || len == 0)
		return -1;

	wpa_hexdump(MSG_DEBUG, "NAN: parse_data_element: Decrypted data",
		    data, len);

	/* Find the peer with an active PASN session */
	dl_list_for_each(peer, &nan_data->peer_list, struct nan_peer, list) {
		if (peer->pairing.pasn &&
		    (peer->non_cluster || !nan_data->nan_started)) {
			found = true;
			break;
		}
	}

	if (!found) {
		wpa_printf(MSG_DEBUG,
			   "NAN: parse_data_element: No peer with active PASN");
		return -1;
	}

	/* Parse NAN element(s) from decrypted data */
	while (end - pos >= 2) {
		u8 eid = *pos++;
		u8 elen = *pos++;

		if (elen > end - pos) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Invalid element length in encrypted data");
			return -1;
		}

		if (eid == WLAN_EID_VENDOR_SPECIFIC && elen >= 4) {
			u32 oui_type = WPA_GET_BE32(pos);

			if (oui_type == NAN_IE_VENDOR_TYPE &&
			    nan_pairing_parse_nika(pos + 4, elen - 4, peer_nik,
						   &nik_lifetime) == 0) {
				os_memcpy(peer->pairing.peer_nik,
					  peer_nik, NAN_NIK_LEN);
				peer->pairing.peer_nik_valid = true;
				peer->pairing.peer_nik_lifetime = nik_lifetime;

				wpa_printf(MSG_DEBUG,
					   "NAN: Successfully parsed peer NIK from %s",
					   peer->pairing.self_pairing_role ==
					   NAN_PAIRING_ROLE_INITIATOR ?
					   "M2 (responder's NIK)" :
					   "M3 (initiator's NIK)");
				return 0;
			}
		}

		pos += elen;
	}

	wpa_printf(MSG_DEBUG, "NAN: Failed to find NIKA in encrypted data");
	return -1;
}


void nan_pairing_store_sae_pmkid(struct nan_data *nan_data, const u8 *addr)
{
	struct nan_peer *peer;

	peer = nan_get_peer(nan_data, addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: store_sae_pmkid: Peer " MACSTR " not found",
			   MAC2STR(addr));
		return;
	}

	if (!peer->pairing.pasn) {
		wpa_printf(MSG_DEBUG,
			   "NAN: store_sae_pmkid: No PASN context for " MACSTR,
			   MAC2STR(addr));
		return;
	}

	if (peer->pairing.pasn->akmp != WPA_KEY_MGMT_SAE) {
		wpa_printf(MSG_DEBUG,
			   "NAN: store_sae_pmkid: akmp=0x%x is not SAE, skipping",
			   peer->pairing.pasn->akmp);
		return;
	}

	wpa_hexdump(MSG_DEBUG, "NAN: store_sae_pmkid: SAE PMKID",
		    peer->pairing.pasn->sae.pmkid, PMKID_LEN);

	os_memcpy(peer->pairing.npkid, peer->pairing.pasn->sae.pmkid,
		  PMKID_LEN);
	peer->pairing.npkid_valid = true;
	wpa_printf(MSG_DEBUG,
		   "NAN: Pairing: Stored SAE PMKID for " MACSTR,
		   MAC2STR(addr));
}
