/*
 * Wi-Fi Aware - NAN Data link security
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "utils/common.h"
#include "common/ieee802_11_common.h"
#include "nan_i.h"


/*
 * nan_sec_reset - Reset security state
 * @nan: NAN module context from nan_init()
 * @ndp_sec: NDP security context to reset
 */
void nan_sec_reset(struct nan_data *nan, struct nan_ndp_sec *ndp_sec)
{
	os_memset(ndp_sec, 0, sizeof(*ndp_sec));
}


static void nan_sec_dump(const struct nan_data *nan,
			 const struct nan_peer *peer)
{
	const struct nan_ndp_sec *s = &peer->ndp_setup.sec;

	wpa_printf(MSG_DEBUG, "NAN: SEC: present=%u, valid=%u",
		   s->present, s->valid);
	wpa_printf(MSG_DEBUG, "NAN: SEC: i_csid=%u, i_instance_id=%u",
		   s->i_csid, s->i_instance_id);
	wpa_printf(MSG_DEBUG, "NAN: SEC: r_csid=%u, r_instance_id=%u",
		   s->r_csid, s->r_instance_id);
}


static int nan_sec_rx_m1_verify(struct nan_data *nan,
				const struct nan_attrs *attrs)
{
	const struct nan_sec_ctxt *sc;
	size_t expected_len;

	expected_len = sizeof(struct nan_cipher_suite_info) +
		sizeof(struct nan_cipher_suite);

	if (!attrs->cipher_suite_info ||
	    attrs->cipher_suite_info_len < expected_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Missing valid cipher suite attribute");
		return -1;
	}

	/* Need at least one PMKID */
	expected_len = sizeof(struct nan_sec_ctxt) + PMKID_LEN;

	if (!attrs->sec_ctxt_info  || attrs->sec_ctxt_info_len < expected_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Missing valid security context attribute");
		return -1;
	}

	sc = (const struct nan_sec_ctxt *) attrs->sec_ctxt_info;
	if (sc->scid != NAN_SEC_CTX_TYPE_ND_PMKID ||
	    le_to_host16(sc->len) != PMKID_LEN) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Got unknown security context");
		return -1;
	}

	return 0;
}


static int nan_sec_parse_csia(const u8 *csia, size_t csia_len, u8 *instance_id,
			      u8 *capab, u8 *csid, u8 *gtk_csid)
{
	const struct nan_cipher_suite_info *cs_info =
		(const struct nan_cipher_suite_info *) csia;
	const u8 *cs_buf = cs_info->cs;
	const struct nan_cipher_suite *cs;

	if (!csia || csia_len < sizeof(*cs_info)) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: Invalid CSIA attribute");
		return -1;
	}

	*instance_id = 0;
	*capab = cs_info->capab;
	csia_len -= sizeof(*cs_info);

	*csid = NAN_CS_NONE;
	*gtk_csid = NAN_CS_NONE;

	while (csia_len >= sizeof(*cs)) {
		cs = (const struct nan_cipher_suite *) cs_buf;
		if (*instance_id && cs->instance_id != *instance_id) {
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Multiple instance IDs in CSIA");
			return -1;
		}

		*instance_id = cs->instance_id;

		if (cs->csid == NAN_CS_GTK_CCMP_128 ||
		    cs->csid == NAN_CS_GTK_GCMP_256) {
			if (*gtk_csid != NAN_CS_NONE) {
				wpa_printf(MSG_DEBUG,
					   "NAN: SEC: Multiple GTK CSIDs in CSIA");
				return -1;
			}

			*gtk_csid = cs->csid;
		} else {
			if (*csid != NAN_CS_NONE) {
				wpa_printf(MSG_DEBUG,
					   "NAN: SEC: Multiple CSIDs in CSIA");
				return -1;
			}

			if (cs->csid != NAN_CS_SK_CCM_128 &&
			    cs->csid != NAN_CS_SK_GCM_256) {
				wpa_printf(MSG_DEBUG,
					   "NAN: SEC: Unsupported cipher suite=%u",
					   cs->csid);
				return -1;
			}

			*csid = cs->csid;
		}

		cs_buf += sizeof(*cs);
		csia_len -= sizeof(*cs);
	}

	if (*csid == NAN_CS_NONE) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: No valid CSID in CSIA");
		return -1;
	}

	return 0;
}


static int nan_sec_rx_m1(struct nan_data *nan, struct nan_peer *peer,
			 const struct nan_msg *msg,
			 const struct wpa_eapol_key *key)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	const struct nan_sec_ctxt *sc;
	u8 instance_id;
	int ret;

	if (peer->ndp_setup.state != NAN_NDP_STATE_REQ_RECV) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: Not expecting m1");
		return -1;
	}

	ret = nan_sec_rx_m1_verify(nan, &msg->attrs);
	if (ret)
		return ret;

	sc = (const struct nan_sec_ctxt *) msg->attrs.sec_ctxt_info;

	instance_id = sc->instance_id;
	if (ndp_sec->i_instance_id && instance_id &&
	    ndp_sec->i_instance_id != instance_id) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: Mismatched instance ID");
		return -1;
	}

	os_memcpy(ndp_sec->i_pmkid, sc->ctxt, PMKID_LEN);

	/* Save initiator's nonce */
	os_memcpy(ndp_sec->i_nonce, key->key_nonce, WPA_NONCE_LEN);

	/* Save the replay counter */
	os_memcpy(ndp_sec->replaycnt, key->replay_counter,
		  sizeof(key->replay_counter));

	/* Store the authentication token, that is required for m3 MIC */
	if (msg->len < 24)
		return -1;
	ret = nan_crypto_calc_auth_token(ndp_sec->i_csid,
					 (const u8 *) &msg->mgmt->u,
					 msg->len - 24, ndp_sec->auth_token);
	if (ret)
		return ret;

	/* The flow will continue, once higher layer ACK the NDP setup */
	ndp_sec->valid = true;
	return 0;
}


static int nan_sec_key_mic_ver(struct nan_data *nan, const u8 *buf, size_t len,
			       const struct wpa_eapol_key *key,
			       const u8 *kck, size_t kck_len, u8 csid)
{
	u8 mic[NAN_KEY_MIC_24_LEN];
	u8 *pos = (u8 *) (key + 1);
	u8 mic_len;
	int ret;

	os_memset(mic, 0, sizeof(mic));

	if (csid == NAN_CS_SK_CCM_128)
		mic_len = NAN_KEY_MIC_LEN;
	else if (csid == NAN_CS_SK_GCM_256)
		mic_len = NAN_KEY_MIC_24_LEN;
	else
		return -1;

	os_memcpy(mic, pos, mic_len);
	os_memset(pos, 0, mic_len);

	ret = nan_crypto_key_mic(buf, len, kck, kck_len, csid, pos);
	if (ret)
		return ret;

	if (os_memcmp_const(mic, pos, mic_len) != 0) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: MIC verification failed");
		return -1;
	}

	return 0;
}


static int nan_sec_rx_m2(struct nan_data *nan, struct nan_peer *peer,
			 const struct nan_msg *msg,
			 const struct wpa_eapol_key *key)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	struct nan_ndp *ndp = peer->ndp_setup.ndp;
	struct nan_ptk tptk;
	const u8 *pos;
	int ret;

	if (peer->ndp_setup.state != NAN_NDP_STATE_RES_RECV) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: Not expecting m2");
		return -1;
	}

	if (ndp_sec->i_csid != ndp_sec->r_csid) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: i_csid != r_csid (%u, %u)",
			   ndp_sec->i_csid, ndp_sec->r_csid);
		return -1;
	}

	/* Save responder's nonce */
	os_memcpy(ndp_sec->r_nonce, key->key_nonce, WPA_NONCE_LEN);

	/* Note: Replay counter should have been verified by the caller */

	/* PTK should be derived using NDI addresses */
	ret = nan_crypto_pmk_to_ptk(ndp_sec->pmk,
				    ndp->init_ndi, ndp->resp_ndi,
				    ndp_sec->i_nonce, ndp_sec->r_nonce,
				    &tptk, ndp_sec->i_csid);
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: m2 failed to derive PTK");
		return ret;
	}

	/*
	 * Due to the different MIC size, need to handle the fields starting
	 * with the MIC differently.
	 */
	pos = (const u8 *) (key + 1);
	if (ndp_sec->i_csid == NAN_CS_SK_CCM_128)
		pos += NAN_KEY_MIC_LEN;
	else
		pos += NAN_KEY_MIC_24_LEN;

	if (WPA_GET_BE16(pos))
		wpa_printf(MSG_DEBUG, "NAN: SEC: TODO: m2 key data");

	/* Verify MIC */
	if (msg->len < 24)
		return -1;
	ret = nan_sec_key_mic_ver(nan, (const u8 *) &msg->mgmt->u,
				  msg->len - 24, key,
				  tptk.kck, tptk.kck_len,
				  ndp_sec->i_csid);
	if (ret)
		return ret;

	/* MIC is verified; save PTK */
	os_memcpy(&ndp_sec->ptk, &tptk, sizeof(tptk));
	forced_memzero(&tptk, sizeof(tptk));

	/* Increment the replay counter here to prevent replays */
	WPA_PUT_BE64(ndp_sec->replaycnt,
		     WPA_GET_BE64(ndp_sec->replaycnt) + 1);
	return 0;
}


static int nan_sec_rx_m3(struct nan_data *nan, struct nan_peer *peer,
			 const struct nan_msg *msg,
			 const struct wpa_eapol_key *key)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	u8 mic[NAN_KEY_MIC_24_LEN];
	u8 *buf;
	u8 mic_len;
	u8 *pos;
	int ret;

	if (peer->ndp_setup.state != NAN_NDP_STATE_CON_RECV) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: Not expecting m3");
		return -1;
	}

	/* Note: Replay counter should have been verified by caller */

	/* Verify the i_nonce did not change */
	if (os_memcmp(key->key_nonce, ndp_sec->i_nonce, WPA_NONCE_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: m3 key nonce mismatch");
		return -1;
	}

	/*
	 * In case of m3, the MIC is calculated over the frame body
	 * concatenated with the authentication token.
	 */
	if (msg->len < 24)
		return -1;
	buf = os_malloc(msg->len - 24 + NAN_AUTH_TOKEN_LEN);
	if (!buf)
		return -ENOBUFS;

	/*
	 * Due to the different MIC size, need to handle the fields starting
	 * with the mic differently
	 */
	pos = (u8 *) (key + 1);
	if (ndp_sec->i_csid == NAN_CS_SK_CCM_128)
		mic_len = NAN_KEY_MIC_LEN;
	else
		mic_len = NAN_KEY_MIC_24_LEN;

	if (WPA_GET_BE16(pos + mic_len))
		wpa_printf(MSG_DEBUG, "NAN: SEC: TODO: m3 key data");

	/* Copy MIC and os_memset it */
	os_memcpy(mic, pos, mic_len);
	os_memset(pos, 0, mic_len);
	os_memcpy(buf, ndp_sec->auth_token, NAN_AUTH_TOKEN_LEN);
	os_memcpy(buf + NAN_AUTH_TOKEN_LEN, (const u8 *) &msg->mgmt->u,
		  msg->len - 24);

	ret = nan_crypto_key_mic(buf, msg->len - 24 + NAN_AUTH_TOKEN_LEN,
				 ndp_sec->ptk.kck, ndp_sec->ptk.kck_len,
				 ndp_sec->i_csid, pos);
	os_free(buf);

	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: m3 MIC calculation failed");
		return ret;
	}

	if (os_memcmp_const(mic, pos, mic_len) != 0) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: m3 MIC verification failed");
		return -1;
	}

	forced_memzero(mic, sizeof(mic));

	/* Save replay counter */
	os_memcpy(ndp_sec->replaycnt, key->replay_counter,
		  sizeof(key->replay_counter));
	return 0;
}


static int nan_sec_rx_m4(struct nan_data *nan, struct nan_peer *peer,
			 const struct nan_msg *msg,
			 const struct wpa_eapol_key *key)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	u8 *pos = (u8 *) (key + 1);
	int ret;

	if (peer->ndp_setup.state != NAN_NDP_STATE_DONE) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: Not expecting m4");
		return -1;
	}

	/* Note: replay counter should have been verified by caller */

	/*
	 * Due to the different MIC size, need to handle the fields starting
	 * with the mic differently
	 */
	if (ndp_sec->i_csid == NAN_CS_SK_CCM_128)
		pos += NAN_KEY_MIC_LEN;
	else
		pos += NAN_KEY_MIC_24_LEN;

	if (WPA_GET_BE16(pos))
		wpa_printf(MSG_DEBUG, "NAN: SEC: TODO: m4 key data");

	/* Verify MIC */
	if (msg->len < 24)
		return -1;
	ret = nan_sec_key_mic_ver(nan, (const u8 *) &msg->mgmt->u,
				  msg->len - 24, key,
				  ndp_sec->ptk.kck, ndp_sec->ptk.kck_len,
				  ndp_sec->i_csid);
	if (ret)
		return ret;

	/* Increment the replay counter here to prevent replays */
	WPA_PUT_BE64(ndp_sec->replaycnt,
		     WPA_GET_BE64(ndp_sec->replaycnt) + 1);

	/* Security negotiation done */
	return 0;
}


/**
 * nan_sec_rx - Handle security context for Rx frames
 * @nan: NAN module context from nan_init()
 * @peer: Peer from which the original message was received
 * @msg: Parsed NAN Action frame
 * Returns: 0 on success, negative on failure
 */
int nan_sec_rx(struct nan_data *nan, struct nan_peer *peer,
	       struct nan_msg *msg)
{
	struct nan_ndp_setup *ndp_setup = &peer->ndp_setup;
	struct nan_ndp_sec *ndp_sec = &ndp_setup->sec;
	struct wpa_eapol_key *key;
	struct nan_shared_key *shared_key_desc;
	size_t shared_key_desc_len;
	u16 info, desc;
	size_t total_len;
	u8 instance_id, cipher, capab, gtk_csid;
	u8 *pos;
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: SEC: NDP security Rx");
	nan_sec_dump(nan, peer);

	if (!ndp_sec->present) {
		if (!ndp_sec->valid)
			return 0;

		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: NDP with security but present=0");
		return -1;
	}

	shared_key_desc = (struct nan_shared_key *) msg->attrs.shared_key_desc;
	shared_key_desc_len = msg->attrs.shared_key_desc_len;

	/* Shared key descriptor mandatory in all messages */
	if (!shared_key_desc || !shared_key_desc_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: No shared key descriptor attribute");
		return -1;
	}

	/*
	 * As the shared key type depends on the cipher suite negotiated, need
	 * to get the cipher suite to validate the proper length of the
	 * descriptor.
	 */
	if (msg->oui_subtype == NAN_SUBTYPE_DATA_PATH_REQUEST ||
	    msg->oui_subtype == NAN_SUBTYPE_DATA_PATH_RESPONSE) {
		if (nan_sec_parse_csia(msg->attrs.cipher_suite_info,
				       msg->attrs.cipher_suite_info_len,
				       &instance_id, &capab, &cipher,
				       &gtk_csid)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Missing/bad cipher suite attribute");
			return -1;
		}
	} else {
		cipher = ndp_sec->i_csid;
	}

	key = (struct wpa_eapol_key *) shared_key_desc->key;
	pos = (u8 *) (key + 1);

	total_len = sizeof(*key) + 2;

	if (cipher == NAN_CS_SK_CCM_128) {
		if (shared_key_desc_len <
		    sizeof(struct nan_shared_key) + sizeof(*key) +
		    NAN_KEY_MIC_LEN + 2) {
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Shared key descriptor too small");
			return -1;
		}

		total_len += NAN_KEY_MIC_LEN +
			WPA_GET_BE16(pos + NAN_KEY_MIC_LEN);

		if (total_len >
		    (shared_key_desc_len - sizeof(struct nan_shared_key))) {
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Invalid shared key: payload len");
			return -1;
		}
	} else {
		if (shared_key_desc_len <
		    (sizeof(struct nan_shared_key) + sizeof(*key) +
		     NAN_KEY_MIC_24_LEN + 2)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Shared key (24) descriptor too small");
			return -1;
		}

		total_len += NAN_KEY_MIC_24_LEN +
			WPA_GET_BE16(pos + NAN_KEY_MIC_24_LEN);

		if (total_len >
		    (shared_key_desc_len - sizeof(struct nan_shared_key))) {
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Invalid shared key (24): payload len");
			return -1;
		}
	}

	/*
	 * Note: Only the fields before the MIC are accessed in the function, so
	 * it is safe to continue with the key pointer.
	 */

	/* Note: According to the NAN specification the following fields should
	 * be ignored:
	 * key->len: as the key length is derived from the cipher suite.
	 * key->iv: not needed for AES Key WRAP
	 * key->rsc: to avoid implicit assumption of a single GTK.
	 */
	if (key->type != NAN_KEY_DESC) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Invalid shared key: key descriptor=0x%x",
			   key->type);
		return -1;
	}

	info = WPA_GET_BE16(key->key_info);

	/* Discard EAPOL-Key frames with an unknown descriptor version */
	desc = info & WPA_KEY_INFO_TYPE_MASK;
	if (desc != WPA_KEY_INFO_TYPE_AKM_DEFINED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Invalid shared key: invalid key version=0x%x",
			   desc);
		return -1;
	}

	if (ndp_sec->replaycnt_ok &&
	    WPA_GET_BE64(key->replay_counter) <
	    WPA_GET_BE64(ndp_sec->replaycnt)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Replay counter did not increase");
		return -1;
	}

	if (info & WPA_KEY_INFO_REQUEST) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Invalid shared key: key request not supported");
		return -1;
	}

	if (!(info & WPA_KEY_INFO_KEY_TYPE)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Invalid shared key: group handshake not supported");
		return -1;
	}

	switch (msg->oui_subtype) {
	case NAN_SUBTYPE_DATA_PATH_REQUEST:
		if (!(info & WPA_KEY_INFO_ACK))
			return -1;

		ndp_sec->i_capab = capab;
		ndp_sec->i_csid = cipher;
		ndp_sec->i_instance_id = instance_id;
		ret = nan_sec_rx_m1(nan, peer, msg, key);
		break;
	case NAN_SUBTYPE_DATA_PATH_RESPONSE:
		if (!(info & WPA_KEY_INFO_MIC))
			return -1;

		ndp_sec->r_capab = capab;
		ndp_sec->r_csid = cipher;
		ndp_sec->r_instance_id = instance_id;
		ret = nan_sec_rx_m2(nan, peer, msg, key);
		break;
	case NAN_SUBTYPE_DATA_PATH_CONFIRM:
		if (!(info & WPA_KEY_INFO_MIC) ||
		    !(info & WPA_KEY_INFO_ACK) ||
		    !(info & WPA_KEY_INFO_SECURE))
			return -1;
		ret = nan_sec_rx_m3(nan, peer, msg, key);
		break;
	case NAN_SUBTYPE_DATA_PATH_KEY_INSTALL:
		if (!(info & WPA_KEY_INFO_MIC) ||
		    !(info & WPA_KEY_INFO_SECURE))
			return -1;
		ret = nan_sec_rx_m4(nan, peer, msg, key);
		break;
	default:
		wpa_printf(MSG_DEBUG, "NAN: SEC: Invalid frame OUI subtype");
		return -1;
	}

	if (ret)
		return ret;

	instance_id = shared_key_desc->publish_id;
	if (ndp_sec->i_instance_id && instance_id &&
	    ndp_sec->i_instance_id != instance_id) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Mismatch instance ID in shared key descriptor");
		return -1;
	}

	return 0;
}


/*
 * nan_sec_add_m1_attrs - Add security attributes to NAN message 1
 * @nan: NAN module context from nan_init()
 * @peer: Peer which is the recipient of the message
 * @buf: Buffer to which the attribute should be added
 * Returns: 0 on success, negative on failure
 *
 * In addition to building the attributes, the function also initializes the
 * security context for the NDP security exchange. Assumes that the following
 * are already set:
 * - initiator CSID
 * - PMK
 * - NDP puslish ID
 * - initiator address
 * - peer_nmi
 */
static int nan_sec_add_m1_attrs(struct nan_data *nan, struct nan_peer *peer,
				struct wpabuf *buf)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	struct wpa_eapol_key *key;
	struct nan_cipher_suite cs;
	u16 info;
	size_t key_len = sizeof(struct wpa_eapol_key) + 2;
	int ret;

	if (ndp_sec->i_csid == NAN_CS_SK_CCM_128)
		key_len += NAN_KEY_MIC_LEN;
	else if (ndp_sec->i_csid == NAN_CS_SK_GCM_256)
		key_len += NAN_KEY_MIC_24_LEN;
	else
		return -1;

	/* Initialize the initiator security state */
	os_get_random(ndp_sec->i_nonce, sizeof(ndp_sec->i_nonce));
	ndp_sec->i_capab = 0;
	ndp_sec->i_instance_id = peer->ndp_setup.publish_inst_id;

	/* Compute the PMKID */
	ret = nan_crypto_calc_pmkid(ndp_sec->pmk,
				    nan->cfg->nmi_addr,
				    peer->nmi_addr,
				    peer->ndp_setup.service_id,
				    ndp_sec->i_csid, ndp_sec->i_pmkid);
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: Failed to compute PMKID (m1)");
		return ret;
	}

	/* Cipher suite information */
	cs.csid = ndp_sec->i_csid;
	cs.instance_id = ndp_sec->i_instance_id;
	nan_add_csia(buf, ndp_sec->i_capab, 1, &cs);

	/* Security context information */
	wpabuf_put_u8(buf, NAN_ATTR_SCIA);
	wpabuf_put_le16(buf, sizeof(struct nan_sec_ctxt) + PMKID_LEN);

	wpabuf_put_le16(buf, PMKID_LEN);
	wpabuf_put_u8(buf, NAN_SEC_CTX_TYPE_ND_PMKID);
	wpabuf_put_u8(buf, ndp_sec->i_instance_id);
	wpabuf_put_data(buf, ndp_sec->i_pmkid, PMKID_LEN);

	/* Shared key descriptor */
	wpabuf_put_u8(buf, NAN_ATTR_SHARED_KEY_DESCR);
	wpabuf_put_le16(buf, sizeof(struct nan_shared_key) + key_len);
	wpabuf_put_u8(buf, ndp_sec->i_instance_id);

	key = (struct wpa_eapol_key *) wpabuf_put(buf, key_len);
	os_memset(key, 0, key_len);

	key->type = NAN_KEY_DESC;
	info = WPA_KEY_INFO_TYPE_AKM_DEFINED | WPA_KEY_INFO_KEY_TYPE |
		WPA_KEY_INFO_ACK;
	WPA_PUT_BE16(key->key_info, info);

	/* Copy the initiator nonce */
	os_memcpy(key->key_nonce, ndp_sec->i_nonce, WPA_NONCE_LEN);

	/* Key length is zero (it can be deduced from the cipher suite) */

	/* Initialize replay counter */
	WPA_PUT_BE64(ndp_sec->replaycnt, 1ULL);
	os_memcpy(key->replay_counter, ndp_sec->replaycnt,
		  sizeof(key->replay_counter));
	ndp_sec->replaycnt_ok = true;

	ndp_sec->valid = true;
	return 0;
}


/*
 * nan_sec_add_m2_attrs - Add security attributes to NAN message 2
 * @nan: NAN module context from nan_init()
 * @peer: Peer which is the recipient of the message
 * @buf: Buffer to which the attribute should be added
 * Returns: 0 on success, negative on failure
 */
static int nan_sec_add_m2_attrs(struct nan_data *nan, struct nan_peer *peer,
				struct wpabuf *buf)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	struct wpa_eapol_key *key;
	struct nan_cipher_suite cs;
	u16 info;
	size_t key_len;

	key_len = sizeof(struct wpa_eapol_key) + 2;
	if (ndp_sec->i_csid == NAN_CS_SK_CCM_128)
		key_len += NAN_KEY_MIC_LEN;
	else if (ndp_sec->i_csid == NAN_CS_SK_GCM_256)
		key_len += NAN_KEY_MIC_24_LEN;
	else
		return -1;

	/* Cipher suite information */
	cs.csid = ndp_sec->r_csid;
	cs.instance_id = ndp_sec->r_instance_id;
	nan_add_csia(buf, ndp_sec->r_capab, 1, &cs);

	/* Security context information */
	wpabuf_put_u8(buf, NAN_ATTR_SCIA);
	wpabuf_put_le16(buf, sizeof(struct nan_sec_ctxt) + PMKID_LEN);

	wpabuf_put_le16(buf, PMKID_LEN);
	wpabuf_put_u8(buf, NAN_SEC_CTX_TYPE_ND_PMKID);
	wpabuf_put_u8(buf, ndp_sec->r_instance_id);
	wpabuf_put_data(buf, ndp_sec->r_pmkid, PMKID_LEN);

	if (peer->ndp_setup.status == NAN_NDP_STATUS_REJECTED)
		return 0;

	/* Shared key descriptor */
	wpabuf_put_u8(buf, NAN_ATTR_SHARED_KEY_DESCR);
	wpabuf_put_le16(buf, sizeof(struct nan_shared_key) + key_len);
	wpabuf_put_u8(buf, ndp_sec->r_instance_id);

	key = (struct wpa_eapol_key *) wpabuf_put(buf, key_len);
	os_memset(key, 0, key_len);

	key->type = NAN_KEY_DESC;
	info = WPA_KEY_INFO_TYPE_AKM_DEFINED | WPA_KEY_INFO_KEY_TYPE |
		WPA_KEY_INFO_MIC;
	WPA_PUT_BE16(key->key_info, info);

	/* Copy the responders's nonce */
	os_memcpy(key->key_nonce, ndp_sec->r_nonce, WPA_NONCE_LEN);

	/*
	 * Key length is zero (it can be deduced from the cipher suite).
	 * No additional data is added.
	 */

	/* Copy replay counter */
	os_memcpy(key->replay_counter, ndp_sec->replaycnt,
		  sizeof(key->replay_counter));
	ndp_sec->replaycnt_ok = true;

	return 0;
}


/*
 * nan_sec_add_key_attrs - Add security key attributes to NAN message
 * @nan: NAN module context from nan_init()
 * @peer: Peer which is the recipient of the message
 * @buf: Buffer to which the attribute should be added
 * @instance_id: Instance ID to use
 * @nonce: Nonce to use
 * @is_ack: Whether to include ACK flag in key info
 * Returns: 0 on success, negative on failure
 */
static int nan_sec_add_key_attrs(struct nan_data *nan, struct nan_peer *peer,
				 struct wpabuf *buf, u8 instance_id,
				 const u8 *nonce, bool is_ack)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	struct wpa_eapol_key *key;
	u16 info;
	size_t key_len = sizeof(struct wpa_eapol_key) + 2;

	if (ndp_sec->i_csid == NAN_CS_SK_CCM_128)
		key_len += NAN_KEY_MIC_LEN;
	else if (ndp_sec->i_csid == NAN_CS_SK_GCM_256)
		key_len += NAN_KEY_MIC_24_LEN;
	else
		return -1;

	/* Shared key descriptor */
	wpabuf_put_u8(buf, NAN_ATTR_SHARED_KEY_DESCR);
	wpabuf_put_le16(buf, sizeof(struct nan_shared_key) + key_len);
	wpabuf_put_u8(buf, instance_id);

	key = (struct wpa_eapol_key *) wpabuf_put(buf, key_len);
	os_memset(key, 0, key_len);

	key->type = NAN_KEY_DESC;

	info = WPA_KEY_INFO_TYPE_AKM_DEFINED | WPA_KEY_INFO_KEY_TYPE |
		WPA_KEY_INFO_MIC | WPA_KEY_INFO_INSTALL | WPA_KEY_INFO_SECURE;
	if (is_ack)
		info |= WPA_KEY_INFO_ACK;

	WPA_PUT_BE16(key->key_info, info);

	os_memcpy(key->key_nonce, nonce, WPA_NONCE_LEN);

	/*
	 * Key length is zero (it can be deduced from the cipher suite).
	 * No additional data is added.
	 *
	 * Copy replay counter. It was already incremented while processing m2
	 * so no need to increment it again.
	 */
	os_memcpy(key->replay_counter, ndp_sec->replaycnt,
		  sizeof(key->replay_counter));
	return 0;
}


/*
 * nan_sec_add_m3_attrs - Add security attributes to NAN message 3
 * @nan: NAN module context from nan_init()
 * @peer: Peer which is the recipient of the message
 * @buf: Buffer to which the attribute should be added
 * Returns: 0 on success, negative on failure
 */
static int nan_sec_add_m3_attrs(struct nan_data *nan, struct nan_peer *peer,
				struct wpabuf *buf)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;

	return nan_sec_add_key_attrs(nan, peer, buf, ndp_sec->i_instance_id,
				     ndp_sec->i_nonce, true);
}


/*
 * nan_sec_add_m4_attrs - Add security attributes to NAN message 4
 * @nan: NAN module context from nan_init()
 * @peer: Peer which is the recipient of the message
 * @buf: Buffer to which the attribute should be added
 * Returns: 0 on success, negative on failure
 */
static int nan_sec_add_m4_attrs(struct nan_data *nan, struct nan_peer *peer,
				struct wpabuf *buf)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;

	return nan_sec_add_key_attrs(nan, peer, buf, ndp_sec->r_instance_id,
				     ndp_sec->r_nonce, false);
}


/**
 * nan_sec_add_attrs - Add security attributes to NAN message
 * @nan: NAN module context from nan_init()
 * @peer: Peer which is the recipient of the message
 * @subtype: Frame subtype
 * @buf: Buffer to which the attribute should be added
 * Returns: 0 on success, negative on failure
 */
int nan_sec_add_attrs(struct nan_data *nan, struct nan_peer *peer,
		      enum nan_subtype subtype, struct wpabuf *buf)
{
	/* NDP establishment is not in progress */
	if (!peer->ndp_setup.ndp)
		return 0;

	wpa_printf(MSG_DEBUG, "NAN: SEC: Add security attributes");
	nan_sec_dump(nan, peer);

	/* No security configuration */
	if (peer->ndp_setup.sec.i_csid != NAN_CS_SK_CCM_128 &&
	    peer->ndp_setup.sec.i_csid != NAN_CS_SK_GCM_256)
		return 0;

	switch (subtype) {
	case NAN_SUBTYPE_DATA_PATH_REQUEST:
		return nan_sec_add_m1_attrs(nan, peer, buf);
	case NAN_SUBTYPE_DATA_PATH_RESPONSE:
		return nan_sec_add_m2_attrs(nan, peer, buf);
	case NAN_SUBTYPE_DATA_PATH_CONFIRM:
		return nan_sec_add_m3_attrs(nan, peer, buf);
	case NAN_SUBTYPE_DATA_PATH_KEY_INSTALL:
		return nan_sec_add_m4_attrs(nan, peer, buf);
	case NAN_SUBTYPE_DATA_PATH_TERMINATION:
		break;
	default:
		return -1;
	}

	return 0;
}


/**
 * nan_sec_init_resp - Initialize security context for responder
 * @nan: NAN module context from nan_init()
 * @peer: Peer with whom the NDP is being established
 * Returns: 0 on success, negative on failure
 *
 * The function initializes the security context for the NDP security
 * exchange for the responder. Assumes that the following re already set:
 * - Initiator CSID
 * - Responder CSID
 * - PMK
 * - NDP publish ID
 * - Initiator address
 * - Responder address
 */
int nan_sec_init_resp(struct nan_data *nan, struct nan_peer *peer)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	struct nan_ndp *ndp = peer->ndp_setup.ndp;
	int ret;

	if (ndp_sec->i_csid != ndp_sec->r_csid)
		return -1;

	/* Initialize the responder's security state */
	os_get_random(ndp_sec->r_nonce, sizeof(ndp_sec->r_nonce));
	ndp_sec->r_capab = 0;
	ndp_sec->r_instance_id = peer->ndp_setup.publish_inst_id;

	if (ndp_sec->i_instance_id != ndp_sec->r_instance_id) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Service instance IDs are different (m2)");
		return -1;
	}

	/* Compute the PMKID */
	ret = nan_crypto_calc_pmkid(ndp_sec->pmk, peer->nmi_addr,
				    nan->cfg->nmi_addr,
				    peer->ndp_setup.service_id,
				    ndp_sec->r_csid, ndp_sec->r_pmkid);
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: SEC: Failed to compute PMKID (m2)");
		return -1;
	}

	/* Sanity check */
	if (os_memcmp(ndp_sec->i_pmkid, ndp_sec->r_pmkid, PMKID_LEN) != 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: m2: Local PMKID differs from remote");
		return -1;
	}

	/* PTK should be derived using the NDI address */
	ret = nan_crypto_pmk_to_ptk(ndp_sec->pmk,
				    ndp->init_ndi, ndp->resp_ndi,
				    ndp_sec->i_nonce, ndp_sec->r_nonce,
				    &ndp_sec->ptk, ndp_sec->i_csid);

	wpa_printf(MSG_DEBUG,
		   "NAN: SEC: Derived PTK for responder (m2). ret=%d",
		   ret);

	return ret;
}


/*
 * nan_sec_pre_tx - Handle security aspects before sending a NDP NAF
 * @nan: NAN module context from nan_init()
 * @peer: Peer with whom the NDP is being established
 * @buf: Buffer holding the NAF body (not including the IEEE 802.11 header)
 * Returns: 0 on success, and a negative error value on failure.
 *
 * Note: The NAF content should not be altered after the function returns,
 * as the function might have signed the frame body, i.e., updated the MIC
 * field.
 */
int nan_sec_pre_tx(struct nan_data *nan, struct nan_peer *peer,
		   struct wpabuf *buf)
{
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	struct nan_attrs attrs;
	struct nan_shared_key *shared_key_desc;
	struct wpa_eapol_key *key;
	u8 *data, *tmp, *mic_ptr;
	size_t len;
	u8 subtype;
	int ret;

	/* NDP establishment is not in progress */
	if (!peer->ndp_setup.ndp ||
	    peer->ndp_setup.status == NAN_NDP_STATUS_REJECTED)
		return 0;

	/* No security configuration */
	if (!ndp_sec->valid)
		return 0;

	wpa_printf(MSG_DEBUG, "NAN: SEC:  NDP setup state=%u (pre Tx)",
		   peer->ndp_setup.state);

	data = wpabuf_mhead_u8(buf);
	len = wpabuf_len(buf);

	if (len < 7) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Buffer is too short=%zu (pre Tx)", len);
		return -1;
	}

	/* The subtype is the 7th octet. See nan_action_build_header() */
	subtype = data[6];

	wpa_printf(MSG_DEBUG, "NAN: SEC: subtype=0x%x (pre Tx)", subtype);

	switch (subtype) {
	case NAN_SUBTYPE_DATA_PATH_REQUEST:
	case NAN_SUBTYPE_DATA_PATH_RESPONSE:
	case NAN_SUBTYPE_DATA_PATH_CONFIRM:
	case NAN_SUBTYPE_DATA_PATH_KEY_INSTALL:
		break;
	default:
		return -1;
	}

	/*
	 * First get a pointer to the shared key descriptor attribute and
	 * validate it.
	 */
	ret = nan_parse_attrs(nan, data + 7, len - 7, &attrs);
	if (ret)
		return ret;

	if (!attrs.shared_key_desc ||
	    attrs.shared_key_desc_len <
	    sizeof(*shared_key_desc) + (sizeof(*key) + 2 + NAN_KEY_MIC_LEN)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: SEC: Invalid shared key descriptor attribute");
		return -1;
	}

	shared_key_desc = (struct nan_shared_key *) attrs.shared_key_desc;
	key = (struct wpa_eapol_key *) shared_key_desc->key;
	mic_ptr = (u8 *) (key + 1);
	nan_attrs_clear(nan, &attrs);

	switch (subtype) {
	case NAN_SUBTYPE_DATA_PATH_REQUEST:
		if (peer->ndp_setup.state != NAN_NDP_STATE_START)
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Request invalid state (pre Tx)");

		/* Save the authentication token for m3. */
		ret = nan_crypto_calc_auth_token(ndp_sec->i_csid, data, len,
						 ndp_sec->auth_token);
		break;
	case NAN_SUBTYPE_DATA_PATH_RESPONSE:
		if (peer->ndp_setup.state != NAN_NDP_STATE_REQ_RECV)
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Pre Tx response invalid state");

		/* Calculate MIC over the frame body. */
		ret = nan_crypto_key_mic(data, len,
					 ndp_sec->ptk.kck,
					 ndp_sec->ptk.kck_len,
					 ndp_sec->i_csid, mic_ptr);
		break;
	case NAN_SUBTYPE_DATA_PATH_CONFIRM:
		if (peer->ndp_setup.state != NAN_NDP_STATE_RES_RECV)
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Confirm invalid state (pre Tx)");

		/*
		 * Calculate MIC over the frame body concatenated with
		 * authentication token.
		 */
		tmp = os_malloc(len + NAN_AUTH_TOKEN_LEN);
		if (!tmp)
			return -1;

		os_memcpy(tmp, ndp_sec->auth_token, NAN_AUTH_TOKEN_LEN);
		os_memcpy(tmp + NAN_AUTH_TOKEN_LEN, data, len);

		ret = nan_crypto_key_mic(tmp, len + NAN_AUTH_TOKEN_LEN,
					 ndp_sec->ptk.kck,
					 ndp_sec->ptk.kck_len,
					 ndp_sec->i_csid, mic_ptr);
		os_free(tmp);
		break;
	case NAN_SUBTYPE_DATA_PATH_KEY_INSTALL:
		if (peer->ndp_setup.state != NAN_NDP_STATE_CON_RECV)
			wpa_printf(MSG_DEBUG,
				   "NAN: SEC: Key install invalid state (pre Tx)");

		/* Calculate MIC over the frame body */
		ret = nan_crypto_key_mic(data, len,
					 ndp_sec->ptk.kck,
					 ndp_sec->ptk.kck_len,
					 ndp_sec->i_csid, mic_ptr);
		break;
	}

	return ret;
}


/*
 * nan_sec_ndp_store_keys - Store the NDP keys after successful NDP
 * establishment
 *
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer for which the NDP was established
 * @peer_ndi: NDI address of the peer for the NDP that was just established
 * @local_ndi: Local NDI address for the NDP that was just established
 *
 * Returns: true if keys were stored, false otherwise
 */
bool nan_sec_ndp_store_keys(struct nan_data *nan, struct nan_peer *peer,
			    const u8 *peer_ndi, const u8 *local_ndi)
{
	struct nan_ndp *ndp = peer->ndp_setup.ndp;
	struct nan_ndp_sec *ndp_sec = &peer->ndp_setup.sec;
	struct nan_peer_sec_info_entry *cur, *next;

	if (!ndp || !ndp_sec->valid || !ndp_sec->i_csid ||
	    peer->ndp_setup.state != NAN_NDP_STATE_DONE)
		return false;

	if (ndp_sec->i_csid != NAN_CS_SK_CCM_128 &&
	    ndp_sec->i_csid != NAN_CS_SK_GCM_256)
		return false;

	dl_list_for_each_safe(cur, next, &peer->info.sec,
			      struct nan_peer_sec_info_entry, list) {
		if (!ether_addr_equal(peer_ndi, cur->peer_ndi) ||
		    !ether_addr_equal(local_ndi, cur->local_ndi))
			continue;

		/*
		 * The security configuration should be updated if it is
		 * stronger than the existing one or equal in strength. Since
		 * GCM-256 is considered stronger than CCM-128, always update if
		 * it is the current one. Otherwise, update only if the previous
		 * one was CCMP-128.
		 */
		if (ndp_sec->i_csid == NAN_CS_SK_GCM_256 ||
		    cur->csid == NAN_CS_SK_CCM_128)
			goto store;

		return false;
	}

	cur = os_zalloc(sizeof(*cur));
	if (!cur) {
		wpa_printf(MSG_INFO,
			   "NAN: SEC: Failed memory allocation for security info");
		return false;
	}

	dl_list_add(&peer->info.sec, &cur->list);
	os_memcpy(cur->peer_ndi, peer_ndi, ETH_ALEN);
	os_memcpy(cur->local_ndi, local_ndi, ETH_ALEN);

store:
	wpa_printf(MSG_DEBUG, "NAN: SEC: Store security information");

	cur->csid = ndp_sec->i_csid;
	os_memcpy(cur->pmkid, ndp_sec->i_pmkid, PMKID_LEN);
	os_memcpy(cur->pmk, ndp_sec->pmk, PMK_LEN);
	os_memcpy(&cur->ptk, &ndp_sec->ptk, sizeof(cur->ptk));

	return true;
}


int nan_sec_get_tk(struct nan_data *nan, struct nan_peer *peer,
		     const u8 *peer_ndi, const u8 *local_ndi,
		     u8 *tk, size_t *tk_len, enum nan_cipher_suite_id *csid)
{
	struct nan_peer_sec_info_entry *cur;

	dl_list_for_each(cur, &peer->info.sec,
			 struct nan_peer_sec_info_entry, list) {
		if (!ether_addr_equal(peer_ndi, cur->peer_ndi) ||
		    !ether_addr_equal(local_ndi, cur->local_ndi))
			continue;

		os_memcpy(tk, &cur->ptk.tk, cur->ptk.tk_len);
		*tk_len = cur->ptk.tk_len;
		*csid = cur->csid;
		return 0;
	}

	return -1;
}
