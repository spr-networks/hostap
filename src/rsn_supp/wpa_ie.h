/*
 * wpa_supplicant - WPA/RSN IE and KDE definitions
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_IE_H
#define WPA_IE_H

struct wpa_sm;

int wpa_gen_wpa_ie(struct wpa_sm *sm, u8 *wpa_ie, size_t wpa_ie_len);
int wpa_gen_wpa_ie_rsn(u8 *rsn_ie, size_t rsn_ie_len,
		       int pairwise_cipher, int group_cipher,
		       int key_mgmt, int mgmt_group_cipher,
		       struct wpa_sm *sm);
int wpa_gen_rsnxe(struct wpa_sm *sm, u8 *rsnxe, size_t rsnxe_len);
u16 rsn_supp_capab(struct wpa_sm *sm);
int wpa_external_auth_add_rsne(struct wpa_sm *sm, u8 *rsne, size_t rsne_len,
			       int akmp, int pairwise_cipher, int group_cipher,
			       int group_mgmt_cipher, u16 rsn_capab,
			       const u8 *pmkid);
u64 wpa_sm_get_rsnxe_capab(struct wpa_sm *sm);
bool security_profile_akm_matches(int profile_num, int key_mgmt);
bool security_profile_has_eppke(const u8 *sp, int ssid_key_mgmt);
const struct security_profile_entry *
security_profile_select(int akmp, int pairwise_cipher,
			bool eap_over_auth, bool eppke,
			const u8 *bitmap, size_t bitmap_len);
int security_profile_build_sta(struct wpa_sm *sm, int selected_profile_num,
			       u8 *buf, size_t buf_len);
int security_profile_build(u16 rsn_capab, const u8 *rsnxe,
			   size_t rsnxe_len, int selected_profile_num,
			   u8 *buf, size_t buf_len);
int security_profile_build_empty(u8 *buf, size_t buf_len);

#endif /* WPA_IE_H */
