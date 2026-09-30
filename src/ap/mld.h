/*
 * hostapd / MLD related shared defines
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MLD_H
#define MLD_H

struct mld_link_info {
	u8 valid:1;
	u8 nstr_bitmap_len:2;
	u8 local_addr[ETH_ALEN];
	u8 peer_addr[ETH_ALEN];

	u8 nstr_bitmap[2];

	u16 capability;

	u16 status;
	u16 resp_sta_profile_len;
	u8 *resp_sta_profile;
};

struct mld_info {
	bool mld_sta;

	struct ml_common_info {
		u8 mld_addr[ETH_ALEN];
		u16 medium_sync_delay;
		u16 eml_capa;
		u16 mld_capa;
	} common_info;

	struct mld_link_info links[MAX_NUM_MLD_LINKS];
};

#endif /* MLD_H */
