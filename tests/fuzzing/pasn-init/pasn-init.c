/*
 * PASN initiator fuzzer
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/defs.h"
#include "common/wpa_common.h"
#include "common/sae.h"
#include "common/ieee802_11_defs.h"
#include "crypto/sha384.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/pmksa_cache.h"
#include "pasn/pasn_common.h"
#include "../fuzzer-common.h"


static int pasn_send_mgmt(void *ctx, const u8 *data, size_t data_len,
			  int noack, unsigned int freq, unsigned int wait)
{
	return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct pasn_data pasn;
	struct wpa_pasn_params_data pasn_data;
	u8 own_addr[ETH_ALEN], bssid[ETH_ALEN];
	struct rsn_pmksa_cache *pmksa;

	wpa_fuzzer_set_debug_level();

	if (os_program_init())
		return 0;

	if (!eloop_init())
		return 0;

	pmksa = pmksa_cache_init(NULL, NULL, NULL, NULL, NULL);
	if (!pmksa)
		goto fail;
	os_memset(&pasn, 0, sizeof(pasn));
	pasn.send_mgmt = pasn_send_mgmt;
	pasn_set_initiator_pmksa(&pasn, pmksa);
	hwaddr_aton("02:00:00:00:00:00", own_addr);
	hwaddr_aton("02:00:00:00:03:00", bssid);
	if (wpas_pasn_start(&pasn, own_addr, bssid, bssid, WPA_KEY_MGMT_PASN,
			    WPA_CIPHER_CCMP, 19, 2412, NULL, 0, NULL, 0,
			    NULL) < 0) {
		wpa_printf(MSG_ERROR, "wpas_pasn_start failed");
		goto fail;
	}

	wpa_pasn_auth_rx(&pasn, data, size, &pasn_data);

fail:
	if (pmksa)
		pmksa_cache_deinit(pmksa);
	wpa_pasn_reset(&pasn);
	eloop_destroy();
	os_program_deinit();

	return 0;
}
