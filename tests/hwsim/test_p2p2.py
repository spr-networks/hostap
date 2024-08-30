# Test cases for Wi-Fi Direct R2 features like unsynchronized service discovery
# (P2P USD), Bootstrapping and Pairing.
# Copyright (c) 2024, Qualcomm Innovation Center, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

from test_nan_usd import check_nan_usd_capab
from test_pasn import check_pasn_capab

def check_p2p2_capab(dev):
    check_nan_usd_capab(dev)
    check_pasn_capab(dev)

def set_p2p2_configs(dev):
    dev.request("P2P_SET pasn_type 3")
    dev.request("P2P_SET supported_bootstrapmethods 6")
    dev.request("P2P_SET pairing_setup 1")
    dev.request("P2P_SET pairing_cache 1")
    dev.request("P2P_SET pairing_verification 1")

def test_p2p_usd_publish_invalid_param(dev):
    """P2P USD Publish with invalid parameters"""
    check_p2p2_capab(dev[0])

    # Both solicited and unsolicited disabled is invalid
    cmd = "NAN_PUBLISH service_name=_test solicited=0 unsolicited=0 p2p=1"
    id0 = dev[0].request(cmd)
    if "FAIL" not in id0:
        raise Exception("NAN_PUBLISH accepts both solicited=0 and unsolicited=0 with p2p=1")

def test_p2p_usd_publish(dev, apdev):
    """P2P USD Publish"""
    check_p2p2_capab(dev[0])
    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 p2p=1"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_PUBLISH for P2P failed")

    cmd = "NAN_UPDATE_PUBLISH publish_id=" + id0 + " ssi=1122334455"
    if "FAIL" in dev[0].request(cmd):
        raise Exception("NAN_UPDATE_PUBLISH for P2P failed")

    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id0
    if "FAIL" in dev[0].request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    ev = dev[0].wait_event(["NAN-PUBLISH-TERMINATED"], timeout=1)
    if ev is None:
        raise Exception("PublishTerminated event not seen")
    if "publish_id=" + id0 not in ev:
        raise Exception("Unexpected publish_id: " + ev)
    if "reason=user-request" not in ev:
        raise Exception("Unexpected reason: " + ev)

    cmd = "NAN_PUBLISH service_name=_test p2p=1"
    count = 0
    for i in range(256):
        if "FAIL" in dev[0].request(cmd):
            break
        count += 1
    logger.info("Maximum services: %d" % count)
    for i in range(count):
        cmd = "NAN_CANCEL_PUBLISH publish_id=%s" % (i + 1)
        if "FAIL" in dev[0].request(cmd):
            raise Exception("NAN_CANCEL_PUBLISH failed")

        ev = dev[0].wait_event(["NAN-PUBLISH-TERMINATED"], timeout=1)
        if ev is None:
            raise Exception("PublishTerminated event not seen")

def test_p2p_usd_subscribe(dev, apdev):
    """P2P USD Subscribe"""
    check_p2p2_capab(dev[0])
    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 p2p=1"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")

    ev = dev[0].wait_event(["NAN-SUBSCRIBE-TERMINATED"], timeout=1)
    if ev is None:
        raise Exception("SubscribeTerminated event not seen")
    if "subscribe_id=" + id0 not in ev:
        raise Exception("Unexpected subscribe_id: " + ev)
    if "reason=user-request" not in ev:
        raise Exception("Unexpected reason: " + ev)

def test_p2p_usd_match(dev, apdev):
    """P2P USD Publish/Subscribe match"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])
    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 p2p=1"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=5 p2p=1"
    id0 = dev[1].request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    # Check for publisher and subscriber functionality to time out
    ev = dev[0].wait_event(["NAN-SUBSCRIBE-TERMINATED"], timeout=5)
    if ev is None:
        raise Exception("Subscribe not terminated")
    ev = dev[1].wait_event(["NAN-PUBLISH-TERMINATED"], timeout=5)
    if ev is None:
        raise Exception("Publish not terminated")

def test_p2p_pairing_password(dev, apdev):
    """P2P Pairing with Password"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair he go_intent=15 p2p2 bstrapmethod=2 auth password=975310123 freq=2437"
    id0 = dev[1].request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth Failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair he go_intent=5 p2p2 bstrapmethod=32 password=975310123"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT Failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    #dev[0].group_form_result(ev)
    dev[0].dump_monitor()

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out(2)")
    #dev[1].group_form_result(ev)

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()

def test_p2p_pairing_opportunistic(dev, apdev):
    """P2P Pairing with Opportunistic"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair he go_intent=15 p2p2 bstrapmethod=1 auth freq=2437"
    id0 = dev[1].request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth Failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair he go_intent=5 p2p2 bstrapmethod=1"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT Failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    #dev[0].group_form_result(ev)
    dev[0].dump_monitor()

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out(2)")
    #dev[1].group_form_result(ev)
    dev[1].wait_sta()

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()

def test_p2p_auto_go_and_client_join(dev, apdev):
    """A new client joining a group using P2P Pairing/Opportunistic"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_GROUP_ADD p2p2"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out(2)")

    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair he go_intent=15 p2p2 bstrapmethod=1 join auth"
    id0 = dev[1].request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair p2p2 join bstrapmethod=1"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    #dev[0].group_form_result(ev)
    dev[0].dump_monitor()

    dev[1].wait_sta()

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()

def test_p2p_auto_go_and_client_join_sae(dev, apdev):
    """A new client joining a group using P2P Pairing/SAE"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_GROUP_ADD p2p2"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out(2)")

    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair he go_intent=15 p2p2 bstrapmethod=2 join auth password=975310123"
    id0 = dev[1].request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair p2p2 join bstrapmethod=32 password=975310123"
    id0 = dev[0].request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    #dev[0].group_form_result(ev)
    dev[0].dump_monitor()

    dev[1].wait_sta()

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()
