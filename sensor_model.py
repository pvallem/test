#!/usr/bin/env python
"""
Implement sensor model defined in
http://sites/intranet/home/technology/network-flow-sensor-asic

The script implements the flow stats models defined in the specs. The modeling
class FlowTable takes packets in time order, and computes stats. These stats
can be exported in proto format, which can then be used by a testing driver to
validate actual sensor outputs.  """

__author__ = "Ashutosh Kulshreshtha <ashutkul@tetrationanalytics.com>"

import hashlib
import logging
import random
import struct
import time
import zlib

import gflags
import google.protobuf  # pylint: disable=F0401,E0611

# pylint: disable=W0403
from dpkt_hack import dpkt
import flow_ac_int
import flow_info_pb2
import sensor_config_pb2
import sensor_util


FLAGS = gflags.FLAGS

gflags.DEFINE_integer('simulation_start_time',
                      time.mktime((2014, 1, 1, 0, 0, 0, 0, 0, -1)) * 1e6,
                      'Start time for the sensor.')

gflags.DEFINE_integer('export_interval_microseconds', 100000,
                      'Sensor export interval in microseconds')

gflags.DEFINE_integer('num_collectors', 1,
                      'Number of colllectors.')

gflags.DEFINE_boolean('asic_mode', True,
                      'Whether the golden model should run in the ASIC mode.')

gflags.DEFINE_boolean('check_tcam_policy_match', False,
                      'If True, crash on packet without matching TCAM policy.')


class SensorError(Exception):
    """Sensor model exceptions, like unsupported protocols."""
    pass


class SensorStatsNotExported(Exception):
    """Sensor error, indicating uncollected stats from previous interval."""
    pass


def DefaultSensorConfig():
    """Sensor Config parameters."""
    sensor_config = sensor_config_pb2.SensorConfig()
    sensor_config.sensor_start_time = FLAGS.simulation_start_time
    sensor_config.export_interval = FLAGS.export_interval_microseconds

    sensor_clock = sensor_config.clock
    # Assume cycle and tick both to be 1 us, which requires no shift.
    sensor_clock.cycle_bitshifts_for_tick = 0
    sensor_clock.export_interval_in_ticks = sensor_config.export_interval

    sensor_clock.tick_bitshifts_for_burst = 10

    sensor_config.tcp_header_length_bins.extend(
        [6, 7, 8, 9, 10, 12, 14])

    # TODO(ashu): Confirm whether these are TCP payload lengths or
    # include TCP header. Does this include IP header?
    sensor_config.tcp_payload_length_bins.extend(
        [1, 10, 100, 200, 500, 1000, 1500, 2000, 3000, 5000, 7000])
    sensor_config.receiver_window_length_bins.extend(
        [1, 10, 100, 1000, 10000])
    sensor_config.tcp_sequence_number_plus_offset = 5000
    sensor_config.tcp_sequence_number_minus_offset = 5000
    sensor_config.num_collectors = FLAGS.num_collectors

    return sensor_config


class PolicyHelper(object):
    """Helper for policy application."""

    # Define proto here for shortcut.
    proto = sensor_config_pb2.TcamPolicy

    ACTION_DISPOSITION_MAP = {
        proto.SECURITY_FAILED: 'port_security_failed',
        proto.DENY: 'deny_policy',
        proto.REDIRECT: 'redirect_service',
        proto.COPY: 'copy_service',
        proto.APPLIED: 'policy_applied',
    }

    def __init__(self, sensor_config):
        """Initialize analytics and policy maps."""
        self.tenant_analytics_map = {}
        for analytics in sensor_config.tenant_policy:
            self.tenant_analytics_map[analytics.tenant_id] =\
                analytics.analytics_type

        self.tep_analytics_map = {}
        for tep in sensor_config.tep_map:
            self.tep_analytics_map[tep.tep_id] = tep.analytics_type

        self.iface_analytics_map = {}
        for iface in sensor_config.iface_map:
            self.iface_analytics_map[iface.switch_port] = iface.analytics_type

        self.tcam_policies = sensor_config.tcam_policy


    def is_match(self, key, policy):
        """Return, if the policy matches the flow. If a policy field is
        not set, it is considered a match."""

        def match_value(mask, value1, value2):
            """Match values with mask."""
            if isinstance(mask, int):
                return (mask & value1) == (mask & value2)
            if isinstance(mask, (bytes, str)):
                if len(mask) != len(value1) or len(mask) != len(value2):
                    raise ValueError("len(mask) != len(value)")
                assert len(mask) == len(value1) and len(mask) == len(value2)
                for i in range(len(mask)):
                    if not match_value(ord(mask[i]),
                                       ord(value1[i]), ord(value2[i])):
                        return False
                return True
            assert "match does not support type %s" % type(mask)

        mask = policy.tcam.mask
        value = policy.tcam.value
        if value.key_type != key.key_type:
            return False

        if mask.HasField("proto") and\
                not match_value(mask.proto, value.proto, key.proto):
            return False
        if mask.HasField("tenant_id") and\
                not match_value(mask.tenant_id,
                                value.tenant_id, key.tenant_id):
            return False
        if mask.HasField("src_address") and\
                not match_value(mask.src_address,
                                value.src_address, key.src_address):
            return False
        if mask.HasField("dst_address") and\
                not match_value(mask.dst_address,
                                value.dst_address, key.dst_address):
            return False
        if mask.HasField("src_port") and\
                not match_value(mask.src_port, value.src_port, key.src_port):
            return False
        if mask.HasField("dst_port") and\
                not match_value(mask.dst_port, value.dst_port, key.dst_port):
            return False
        return True

    def policy_action(self, flow_key):
        """Return action from the matching policy."""
        for p in self.tcam_policies:
            if p.action == self.proto.UNDEFINED:
                continue
            try:
                if self.is_match(flow_key, p):
                    return p.action
            except ValueError:
                if FLAGS.check_tcam_policy_match:
                    assert False, "\n".join([str(s)
                                            for s in self.tcam_policies])
        return None

    @classmethod
    def collect(cls, analytics_type):
        """Combine collect/no-collect."""
        if analytics_type is None:
            # Consider default to be FULL analytics.
            return True
        return analytics_type != sensor_config_pb2.Analytics.NO_ANALYTICS

    @classmethod
    def valid(cls, analytics_type):
        """Combine full/concise analytics."""
        if analytics_type is None:
            # Consider default to be FULL analytics.
            return True
        return analytics_type == sensor_config_pb2.Analytics.FULL

    @classmethod
    def analytics_type(cls, collect, valid):
        """Combine collect and valid to analytics type."""
        if not collect:
            return sensor_config_pb2.Analytics.NO_ANALYTICS
        elif valid:
            return sensor_config_pb2.Analytics.FULL
        return sensor_config_pb2.Analytics.CONCISE

    @classmethod
    def derive_analytics(cls, iface_analytics, tep_analytics,
                         tenant_analytics):
        """Combine port/tep/tenant analytics for final analytics."""
        final_collect = cls.collect(iface_analytics) and (
            cls.collect(tep_analytics) or cls.collect(tenant_analytics))
        final_valid = cls.valid(iface_analytics) and (
            cls.valid(tep_analytics) or cls.valid(tenant_analytics))
        return cls.analytics_type(final_collect, final_valid)

    def lu_analytics_type(self, tenant_id, tep, switch_port):
        """Analytics type based only on tep and switch port."""
        iface_analytics = self.iface_analytics_map.get(switch_port, None)
        tep_analytics = self.tep_analytics_map.get(tep, None)
        tenant_analytics = self.tenant_analytics_map.get(tenant_id, None)
        combined = sensor_config_pb2.Analytics()
        combined.analytics_type = self.derive_analytics(
            iface_analytics, tep_analytics, tenant_analytics)
        return combined

    def analytics(self, flow_key, tep, switch_port):
        """Return analytics type required from matching policy."""
        tcam = None
        for p in self.tcam_policies:
            if not p.HasField('analytics'):
                continue
            if self.is_match(flow_key, p):
                tcam = p.analytics
                break
        lu_analytics = self.lu_analytics_type(flow_key.tenant_id, tep,
                                              switch_port)
        if not tcam:
            return lu_analytics

        if tcam.collect_override and tcam.analytics_vld_override:
            return tcam

        # If override bits are not set, reset TCAM values.
        lu_collect = self.collect(lu_analytics.analytics_type)
        lu_valid = self.valid(lu_analytics.analytics_type)
        tcam_collect = self.collect(tcam.analytics_type)
        tcam_valid = self.valid(tcam.analytics_type)
        if not tcam.collect_override:
            tcam_collect = lu_collect
        if not tcam.analytics_vld_override:
            tcam_valid = lu_valid
        tcam.analytics_type = self.analytics_type(tcam_collect, tcam_valid)
        return tcam

    def packet_disposition(self, flow_key, pd):
        """Iterate over all policies, and return action from matching one."""
        action = self.policy_action(flow_key)
        if action:
            field_name = PolicyHelper.ACTION_DISPOSITION_MAP[action]
            setattr(pd, field_name, 1)


class NetworkConfig(object):
    """Class to help with network config lookups."""
    def __init__(self, sensor_config):
        """Initialize network config with data provided in sensor_config."""
        self.config = sensor_config

    def get_iface(self, iface_name=None, switch_port=None):
        """Return full iface proto based on interface."""
        assert iface_name is not None or switch_port is not None
        for iface in self.config.iface_map:
            if iface_name is not None and iface.iface_name == iface_name:
                return iface
            if switch_port is not None and iface.switch_port == switch_port:
                return iface
        return sensor_config_pb2.InterfaceMap()

    def get_tenant_id(self, iface_name=None, switch_port=None):
        """Get tenant id based on interface."""
        assert iface_name or switch_port
        for iface in self.config.iface_map:
            if iface_name and iface.iface_name == iface_name:
                return iface.tenant_id
            if switch_port and iface.switch_port == switch_port:
                return iface.tenant_id
        return None


    def get_tep(self, tenant_id, host_address):
        """Get Tunnel End Point (TEP) id, for host_address given tenant."""
        for tep in self.config.tep_map:
            for end_host in tep.end_hosts:
                if end_host.tenant_id == tenant_id and\
                        end_host.host_address == host_address:
                    return tep.tep_id
        return None


def add_saturate(current, to_add, bits):
    """Add value and saturate at given bits."""
    assert bits <= 64
    if current >= ((0x1 << bits) - 1 - to_add):
        return (0x1 << bits) - 1
    return current + to_add


def fill_parsed_packet(eth, packet, timestamp=None, iface_name=None,
                       switch_port=None):
    """Given ethernet frame, build packet proto."""
    assert isinstance(eth, dpkt.ethernet.Ethernet)
    assert isinstance(packet, sensor_config_pb2.Packet)
    packet.timestamp = timestamp
    if iface_name is not None:
        packet.iface = iface_name
    if switch_port is not None:
        packet.switch_port = switch_port

    # Rather than directly using eth object, pack and unpack, because many
    # of the dpkt computations (like TCP cksum) happen during pack.
    eth = dpkt.ethernet.Ethernet(str(eth))

    # Ethernet frame without FCS must be at least 60 bytes. Add padding
    # otherwise.
    eth_str = str(eth)
    if len(eth_str) < 60:
        eth_str += '\x00' * (60 - len(eth_str))
    # FCS includes padding and is added in little-endian!
    fcs = zlib.crc32(eth_str) & 0xffffffff
    packet.pcap = eth_str + struct.pack("<L", fcs)
    packet.l2_len = len(packet.pcap)

    if eth.type in [dpkt.ethernet.ETH_TYPE_IP,
                    dpkt.ethernet.ETH_TYPE_IP6]:
        ip = eth.data
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            packet.ip_header_length = len(ip.pack_hdr() + ip.opts)
            packet.ip_fragment_offset_non_zero = \
                (ip.off & dpkt.ip.IP_OFFMASK) > 0
            packet.ip_mf = (ip.off & dpkt.ip.IP_MF) > 0
            packet.ip_id = ip.id
            if ip.len != len(ip):
                packet.parser_error = True
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            packet.ip_header_length = len(ip.pack_hdr() + ip.headers_str())
            # Use len(str(ip)) rather than len(ip), because dpkt does not
            # include extension headers in len(ip).
            if ip.plen != len(str(ip)) - 40:
                packet.parser_error = True
            for value in ip.extension_hdrs.values():
                if value and isinstance(value, dpkt.ip6.IP6FragmentHeader):
                    packet.ip_fragment_offset_non_zero = value.frag_off > 0
                    packet.ip_mf = value.m_flag > 0
                    packet.ip_id = value.id

        if isinstance(ip.data, dpkt.tcp.TCP):
            packet.tcp_receive_window = ip.data.win
            packet.tcp_data_offset = ip.data.off
            # ACK num is set in parser, even if ACK bit is not set.
            # if ip.data.flags & dpkt.tcp.TH_ACK:
            packet.tcp_ack_num = ip.data.ack

        if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            packet.l4_payload_len = len(ip.data.data)
        if isinstance(ip.data, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
            packet.icmp_checksum = ip.data.sum


        # L4 payload length could potentially be taken from fragmented
        #  packets in TCP, but ASIC parser does not do this. So matching
        # it.
#         if isinstance(ip.data, str) and ip.p == 6:
            # packet.tcp_receive_window =  0
            # packet.tcp_data_offset = 0
            # packet.tcp_ack_num = 0
            # packet.l4_payload_len = 0 # len(ip.data)


def hashstr(val):
    """Return hash value in hex string."""
    if len(val) < 8: # Return small key as it, typically in unittests.
        return val
    # Remove 0x prefix and L suffix.
    return hex(hash(val) & 0xffffffffffffffff)[2:-1]

class FlowTableEntry(object):
    """A single entry in the flow table."""
    def __init__(self, column, key, size, valid=True):
        self.column = column
        self.key = key
        self.size = size
        self.valid = valid

    def __lt__(self, other):
        """For sorting."""
        if self.valid != other.valid:
            return self.valid > other.valid
        return self.column < other.column

    def __repr__(self):
        """Readable item."""
        valid_str = {True: "*", False: ""}
        return "%d-%d:%s%s" % (self.column, self.column + self.size - 1,
                               hashstr(self.key), valid_str[self.valid])


class AsicFlowTableBank(object):
    """Class to mimic ASIC flow table bank containing 4 cells."""
    NUM_COLUMNS = 4

    def __init__(self, bank):
        """Initialize empty row."""
        self.bank = bank
        self.flow_items = []

    def __repr__(self):
        """Readable row."""
        return " ".join([repr(k) for k in self.flow_items])

    def sort_items(self):
        """Sort the items."""
        self.flow_items.sort()
        col = 0
        for k in self.flow_items:
            k.column = col
            col += k.size

    def get_size(self):
        """Get total size of valid items."""
        return sum([k.size for k in self.flow_items if k.valid])

    def get_item(self, key):
        """Return the column for the key."""
        # If item is already in the table, return the column.
        for item in self.flow_items:
            if item.key == key:
                return item
        return None

    def insert_item(self, item):
        """Insert item in the bank at given column. Replace ghost items, if
        needed."""
        # We may have to remove some invalid items,
        remove_items = []
        # start and end (inclusive) of indices in flow_items that need to be
        # removed.
        (remove_index_start, remove_index_end) = (None, None)
        last_column_removed = None
        # print "Inserting item " + repr(item) + " in table " + repr(self)
        for (index, k) in enumerate(self.flow_items):
            # If the range of current item overlaps with the range of item
            # present, it should be removed.
            if (k.column + k.size - 1 >= item.column and
                    k.column <= item.column + item.size - 1):
                # print "Removing item " + repr(k) + " from table ",
                # print repr(self) + " to insert " + repr(item)
                assert not k.valid, "Removing valid item " + repr(k) +\
                    " from table " + repr(self) + " to insert " + repr(item)
                if remove_index_start is None:
                    remove_index_start = index
                remove_index_end = index
                last_column_removed = k.column + k.size
                remove_items.append(k.key)

        if remove_items:
            insert_array = [item]
            # If the new item doesn't completely cover the removed items, we
            # may have to add a dummy item.
            dummy_size = last_column_removed - (item.column + item.size)
            if dummy_size > 0:
                dummy = FlowTableEntry(item.column + item.size, "dummy",
                                       dummy_size, False)
                insert_array.append(dummy)
            self.flow_items = self.flow_items[0 : remove_index_start] +\
                insert_array + self.flow_items[remove_index_end + 1:]
        else:
            # print "No items to remove"
            self.flow_items.append(item)
        # print "After inserting table ", repr(self)

        # Remove "dummy" from remove_items, before returning..
        remove_items = [r for r in remove_items if r != "dummy"]
        return (item.column, remove_items)


    def add_key(self, key, size):
        """Add a key, possibly existing. Return column index, where the
        key exists or newly added. The method returns (column, ghost_key_list)
        tuple. The ghost items are those that adding this key pushed out.
        If row is full, column = -1."""
        item = self.get_item(key)
        if item:
            if not item.valid:
                item.valid = True
                self.sort_items()
                item = self.get_item(key)
            return (item.column, [])

        if self.get_size() + size > self.NUM_COLUMNS:
            logging.debug("Can't fit key in the row in ASIC.")
            return (-1, [])

        item = FlowTableEntry(self.get_size(), key, size, True)
        return self.insert_item(item)

    def remove_key(self, key, do_compaction=True):
        """Simply mark the entry invalid. Removal happens during compaction."""
        for k in self.flow_items:
            if k.key == key:
                k.valid = False
                if do_compaction:
                    self.sort_items()
                return


class AsicFlowTableRow(object):
    """Class to mimic ASIC flow table row."""
    NUM_BANKS = 4

    def __init__(self):
        """Initialize empty row."""
        self.banks = [AsicFlowTableBank(i)
                      for i in range(AsicFlowTableRow.NUM_BANKS)]

    def __repr__(self):
        """Readable flow table."""
        return " ".join(["[%s]" % repr(v) for v in self.banks])

    def add_key(self, key, size):
        """Add key to a given row. Returns (column, removed_list)."""
        # First check if the item is already present in the bank.
        for (index, bank) in enumerate(self.banks):
            item = bank.get_item(key)
            if item:
                (col, remove_items) = bank.add_key(key, size)
                assert remove_items == []
                return (index * AsicFlowTableBank.NUM_COLUMNS + col, [])

        # Then add the item to first available bank.
        for (index, bank) in enumerate(self.banks):
            (col, remove_items) = bank.add_key(key, size)
            if col >= 0:
                return (index * AsicFlowTableBank.NUM_COLUMNS + col,
                        remove_items)
        return (-1, [])

    def remove_key(self, key, do_compaction=True):
        """Remove key from given row."""
        for bank in self.banks:
            bank.remove_key(key, do_compaction)

    def get_item(self, key):
        """Get item given key."""
        for bank in self.banks:
            item = bank.get_item(key)
            if item is not None:
                return item
        return None


class AsicFlowTable(object):
    """Class to mimic ASIC flow table behavior."""
    NUM_ROWS = (1 << 12)

    def __init__(self):
        """Initialize the row_index -> AsicFlowTableRow map. We use a map,
        rather than array, because most of the tests will have a sparse
        row fillup."""
        self.rows = {}

    def __repr__(self):
        """Readable flow table."""
        return "\n".join("%d: %s" % (k, v) for (k, v) in self.rows.items())

    def add_key(self, row, key, size):
        """Add key to a given row. Returns (column, removed_list)."""
        if row not in self.rows:
            self.rows[row] = AsicFlowTableRow()
        return self.rows[row].add_key(key, size)

    def remove_key(self, row, key, do_compaction=True):
        """Remove key from given row."""
        if row in self.rows:
            self.rows[row].remove_key(key, do_compaction)

    def get_item(self, row, key):
        """Get item given key in a row."""
        return self.rows[row].get_item(key)


class SingleFlowState(object):
    """Flow state for a single flow."""

    # Consts related to flow table saturation.
    PACKET_COUNT_BITS = 22
    BYTE_COUNT_BITS = 30
    CURRENT_BURST_BITS = 16
    MAX_BURST_BITS = 11
    FLOWLET_COUNT_BITS = 7

    def __init__(self, flow_key, timestamp, sensor_config,
                 interval_start_time, switch_port, analytics=None):
        """Initialize flow state."""
        self._flow_info = flow_info_pb2.FlowInfo()
        self._flow_info.key.CopyFrom(flow_key)

        self._flow_info.key.flow_start_time = timestamp
        self.crc12 = flow_ac_int.flow_key_crc12(flow_key, switch_port)

        # Flow state variables
        self.payload_len = 0
        self.last_packet_timestamp = None

        self.current_burst_index = 0
        self.current_burst = 0
        self.max_burst_index = 0
        self.max_burst = 0

        self.num_flowlets = 0
        self.packet_count = 0
        self.byte_count = 0

        self.interval_start_time = interval_start_time

        # Config parameters, read from sensor_config
        self.burst_interval = 0
        self.current_burst_bitshifts = 0
        self.additional_max_burst_bitshifts = 0
        self.flowlet_pause = 0

        # Cache analytics requirements for the flow.
        self._analytics = sensor_config_pb2.Analytics()
        if analytics:
            self._analytics.CopyFrom(analytics)
        self.analytics_changed = False
        self.sensor_mode = None
        self.update_sensor_config(sensor_config)
    
    def get_analytics(self):
        """Get analytics."""
        return self._analytics
    
    def set_analytics(self, analytics):
        """Set analytics value."""
        # If anaytics value is different from previous value, record it.
        if self._analytics.analytics_type != analytics.analytics_type:
            self.analytics_changed = True
        self._analytics.CopyFrom(analytics)

    # Use property for analytics get/set to take care of the side effects.
    analytics = property(get_analytics, set_analytics)
    
    def __repr__(self):
        """Readable flow state."""
        return str(self._flow_info)

    def update_sensor_config(self, sensor_config):
        """Set parameters from sensor_config."""
        burst_bitshift = sensor_config.clock.tick_bitshifts_for_burst
        self.burst_interval = 0x1 << burst_bitshift
        # self.interval_start_time = sensor_config.sensor_start_time
        self.current_burst_bitshifts = \
            sensor_config.burst.burst_size_bitshifts
        self.additional_max_burst_bitshifts = \
            sensor_config.burst.additional_max_burst_size_bitshifts
        self.flowlet_pause = sensor_config.flowlet_pause_duration
        self.sensor_mode = sensor_config.sensor_mode

    def flow_info_after_export(self, new_interval_start_time):
        """Flow info to be kept after export."""
        # Rather than removing information, we copy relevant fields.
        flow_info_preserved = flow_info_pb2.FlowInfo()
        flow_info_preserved.key.CopyFrom(self._flow_info.key)
        if self._flow_info.HasField("ip_info"):
            if self._flow_info.ip_info.dont_fragment_set:
                flow_info_preserved.ip_info.dont_fragment_set = 1
            if self._flow_info.ip_info.HasField("last_cached_ttl"):
                flow_info_preserved.ip_info.last_cached_ttl = \
                    self._flow_info.ip_info.last_cached_ttl
        if self._flow_info.HasField("tcp_info"):
            tcp_info = self._flow_info.tcp_info
            if tcp_info.HasField("sequence_num"):
                flow_info_preserved.tcp_info.sequence_num =\
                    tcp_info.sequence_num
            # Although, the ack_num should be preserved, ACK flag is not.
            # Current ASIC implementation uses ACK flag before checking
            # ack_num, and thus behaves like ack_num is not preserved.
            if self.sensor_mode !=\
                sensor_config_pb2.SensorConfig.ASIC_SENSOR_MODEL:
                if tcp_info.HasField("ack_num"):
                    flow_info_preserved.tcp_info.ack_num = \
                        tcp_info.ack_num

        # Reset stats.
        self.interval_start_time = new_interval_start_time
        self.last_packet_timestamp = None
        self.current_burst_index = 0
        self.current_burst = 0
        self.max_burst_index = 0
        self.max_burst = 0

        self.num_flowlets = 0
        self.packet_count = 0
        self.byte_count = 0

        self._flow_info = flow_info_preserved

    def new_packet(self, timestamp, l2_bytes, payload_len=None):
        """Update flow state given packet at a timestamp.

        l2_bytes: L2 packet length (inner packet in case of encapsulation).
        payload_bytes: Size of the TCP/UDP payload. Only available in case
            of TCP/UDP packets."""
        if payload_len is not None:
            self.payload_len = payload_len
        else:
            self.payload_len = l2_bytes
        burst_index = (timestamp - self.interval_start_time) / \
            self.burst_interval
        if burst_index != self.current_burst_index:
            self.current_burst_index = burst_index
            self.current_burst = 0
        current_bytes = l2_bytes >> self.current_burst_bitshifts
        self.current_burst = \
            add_saturate(self.current_burst, current_bytes,
                         self.CURRENT_BURST_BITS)
        max_bytes = self.current_burst >> self.additional_max_burst_bitshifts
        if max_bytes > self.max_burst:
            self.max_burst = max_bytes
            self.max_burst_index = burst_index


        # Num flowlets. Saturate after FLOWLET_COUNT_BITS.
        if self.last_packet_timestamp is None or\
                timestamp - self.last_packet_timestamp > self.flowlet_pause:
            self.num_flowlets = \
                add_saturate(self.num_flowlets, 1, self.FLOWLET_COUNT_BITS)

        # print "last time stamp ", self.last_packet_timestamp, "timestamp ",\
        #       timestamp, " num flowlets ", self.num_flowlets

        # Packet count. Saturate.
        self.packet_count = add_saturate(self.packet_count, 1,
                                         self.PACKET_COUNT_BITS)

        # Byte count with saturation.
        self.byte_count = add_saturate(self.byte_count, l2_bytes,
                                       self.BYTE_COUNT_BITS)

        # Cache last packet timestamp for flowlet computation.
        self.last_packet_timestamp = timestamp

    def get_flow_info(self):
        """flow_info getter."""
        return self._flow_info

    def set_flow_info(self, flow_info):
        """flow_info setter. Also set side effects from the flow info."""
        logging.debug("Setting flow info: %s", str(flow_info))
        self.last_packet_timestamp = flow_info.end_time
        if len(flow_info.flow_features) > 0:
            flow_features = flow_info.flow_features[0]
            self.current_burst_index = \
                (flow_info.end_time - self.interval_start_time) / \
                self.burst_interval
            self.current_burst = flow_features.current_burst
            self.max_burst_index = flow_features.max_burst_index
            self.max_burst = flow_features.max_burst

            self.num_flowlets = flow_features.num_flowlets
            self.packet_count = flow_features.packet_count
            self.byte_count = flow_features.byte_count

            self._flow_info = flow_info

    flow_info = property(get_flow_info, set_flow_info)


class FlowTable(object):

    """Maintain flow table and stats that are used in the sensor model.

    The class maintains all flows in an export interval. The stats are indexed
    by flow-key. The class also maintains data like packet lengths and
    bursts/flowlets, which are later used to derive overall stats."""

    # Map of ARP op code to sensor proto.
    ARP_OP_PROTO_MAP = {
        dpkt.arp.ARP_OP_REVREPLY: 248,
        dpkt.arp.ARP_OP_REVREQUEST: 247,
        dpkt.arp.ARP_OP_REQUEST: 249,
        dpkt.arp.ARP_OP_REPLY: 250
    }

    # Consts related to flow table.
    # TODO(ashu): Move this logic to SingleFlowState class.
    RANDOM_PACKET_LEN_BITS = 14

    # Event type fields in the EventDescriptor proto.
    EVENT_TYPES = ['event_type_rtt_seq',
                   'event_type_rtt_ack',
                   'event_type_table_full',
                   'event_type_pkt_value_match',
                   'event_type_mouse_pkt',
                   'event_type_first_pkt',
                   'event_type_export_flow',
                   'event_type_analytics_changed']

    def __init__(self, sensor_config=DefaultSensorConfig(),
                 sensor_mode_cache=True,
                 include_validation=True, sensor_export_callback=None,
                 event_export_callback=None):
        """Initialize various maps.

        Args:
            sensor_config: SensorConfig object.
            sensor_mode_cache: Whether sensor keeps export stats cache. See
                 below for more details.
            include_validation: Whether to include validation information
                in flow_info exports.
        """
        # Initialize members to None in __init__ to keep lint happy. These
        # values are set later by set_sensor_config.
        self.policy_helper = None
        self.network_helper = None

        # Start time for the first export interval.
        self.interval_start_time = 0
        self.burst_interval = None

        # flow_key -> SingleFlowState map
        self.flow_state_map = {}

        self.asic_flow_table = AsicFlowTable()

        # Configuration for the sensor. Set other members using
        # sensor configuration.
        self.set_sensor_config(sensor_config)

        # If sensor_mode_cache is True, the FlowTable keeps the list of
        # flow stats per export duration in export_stats_cache. This is useful
        # to run sensor model for test or on a small set of packets.
        # If sensor_mode_cache is False, the model raises
        # SensorStatsNotExported exception, which allows caller to collect
        # sensor stats. In this mode, this object does not maintain the cache.
        self.sensor_mode_cache = sensor_mode_cache
        # Method to callback, when export interval is over.
        self.sensor_export_callback = sensor_export_callback
        if self.sensor_export_callback:
            assert self.sensor_mode_cache is False
        self.export_stats_cache = flow_info_pb2.FlowInfoFromSensorList()

        # Whether there is a new packet after the last export.
        self.export_pending = False
        self.include_validation = include_validation

        # Callback method for event export.
        self.event_export_callback = event_export_callback

        # Enable/disable debug.
        self.debug = False

    def remove_flow_item(self, flow_key_str, check_item=True):
        """Remove invalid/preserved flow item from the table."""
        # Make sure that the items getting removed are ghost items.
        remove_flow_info = self.flow_state_map[flow_key_str].flow_info
        if check_item:
            assert (not remove_flow_info.flow_features or
                    not remove_flow_info.flow_features[0].packet_count)
        del self.flow_state_map[flow_key_str]

    def set_sensor_config(self, sensor_config):
        """Set sensor_config, including side-effects."""
        self._sensor_config = sensor_config
        self.policy_helper = PolicyHelper(self._sensor_config)
        self.network_helper = NetworkConfig(self._sensor_config)
        self.interval_start_time = self._sensor_config.sensor_start_time

        burst_bitshift = self._sensor_config.clock.tick_bitshifts_for_burst
        self.burst_interval = 0x1 << burst_bitshift

        if sensor_config.HasField("initial_flow_table_state"):
            for info in sensor_config.initial_flow_table_state.flow_info:
                self.set_flow_info(info)
                # TODO(ashu): Add burst interval stats from initial state.
                # key = self.flow_key_str(flow_info.key)
                # self.burst_lists[key].set_current_burst

    def get_sensor_config(self):
        """Get sensor config."""
        return self._sensor_config

    # Setting getter and setter for sensor_config, to take care of the
    # side effects when setting, rather than directly exposing the
    # variable.
    sensor_config = property(get_sensor_config, set_sensor_config)

    def set_export_callback(self, sensor_export_callback):
        """Set callback function for flow table export."""
        self.sensor_mode_cache = False
        assert callable(sensor_export_callback)
        self.sensor_export_callback = sensor_export_callback

    def set_event_callback(self, event_export_callback):
        """Set callback function for event export."""
        assert callable(event_export_callback)
        self.event_export_callback = event_export_callback

    def __del__(self):
        """Write any remaining flow table records."""
        if callable(self.sensor_export_callback):
            self.sensor_export_callback(self.export_done())

    def __repr__(self):
        """Readable string for the stats."""
        flow_info_str = "\n".join(
            [str(fi.flow_info.key) for fi in self.flow_state_map.values()])
        return flow_info_str

    def set_flow_info(self, flow_info):
        """Set a given flow info state in the model. Useful for testing."""
        validation = flow_info.Extensions[sensor_config_pb2.validation]
        key = self.flow_key_str(flow_info.key,
                                validation.analytics.analytics_type)
        if key not in self.flow_state_map:
            self.flow_state_map[key] = SingleFlowState(
                flow_info.key, flow_info.key.flow_start_time,
                self._sensor_config, self.interval_start_time,
                validation.switch_port, validation.analytics)
        self.flow_state_map[key].flow_info = flow_info
        # TODO(ashu): Also add the packet to asic_flow_table
        # validation.flow_table_row = flow_state.crc12
        # asic_cells = self.asic_num_cells(stats.key, flow_state.analytics)
        # (column, removed_keys) = self.asic_flow_table.add_key(
        #   flow_state.crc12, flow_key_str, asic_cells)

    def collector_analytics_match(self, flow_key, col_analytics, analytics):
        """Check whether collector analytics matched flow analytics."""
        analytics_type = analytics.analytics_type
        # CE flows are always considered CONCISE.
        if flow_key.key_type == flow_info_pb2.FlowKey.MAC:
            analytics_type = sensor_config_pb2.Analytics.CONCISE
        if col_analytics == sensor_config_pb2.SensorCollectorConfig.BOTH:
            return True
        if col_analytics == sensor_config_pb2.SensorCollectorConfig.FULL:
            return analytics_type == sensor_config_pb2.Analytics.FULL
        if col_analytics == sensor_config_pb2.SensorCollectorConfig.CONCISE:
            return analytics_type == sensor_config_pb2.Analytics.CONCISE
        assert False, "Unknown collector analytics %d" % col_analytics

    def collector_index(self, flow_key, analytics):
        """If there are multiple collectors, load-balance between those."""
        if self._sensor_config.num_collectors <= 1:
            return 0

        # If the collector range is really small, assume this flow will
        # not be collected.
        if (self._sensor_config.collector_config.range_high -
                self._sensor_config.collector_config.range_low) <= 1:
            return -1

        # Match collector config with analytics.
        if not self.collector_analytics_match(
                flow_key,
                self.sensor_config.collector_config.analytics_setup,
                analytics):
            return -1

        # Use required fields from flow_key, based on collector config.
        (src_addr, dst_addr) = ("", "")
        (src_port, dst_port) = ("", "")
        tenant_id = ""

        if self._sensor_config.collector_config.include_src_address:
            src_addr = sensor_util.convert_ip(flow_key.src_address)
        if self._sensor_config.collector_config.include_dst_address:
            dst_addr = sensor_util.convert_ip(flow_key.dst_address)
        if self._sensor_config.collector_config.include_src_port:
            src_port = str(flow_key.src_port)
        if self._sensor_config.collector_config.include_dst_port:
            dst_port = str(flow_key.dst_port)
        if self._sensor_config.collector_config.include_tenant_id:
            tenant_id = str(flow_key.tenant_id)


        # Create a direction independent hash, using min/max.
        m = hashlib.md5()
        for i in range(10):
            m.update(min(src_addr, dst_addr))
            m.update(max(src_addr, dst_addr))
            m.update(min(src_port, dst_port))
            m.update(max(src_port, dst_port))
            m.update(tenant_id)
        # Use last 16 bytes of the digest.
        collector_hash = int(m.hexdigest(), 16)

        ret = collector_hash % self._sensor_config.num_collectors
        # print (src_addr, dst_addr, src_port, dst_port, tenant_id,
        #        collector_hash, ret, min(src_addr, dst_addr),
        #        max(src_addr, dst_addr))
        return ret

    def get_sensor_flow_info(self, preserve_after_export=False):
        """Return flow_info accumulated in the current interval.

        Args:
            preserve_after_export: If True, only fields that should be
                preserved after export are kept, others are cleared.
        """
        preserved_map = {}
        sensor_flow_info = flow_info_pb2.FlowInfoFromSensor()
        for (key, stats) in self.flow_state_map.items():
            # Only consider flows that arrived in the current interval,
            # and not the ones that were preserved. Preserved flows won't
            # have flow_features.
            if len(stats.flow_info.flow_features) > 0:
                stats_to_add = sensor_flow_info.flow_info.add()
                stats_to_add.CopyFrom(stats.flow_info)
                # Remove key from asic row
                validation = stats_to_add.Extensions[
                    sensor_config_pb2.validation]
                if (validation.flow_table_column < 0 and
                        len(stats.flow_info.flow_features) > 0):
                    sensor_flow_info.table_full_packets +=\
                        stats.flow_info.flow_features[0].packet_count

                validation.collector_index = \
                    self.collector_index(stats.flow_info.key,
                                         validation.analytics)
                if validation.collector_index >= 0:
                    self.asic_flow_table.remove_key(validation.flow_table_row,
                                                    key, do_compaction=False)
                if not self.include_validation:
                    stats_to_add.ClearExtension(sensor_config_pb2.validation)

                # If the flow info is not covered by a collector, we don't
                # clean-out/preserve the stats in flow table.
                if validation.collector_index >= 0 and preserve_after_export:
                    stats.flow_info_after_export(self.interval_start_time)
                    preserved_map[key] = stats

        # Sort flow_info by start_time to make debugging easy.
        sensor_flow_info.flow_info.sort(key=lambda f: f.start_time)

        # Replace current map values with map to be preserved.
        self.flow_state_map.update(preserved_map)
        return sensor_flow_info

    def export_done(self):
        """Export flow stats and close current export interval."""
        sensor_flow_info = self.get_sensor_flow_info(
            preserve_after_export=True)
        self.export_pending = False
        # self.burst_lists = {}
        return sensor_flow_info

    def get_export_stats_cache(self):
        """Return cached export stats."""
        # Add current export interval to the cache.
        if self.export_pending:
            new_export = self.export_stats_cache.flow_info_from_sensor.add()
            new_export.CopyFrom(self.export_done())

        return self.export_stats_cache

    @classmethod
    def is_ip_frame(cls, eth_frame):
        """Check if dpkt frame is IPv4 or IPv6."""
        return eth_frame.type in [dpkt.ethernet.ETH_TYPE_IP,
                                  dpkt.ethernet.ETH_TYPE_IP6]

    @classmethod
    def is_frame_tcp_udp(cls, eth_frame):
        """Check if the eth frame has TCP/UDP payload."""
        if not FlowTable.is_ip_frame(eth_frame):
            return False
        return eth_frame.data.proto in [dpkt.ip.IP_PROTO_TCP,
                                        dpkt.ip.IP_PROTO_UDP]

    @staticmethod
    def key_from_packet(packet):
        """FlowKey based on the packet."""
        flow_key = flow_info_pb2.FlowKey()
        if FlowTable.is_ip_frame(packet):
            ip = packet.data
            flow_key.src_address = ip.src
            flow_key.dst_address = ip.dst
            if packet.type == dpkt.ethernet.ETH_TYPE_IP:
                flow_key.key_type = flow_info_pb2.FlowKey.IPV4
                flow_key.proto = ip.p
            else:
                flow_key.key_type = flow_info_pb2.FlowKey.IPV6
                if hasattr(ip, 'p'):
                    flow_key.proto = ip.p
                else:
                    flow_key.proto = ip.nxt

            if flow_key.proto in [dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP]:
                if not isinstance(ip.data, str):
                    flow_key.src_port = ip.data.sport
                    flow_key.dst_port = ip.data.dport
            elif flow_key.proto in [dpkt.ip.IP_PROTO_ICMP,
                                    dpkt.ip.IP_PROTO_ICMP6]:
                # TODO(ashu): This should be done only for ASIC, not software
                # sensor.
                flow_key.src_port = (ip.data.type << 8 | ip.data.code)
                flow_key.dst_port = ip.data.sum
            elif flow_key.proto == dpkt.ip.IP_PROTO_IGMP:
                pass
            else:
                raise SensorError("Unsupported proto %s in IP" %
                                  flow_key.proto)
        elif packet.type in [dpkt.ethernet.ETH_TYPE_ARP,
                             dpkt.ethernet.ETH_TYPE_REVARP]:
            flow_key.key_type = flow_info_pb2.FlowKey.IPV4
            arp = packet.data
            flow_key.src_address = arp.spa
            flow_key.dst_address = arp.tpa
            try:
                flow_key.proto = FlowTable.ARP_OP_PROTO_MAP[arp.op]
            except KeyError:
                raise SensorError("Unsupported OP %s in ARP" % arp.op)
        else:
            flow_key.src_address = packet.src
            flow_key.dst_address = packet.dst
            flow_key.key_type = flow_info_pb2.FlowKey.MAC
            flow_key.ether_type = packet.type

        # TODO(ashu): tenant_id not set yet.
        return flow_key

    def flow_key_clear_for_hash(self, flow_key, flow_key_hash):
        """Clear fields that are not included in the hash from the key."""
        if flow_key_hash != sensor_config_pb2.Analytics.FULL_KEY:
            flow_key.src_port = 0
            flow_key.dst_port = 0

        if flow_key_hash == sensor_config_pb2.Analytics.SRC_ADDRESS:
            flow_key.dst_address = '\x00' * len(flow_key.dst_address)

        if flow_key_hash == sensor_config_pb2.Analytics.DST_ADDRESS:
            flow_key.src_address = '\x00' * len(flow_key.src_address)

    def flow_key_str(self, flow_key, analytics_type):
        """Flow key string, useful as the key in maps."""
        # Do not use flow_start_time in the flow key.
        flow_start_time = flow_key.flow_start_time
        flow_key.ClearField("flow_start_time")
        # Make flow key str readable, as it helps debugging.
        flow_key_str = google.protobuf.text_format.MessageToString(
            flow_key, as_one_line=True)
        if self.sensor_config.sensor_mode ==\
                sensor_config_pb2.SensorConfig.ASIC_SENSOR_MODEL:
            assert analytics_type is not None
            flow_key_str = flow_key_str + " analytics: " + str(analytics_type)
        flow_key.flow_start_time = flow_start_time
        return flow_key_str

    @classmethod
    def update_length_bins(cls, length, sixteen_bins, buckets):
        """Update the right bit in the length bucket."""
        assert len(buckets) < 16
        # If length is smaller than the first bin, no bits are set.
        for i in range(len(buckets)):
            if length < buckets[i]:
                # Set the bit in the previous field.
                field_name = "bin%d" % (i + 1)
                setattr(sixteen_bins, field_name, 1)
                return
        field_name = "bin%d" % (len(buckets) + 1)
        setattr(sixteen_bins, field_name, 1)


    @classmethod
    def update_given_tcp_flag(cls, flag):
        """ Updates the tcp flag as per the mode. Asic sensor simply uses a
        boolean value for telling if a given tcp flag is seen. But Software
        sensor counts the number of times each flag is seen."""
        if FLAGS.asic_mode:
            flag = 1
        else:
            flag += 1


    @classmethod
    def update_accumulated_tcp_flags(cls, tcp, tcp_info):
        """TCP flags from the packet."""
        if tcp.flags & dpkt.tcp.TH_FIN:
            update_given_tcp_flag(tcp_info.accumulated_flags.fin)
        if tcp.flags & dpkt.tcp.TH_SYN:
            update_given_tcp_flag(tcp_info.accumulated_flags.syn)
        if tcp.flags & dpkt.tcp.TH_RST:
            update_given_tcp_flag(tcp_info.accumulated_flags.rst)
        if tcp.flags & dpkt.tcp.TH_PUSH:
            update_given_tcp_flag(tcp_info.accumulated_flags.psh)
        if tcp.flags & dpkt.tcp.TH_ACK:
            update_given_tcp_flag(tcp_info.accumulated_flags.ack)
        if tcp.flags & dpkt.tcp.TH_URG:
            update_given_tcp_flag(tcp_info.accumulated_flags.urg)
        if tcp.flags & dpkt.tcp.TH_ECE:
            update_given_tcp_flag(tcp_info.accumulated_flags.ece)
        if tcp.flags & dpkt.tcp.TH_CWR:
            update_given_tcp_flag(tcp_info.accumulated_flags.cwr)

    @classmethod
    def within_wrapped_range(cls, num, low, high):
        """Check whether num is within (low, high) range, where num is
        unsigned 32 bits, and could have wrapped around. low and high
        are regular python int and don't wrap around."""
        assert low <= high

        def within_range(num, low, high):
            """Simple within range check."""
            return num >= low and num <= high

        # Check for num in regular range, or wrapped value of num,
        # or wrapped value of the range.
        return (within_range(num, low, high) or
                within_range(num + (1 << 32), low, high) or
                within_range(num - (1 << 32), low, high))

    def update_tcp_info(self, tcp, tcp_info, first_packet_in_flow=False):
        """Get TCP stats from the packet.

        tcp_info: TCP info for the flow, without including current packet.
        event: EventDescriptor to record RTT events based on TCP seq.

        first_packet_in_flow: Whether this is the first packet in the TCP flow,
            in which case, we don't process possible sequence guess kind of
            checks.
        """
        self.update_accumulated_tcp_flags(tcp, tcp_info)

        syn_fin = dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN
        if (tcp.flags & syn_fin) == syn_fin:
            tcp_info.syn_and_fin_set = 1
        syn_rst = dpkt.tcp.TH_SYN | dpkt.tcp.TH_RST
        if (tcp.flags & syn_rst) == syn_rst:
            tcp_info.syn_and_rst_set = 1
        xmas = dpkt.tcp.TH_FIN | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_URG
        if (tcp.flags & xmas) == xmas:
            tcp_info.xmas_flags_set = 1
        if tcp.flags == 0:
            tcp_info.null_flags = 1
        if tcp.flags & dpkt.tcp.TH_SYN > 0 and tcp.data != '':
            tcp_info.syn_with_data = 1
        if ((tcp.flags & dpkt.tcp.TH_FIN > 0) and not
                (tcp.flags & dpkt.tcp.TH_ACK > 0)):
            tcp_info.fin_with_no_ack = 1
        if ((tcp.flags & dpkt.tcp.TH_RST > 0) and not
                (tcp.flags & dpkt.tcp.TH_ACK > 0)):
            tcp_info.rst_with_no_ack = 1
        syn_fin_rst_ack = (dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN |
                           dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK)
        if (tcp.flags & syn_fin_rst_ack) == 0:
            tcp_info.syn_fin_rst_ack_all_zero = 1
        if ((tcp.flags & dpkt.tcp.TH_URG) > 0) != (tcp.urp > 0):
            tcp_info.urg_ptr_not_consistent = 1

        last_ack_num = None
        if not first_packet_in_flow:
            # Range of sequence numbers computed using config params.
            max_seq = (tcp_info.sequence_num +
                       self._sensor_config.tcp_sequence_number_plus_offset)
            min_seq = (tcp_info.sequence_num -
                       self._sensor_config.tcp_sequence_number_minus_offset)
            # If new seq is in range (old_seq + 1, max) -> valid
            # Else if in range(min_seq, old_seq) -> retransmission.
            # Else guess.
            if self.within_wrapped_range(tcp.seq, min_seq,
                                         tcp_info.sequence_num):
                tcp_info.possible_retransmission = 1
            elif not self.within_wrapped_range(
                    tcp.seq, tcp_info.sequence_num + 1, max_seq):
                tcp_info.possible_sequence_num_guess = 1

            if tcp_info.HasField("ack_num"):
                last_ack_num = tcp_info.ack_num

        tcp_info.sequence_num = tcp.seq
        if tcp.flags & dpkt.tcp.TH_ACK > 0:
            tcp_info.ack_num = tcp.ack

            # Check for repeated ack numbers, only when ACK is valid
            if last_ack_num is not None and last_ack_num == tcp.ack:
                tcp_info.ack_repeated = 1

        self.update_length_bins(tcp.off,
                                tcp_info.option_len_bins.sixteen_bins,
                                self._sensor_config.tcp_header_length_bins)

        # tcp_info.ack_repeated = 0;
        self.update_length_bins(
            tcp.win,
            tcp_info.rcv_window_bins.sixteen_bins,
            self._sensor_config.receiver_window_length_bins)

    def masked_packet_id(self, packet_id):
        """Get IP packet id with masking."""
        pid = packet_id >> self._sensor_config.ip_packet_id_min_bit
        pid_bitmask = (1 << self._sensor_config.ip_packet_id_num_bits) - 1
        return pid & pid_bitmask

    def update_ipv4_info(self, packet, ip_info, first_packet_in_flow=False):
        """Get IP stats from the IP packet."""
        if packet.opts != '':
            ip_info.ip_options_present = 1
        if (ip_info.HasField("last_cached_ttl") and
                packet.ttl != ip_info.last_cached_ttl):
            ip_info.ttl_changed = 1
        if packet.len != len(packet):
            ip_info.length_error = 1
        if packet.off & dpkt.ip.IP_RF:
            ip_info.ip_reserved_not_zero = 1
        # optional PacketDisposition packet_disposition = 5;

        packet_dont_fragment_set = (packet.off & dpkt.ip.IP_DF > 0)
        # Check if the dont_fragment changed.
        if (not first_packet_in_flow and
                packet_dont_fragment_set != ip_info.dont_fragment_set):
            ip_info.dont_fragment_flag_changed = 1
        if packet_dont_fragment_set:
            ip_info.dont_fragment_set = 1

        # No need to shift, as OFFMASK is lower bits.
        fragment_offset = packet.off & dpkt.ip.IP_OFFMASK
        # We only need to check with the length in IP header, and
        # not the actual packet length.
        if fragment_offset * 8 + packet.len > (1 << 16):
            ip_info.ping_of_death = 1

        if packet.off & (dpkt.ip.IP_MF | dpkt.ip.IP_OFFMASK):
            ip_info.fragment_seen = 1

        if ((packet.p == dpkt.ip.IP_PROTO_TCP) and
                ((fragment_offset == 0 and len(packet.data) < 20) or
                 (fragment_offset == 1))):
            ip_info.tiny_fragment_seen = 1
        ip_info.last_cached_ttl = packet.ttl

        # TODO(ashu): QOS removed to match ASIC parser implementation.
        # TODO(ashu): Currently, we are only using TOS from IP header. But,
        # it may also come from policy table, etc.
        # TODO(ashu): In case of changing QoS, should this value be
        # OR of all the packets?
        ip_info.qos = 0  # packet.tos & 0x7

        # TODO(ashu): Implement this.
        # ip_info.overlapping_fragment_seen = 14

    @classmethod
    def update_ipv6_info(cls, packet, ip_info):
        """Get IP stats from the IPv6 packet."""
        if (ip_info.HasField("last_cached_ttl") and
                packet.hlim != ip_info.last_cached_ttl):
            ip_info.ttl_changed = 1
        ip_info.last_cached_ttl = packet.hlim

        # The IPv6 payload length includes all but first header. dpkt does
        # not include extension header in len(ip6), so use len(str(ip6)).
        if packet.plen != len(str(packet)) - 40:
            ip_info.length_error = 1

        # TODO(ashu): In case of changing QoS, should this value be
        # OR of all the packets?
        ip_info.qos = packet.flow & 0x7

        for value in packet.extension_hdrs.values():
            if value:
                ip_info.ip_options_present = 1

            if value and isinstance(value, dpkt.ip6.IP6FragmentHeader):
                # Fragment header
                if value.frag_off > 0 or value.m_flag > 0:
                    ip_info.fragment_seen = 1
                if value.frag_off * 8 + len(packet.data) > (1 << 16):
                    ip_info.ping_of_death = 1

    @classmethod
    def update_ce_info(cls, packet, flow_info):
        """Update CE related info."""
        if flow_info.key.key_type == flow_info_pb2.FlowKey.MAC:
            # Unfortunately, COS information from ethernet is added in ip_info.
            # TODO(ashu): Translate values from Ethernet TOS.
            flow_info.ip_info.qos = 0

    @classmethod
    def update_icmp_info(cls, icmp, flow_info):
        """Update ICMP related info."""
        icmp_info = flow_info.icmp_info.add() # _pb2.ICMPInfo()
        icmp_info.type = icmp.type
        icmp_info.code = icmp.code

    def get_packet_id(self, packet):
        """Get IP ID or IPv6 fragment id from the packet."""
        if isinstance(packet, dpkt.ip.IP):
            return packet.id
        if isinstance(packet, dpkt.ip6.IP6):
            for value in packet.extension_hdrs.values():
                if value and isinstance(value, dpkt.ip6.IP6FragmentHeader):
                    return value.id
        return None

    def update_final_stats(self, flow_key_str, stats):
        """Update cross packet flow stats."""
        if len(stats.flow_features) > 0:
            flow_feature = stats.flow_features[0]
        else:
            flow_feature = stats.flow_features.add()

        # Get flow features from flow state
        flow_state = self.flow_state_map[flow_key_str]
        flow_feature.packet_count = flow_state.packet_count
        flow_feature.byte_count = flow_state.byte_count

        # Update burst variables.
        flow_feature.num_flowlets = flow_state.num_flowlets
        flow_feature.current_burst = flow_state.current_burst
        flow_feature.max_burst = flow_state.max_burst
        flow_feature.max_burst_index = flow_state.max_burst_index

        validation = stats.Extensions[sensor_config_pb2.validation]
        # Copy CRC12 as flow table row.
        validation.flow_table_row = flow_state.crc12

        asic_cells = self.asic_num_cells(stats.key, flow_state.analytics)

        # If analytics = NO_COLLECT, then don't insert flow in the flow
        # table.
        if (flow_state.analytics.analytics_type !=
                sensor_config_pb2.Analytics.NO_ANALYTICS):
            if self.debug:
                print "adding packet hash %s" % hashstr(flow_key_str),
                print " to table\n", repr(self.asic_flow_table)
            (column, removed_keys) = self.asic_flow_table.add_key(
                flow_state.crc12, flow_key_str, asic_cells)
            if self.debug:
                if removed_keys:
                    print "removing ", [hashstr(k) for k in removed_keys]
                print "added at %d: %d" % (flow_state.crc12, column)
                print " table after add\n", repr(self.asic_flow_table)
        else:
            (column, removed_keys) = (-2, [])

        # Negative flow_table_column has special meaning now.
        # -1 = table full. -2 = no analytics.
        validation.flow_table_column = column
        if removed_keys:
            for remove in removed_keys:
                self.remove_flow_item(remove)

        # Randomly sample one of the packet lengths.
        if len(validation.packet_ids) > 0:
            stats.ip_info.packet_id = \
                random.sample(validation.packet_ids, 1)[0]

        packet_lengths = validation.packet_lengths

        # Randomly sample one of the packet lengths.
        flow_feature.random_packet_length = \
            add_saturate(random.sample(packet_lengths, 1)[0], 0,
                         self.RANDOM_PACKET_LEN_BITS)

        self.update_length_bins(flow_state.payload_len,
                                flow_feature.packet_length_bins.sixteen_bins,
                                self._sensor_config.tcp_payload_length_bins)

        # Set the fields in validation.
        validation.analytics.CopyFrom(flow_state.analytics)

        # For parser model, keep all fields. Otherwise, remove fields that
        # are not required.
        if self.sensor_config.sensor_mode !=\
                sensor_config_pb2.SensorConfig.PACKET_PARSER_MODEL:
            self.filter_required_stats(stats)

    def asic_num_cells(self, flow_key, analytics):
        """Number of ASIC cells needed to store the flow table."""
        if flow_key.key_type == flow_info_pb2.FlowKey.MAC:
            return 1
        if analytics.analytics_type == sensor_config_pb2.Analytics.CONCISE:
            if flow_key.key_type == flow_info_pb2.FlowKey.IPV6:
                return 2
            else:
                return 1  # IPv4 concise.
        if flow_key.key_type == flow_info_pb2.FlowKey.IPV6:
            return 3
        return 2  # IPv4 full

    def filter_required_stats(self, flow_info):
        """Based on the ananlytics requirements (concise or full), filter out
        stats that are not required."""
        validation = flow_info.Extensions[sensor_config_pb2.validation]
        analytics = validation.analytics
        if (flow_info.key.key_type == flow_info_pb2.FlowKey.MAC or
                analytics.analytics_type ==
                sensor_config_pb2.Analytics.CONCISE):
            flow_info_copy = flow_info_pb2.FlowInfo()
            flow_info_copy.key.CopyFrom(flow_info.key)
            flow_info_copy.start_time = flow_info.start_time
            flow_info_copy.end_time = flow_info.end_time
            if flow_info.HasField("ip_info"):
                if flow_info.ip_info.HasField("qos"):
                    flow_info_copy.ip_info.qos = flow_info.ip_info.qos
            ff_old = flow_info.flow_features[0]
            ff_new = flow_info_copy.flow_features.add()
            ff_new.packet_count = ff_old.packet_count
            ff_new.byte_count = ff_old.byte_count

            # In the ASIC, num flowlets are not supported for MAC.
            if flow_info.key.key_type != flow_info_pb2.FlowKey.MAC:
                ff_new.num_flowlets = ff_old.num_flowlets

            # Clear non-extension fields from flow_info.
            flow_info_copy.Extensions[sensor_config_pb2.validation].\
                CopyFrom(validation)

            flow_info.Clear()
            flow_info.CopyFrom(flow_info_copy)

    def add_packet(self, eth, timestamp, iface_name=None, switch_port=None):
        """Consider new Ethernet packet arrived within the export interval."""
        assert isinstance(eth, dpkt.ethernet.Ethernet)
        pproto = sensor_config_pb2.Packet()
        fill_parsed_packet(eth, pproto, timestamp, iface_name, switch_port)
        self.add_packet_proto(pproto)

    def add_packet_proto(self, packet):
        """Consider new Ethernet packet arrived within the export interval.

        packet is sensor_config.Packet object that provided timestamp,
        iface_name, switch_port, etc."""
        if self.debug:
            print "\ninterval start time ", self.interval_start_time
            print "\nnew packet at time ", packet.timestamp

        assert packet.timestamp >= self.interval_start_time

        if packet.parser_error and self.sensor_config.sensor_mode ==\
                sensor_config_pb2.SensorConfig.ASIC_SENSOR_MODEL:
            logging.error("Parser error. Packet ignored")
            return

        assert isinstance(packet, sensor_config_pb2.Packet)
        # Remove last 4 bytes of Ethernet CRC from pcap.
        eth_frame = dpkt.ethernet.Ethernet(packet.pcap[0:-4])

        timestamp = packet.timestamp
        iface_name = packet.iface
        switch_port = packet.switch_port

        if (timestamp >= self.interval_start_time +
                self._sensor_config.export_interval):
            # Increment export window to contain current packet timestamp.
            n = int((timestamp - self.interval_start_time)
                    / self._sensor_config.export_interval)
            self.interval_start_time += n * self._sensor_config.export_interval

            # Close export interval, if there are unexported items.
            if self.export_pending:
                if self.sensor_mode_cache:
                    self.get_export_stats_cache()
                elif callable(self.sensor_export_callback):
                    self.sensor_export_callback(self.export_done())
                else:
                    raise SensorStatsNotExported()

        if not isinstance(eth_frame, dpkt.ethernet.Ethernet):
            raise SensorError("Frame must be Ethernet not ",
                              type(eth_frame).__name__)

        self.export_pending = True
        ip = eth_frame.data

        # FlowKey is set only the first time.
        flow_key = FlowTable.key_from_packet(eth_frame)

        # TCAM based information is looked up based on the packet (or the
        # full flow key). The flow key itself may change later, based on the
        # fields required to build the hash.

        # First lookup tenant_id and set in the flow key, because the TCAM
        # lookup depends on the tenant_id.
        iface = self.network_helper.get_iface(
            iface_name=iface_name, switch_port=switch_port)
        flow_key.tenant_id = iface.tenant_id
        on_ingress = iface.on_ingress

        # Compute packet disposition
        packet_disposition = flow_info_pb2.PacketDisposition()
        self.policy_helper.packet_disposition(flow_key, packet_disposition)

        overlay_info = flow_info_pb2.OverlayInfo()
        # Look up overlay info.
        if flow_key.HasField("tenant_id"):
            src_tep = self.network_helper.get_tep(
                flow_key.tenant_id, flow_key.src_address)
            assert src_tep, ("TEP not set for src", str(flow_key))
            overlay_info.src_tep = src_tep
            dst_tep = self.network_helper.get_tep(
                flow_key.tenant_id, flow_key.dst_address)
            assert dst_tep, ("TEP not set for dst", str(flow_key))
            overlay_info.dst_tep = dst_tep
            if src_tep or dst_tep:
                overlay_info.encap_type = flow_info_pb2.OverlayInfo.VX_LAN

        # Find the tep on which analytics would be defined.
        if on_ingress:
            tep = overlay_info.dst_tep
        else:
            tep = overlay_info.src_tep

        # Look up analytics based on full flow key.
        analytics = self.policy_helper.analytics(
            flow_key, tep, iface.switch_port)

        # Based on analytics config, we may clear some fields from the key.
        if self.sensor_config.sensor_mode !=\
                sensor_config_pb2.SensorConfig.PACKET_PARSER_MODEL:
            self.flow_key_clear_for_hash(flow_key, analytics.flow_key_hash)


        flow_key_str = self.flow_key_str(flow_key, analytics.analytics_type)

        def CreateFlowInfo(flow_key, start_time):
            """Create new FlowInfo with the key and start_time."""
            flow_info = flow_info_pb2.FlowInfo()
            flow_info.key.CopyFrom(flow_key)
            # Only for a new flow_key, set start_time.
            flow_info.key.flow_start_time = start_time
            return flow_info

        # Pick existing flow_info from the map, or create new.
        flow_state = self.flow_state_map.setdefault(
            flow_key_str,
            SingleFlowState(flow_key, timestamp,
                            self._sensor_config,
                            self.interval_start_time, switch_port, analytics))

        flow_info = flow_state.flow_info
        flow_info.on_ingress = on_ingress

        # Put previously looked up information in flow_info.
        flow_info.overlay_info.CopyFrom(overlay_info)
        # Merge packet_disposition, rather than copy.
        flow_info.ip_info.packet_disposition.MergeFrom(packet_disposition)

        # Maintain the events based on this packet.
        event = flow_info_pb2.EventDescriptor()
        event.event_time = timestamp

        # If the flow is not present or preserved, mark it as first pkt.
        first_packet_in_flow = False

        # TODO(ashu): event_type_first_pkt is defined as first pkt
        # within interval. Check, if we want this to be the first pkt within
        # flow ever.
        if flow_info.key.flow_start_time == timestamp:
            first_packet_in_flow = True
            event.event_type_first_pkt = True

        # print "flow_info.key.flow_start_time", flow_info.key.flow_start_time,
        # print "timestamp", timestamp, "first packet? ", first_packet_in_flow

        # Set start_time, if flow_info is new within export interval.
        # start_time should be within export interval.
        if len(flow_info.flow_features) == 0:
            flow_info.start_time = timestamp

        flow_info.end_time = timestamp

        if eth_frame.type == dpkt.ethernet.ETH_TYPE_IP:
            self.update_ipv4_info(ip, flow_info.ip_info, first_packet_in_flow)
            if ip.p in (dpkt.ip.IP_PROTO_ICMP, dpkt.ip.IP_PROTO_ICMP6):
                self.update_icmp_info(ip.data, flow_info)
        elif eth_frame.type == dpkt.ethernet.ETH_TYPE_IP6:
            self.update_ipv6_info(ip, flow_info.ip_info)
            if ip.nxt in (dpkt.ip.IP_PROTO_ICMP, dpkt.ip.IP_PROTO_ICMP6):
                self.update_icmp_info(ip.data, flow_info)
        else:
            self.update_ce_info(eth_frame, flow_info)

        flow_state.payload_len = packet.l4_payload_len

        if hasattr(ip, 'data') and isinstance(ip.data, dpkt.tcp.TCP):
            # before updating tcp_info, record previous ack_num.
            last_ack_num = None
            if flow_info.tcp_info.HasField("ack_num"):
                last_ack_num = flow_info.tcp_info.ack_num
            self.update_tcp_info(ip.data, flow_info.tcp_info,
                                 first_packet_in_flow)
            # Check for RTT event that uses TCP seq/ack numbers.
            # Take RTT profile from matching analytics, if available,
            # otherwise use sensor config.
            if analytics.rtt_profile_index >= 0:
                zero_k = self.sensor_config.event_config.\
                    rtt_profile_lower_bits_zero[
                        analytics.rtt_profile_index]
            else:
                zero_k = self.sensor_config.event_config.\
                    rtt_sequence_lower_bits_zero
            self.check_rtt_event(ip.data, last_ack_num, event, zero_k)

        validation = flow_info.Extensions[sensor_config_pb2.validation]
        # The LU analytics type, based only on TEP and switch port.
        validation.lu_analytics_type = self.policy_helper.lu_analytics_type(
            flow_key.tenant_id, tep, iface.switch_port).analytics_type

        # Fill in iface name and switch port.
        validation.iface_name = iface_name
        validation.switch_port = switch_port

        # Add IP packet id to validation map.
        packet_id = self.get_packet_id(eth_frame.data)
        if packet_id is not None:
            packet_id = self.masked_packet_id(packet_id)
            if packet_id not in validation.packet_ids:
                validation.packet_ids.append(packet_id)

        # TODO(ashu): For IP, the length is IP packet length. For rest,
        # the length is the Ethernet packet length. This could change,
        # if ASIC does not support it, so we'll keep this as L2
        # frame length for the time.
        if packet.HasField('l4_payload_len'):
            packet_len = packet.l4_payload_len
        else:
            packet_len = packet.l2_len
        if packet_len not in validation.packet_lengths:
            validation.packet_lengths.append(packet_len)

        flow_state.new_packet(timestamp, packet.l2_len, packet.l4_payload_len)

        self.update_final_stats(flow_key_str, flow_info)

        # Add event related info.
        if self.event_export_callback:
            assert packet.HasField("flow_info"), packet
            if flow_info.flow_features[0].packet_count <=\
                    self.sensor_config.event_config.mice_packets_threshold:
                event.event_type_mouse_pkt = True

            if analytics.export_flow_override and analytics.export_flow:
                event.event_type_export_flow = True

            if analytics.analytics_type != sensor_config_pb2.Analytics.FULL:
                event.ClearField("event_type_rtt_ack")
                event.ClearField("event_type_rtt_seq")

            # Negative flow_table_column has special meaning now.
            # -1 = table full. -2 = no analytics.
            if validation.flow_table_column == -1:
                event.event_type_table_full = True

            if (event.event_type_table_full or
                    analytics.analytics_type ==
                    sensor_config_pb2.Analytics.NO_ANALYTICS):
                # With table full or collect=False, we don't have even the
                # concise info, so suppress events that are related to number
                # of packets in the flow.
                event.ClearField("event_type_first_pkt")
                event.ClearField("event_type_mouse_pkt")
                event.ClearField("event_type_rtt_seq")

            self.send_event_export(event, flow_key, packet)

        # In ASIC mode, Remove the flow from the flow table, if we could not
        # find a place in FT for the flow.
        if validation.flow_table_column < 0 and\
               (self.sensor_config.sensor_mode ==
                sensor_config_pb2.SensorConfig.ASIC_SENSOR_MODEL):
            self.remove_flow_item(flow_key_str, check_item=False)


    @classmethod
    def next_zero_k(cls, num, zero_k=10):
        """Next number >= given num, which has last K bits zero."""
        if num & ((0x1 << zero_k) -1) == 0:
            return num
        return ((num >> zero_k) + 1) << zero_k

    @classmethod
    def check_rtt_event_tcp_seq(cls, tcp_seq, tcp_len, zero_k):
        """Check for TCP seq based RTT."""
        seq_xi = cls.next_zero_k(tcp_seq, zero_k)
        # For seq + len, we don't need to worry about wrap around beyond
        # 4 bytes, because python int is long. Note that tcp_seq can also
        # be 0.
        if tcp_seq <= seq_xi and tcp_seq + tcp_len > seq_xi:
            return True
        return False

    @classmethod
    def check_rtt_event_tcp_ack(cls, last_tcp_ack, tcp_ack, zero_k):
        """Check for TCP ack based RTT."""
        if not last_tcp_ack:
            return False
        ack_xi = cls.next_zero_k(last_tcp_ack, zero_k)
        if last_tcp_ack <= ack_xi and tcp_ack > ack_xi:
            return True

        # if new tcp_ack is a tiny number and last_tcp_ack is closer to wrap
        # consider new tcp_ack a wrap around, which should match the trigger.
        return ack_xi == (0x1 << 32) and not (tcp_ack >> zero_k)

    def check_rtt_event(self, tcp, last_ack, event, zero_k):
        """Check whether sensor should send RTT event for the packet."""
        # if [seq num, seq_num + payload len) contains xi, where xi is any
        # number containing K zeros in the least significant bits, then
        # this packet should be considered for sequence number based RTT event.
        if self.check_rtt_event_tcp_seq(tcp.seq, len(tcp.data), zero_k):
            event.event_type_rtt_seq = True
        if last_ack is not None:
            if self.check_rtt_event_tcp_ack(last_ack, tcp.ack, zero_k):
                event.event_type_rtt_ack = True
        return event.event_type_rtt_seq or event.event_type_rtt_ack

    def send_event_export(self, event, flow_key, packet_proto):
        """Check if we need to export event for the packet and generate
        event."""
        if not self.event_export_callback:
            return

        send_event = False
        event_mask = self.sensor_config.event_config.event_mask
        # Find events that are enabled in the mask and are present.
        for event_type in self.EVENT_TYPES:
            if getattr(event, event_type):
                if getattr(event_mask, event_type):
                    send_event = True
                else:
                    event.ClearField(event_type)

        if not send_event:
            return
        
        # If no collector is setup to receive the event, drop it.
        # TODO(ashu): This does not match ASIC implementation.
        # if self.collector_index(per_packet_flow_info.key) < 0:
        #    return
        
        # Copy event info from per-packet flow info.
        event.event_info.key.CopyFrom(flow_key)

        per_packet_flow_info = packet_proto.flow_info
        event.event_info.ip_info.CopyFrom(per_packet_flow_info.ip_info)

        if len(per_packet_flow_info.flow_features) > 0:
            ff = per_packet_flow_info.flow_features[0]
            if ff.HasField("byte_count"):
                event.event_info.event_features.byte_count = ff.byte_count

        if packet_proto.HasField("l4_payload_len"):
            event.event_info.event_features.payload_length =\
                packet_proto.l4_payload_len

        if packet_proto.HasField('tcp_ack_num'):
            event.event_info.tcp_info.ack_num = packet_proto.tcp_ack_num

        if packet_proto.HasField("ip_id"):
            # packet id should be full id, not shifted packed id in the
            # flow info. If required, copy from packet proto.
            event.event_info.ip_info.packet_id = packet_proto.ip_id

        # Replace relevant fields in IP info.
        if per_packet_flow_info.HasField("ip_info"):
            ip_info = per_packet_flow_info.ip_info
            if ip_info.HasField("qos"):
                event.event_info.ip_info.qos = ip_info.qos

        # Clear values that are not available in the events export.
        if per_packet_flow_info.HasField("tcp_info"):
            tinfo = per_packet_flow_info.tcp_info
            event.event_info.tcp_info.accumulated_flags.\
                CopyFrom(tinfo.accumulated_flags)
            if tinfo.HasField('sequence_num'):
                event.event_info.tcp_info.sequence_num = tinfo.sequence_num

        event_export = flow_info_pb2.FlowInfoFromSensor()
        event_export.event.add().CopyFrom(event)

        # Export the event to collector.
        # TODO(ashu): Implement callbak on timeout or event full.
        self.event_export_callback(event_export)
