## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011-2012
## 2012-03-10 Roger Meyer <roger.meyer@csus.edu>: Added frames
## This program is published under a GPLv2 license

import struct
from scapy.packet import Packet, bind_layers
from scapy.fields import *
from scapy.layers.dot15d4 import dot15d4AddressField, Dot15d4Beacon

# ZigBee Cluster Library Identifiers, Table 2.2 ZCL
_zcl_cluster_identifier = {
    # Functional Domain: General
    0x0000: "basic",
    0x0001: "power_configuration",
    0x0002: "device_temperature_configuration",
    0x0003: "identify",
    0x0004: "groups",
    0x0005: "scenes",
    0x0006: "on_off",
    0x0007: "on_off_switch_configuration",
    0x0008: "level_control",
    0x0009: "alarms",
    0x000a: "time",
    0x000b: "rssi_location",
    0x000c: "analog_input",
    0x000d: "analog_output",
    0x000e: "analog_value",
    0x000f: "binary_input",
    0x0010: "binary_output",
    0x0011: "binary_value",
    0x0012: "multistate_input",
    0x0013: "multistate_output",
    0x0014: "multistate_value",
    0x0015: "commissioning",
    # 0x0016 - 0x00ff reserved
    # Functional Domain: Closures
    0x0100: "shade_configuration",
    # 0x0101 - 0x01ff reserved
    # Functional Domain: HVAC
    0x0200: "pump_configuration_and_control",
    0x0201: "thermostat",
    0x0202: "fan_control",
    0x0203: "dehumidification_control",
    0x0204: "thermostat_user_interface_configuration",
    # 0x0205 - 0x02ff reserved
    # Functional Domain: Lighting
    0x0300: "color_control",
    0x0301: "ballast_configuration",
    # Functional Domain: Measurement and sensing
    0x0400: "illuminance_measurement",
    0x0401: "illuminance_level_sensing",
    0x0402: "temperature_measurement",
    0x0403: "pressure_measurement",
    0x0404: "flow_measurement",
    0x0405: "relative_humidity_measurement",
    0x0406: "occupancy_sensing",
    # Functional Domain: Security and safethy
    0x0500: "ias_zone",
    0x0501: "ias_ace",
    0x0502: "ias_wd",
    # Functional Domain: Protocol Interfaces
    0x0600: "generic_tunnel",
    0x0601: "bacnet_protocol_tunnel",
    0x0602: "analog_input_regular",
    0x0603: "analog_input_extended",
    0x0604: "analog_output_regular",
    0x0605: "analog_output_extended",
    0x0606: "analog_value_regular",
    0x0607: "analog_value_extended",
    0x0608: "binary_input_regular",
    0x0609: "binary_input_extended",
    0x060a: "binary_output_regular",
    0x060b: "binary_output_extended",
    0x060c: "binary_value_regular",
    0x060d: "binary_value_extended",
    0x060e: "multistate_input_regular",
    0x060f: "multistate_input_extended",
    0x0610: "multistate_output_regular",
    0x0611: "multistate_output_extended",
    0x0612: "multistate_value_regular",
    0x0613: "multistate_value",
    # Smart Energy Profile Clusters
    0x0700: "price",
    0x0701: "demand_response_and_load_control",
    0x0702: "metering",
    0x0703: "messaging",
    0x0704: "smart_energy_tunneling",
    0x0705: "prepayment",
    # Functional Domain: General
    # Key Establishment
    0x0800: "key_establishment",
}

# ZigBee stack profiles
_zcl_profile_identifier = {
    0x0000: "ZigBee_Stack_Profile_1",
    0x0101: "IPM_Industrial_Plant_Monitoring",
    0x0104: "HA_Home_Automation",
    0x0105: "CBA_Commercial_Building_Automation",
    0x0107: "TA_Telecom_Applications",
    0x0108: "HC_Health_Care",
    0x0109: "SE_Smart_Energy_Profile",
}

# ZigBee Cluster Library, Table 2.8 ZCL Command Frames
_zcl_command_frames = {
    0x00: "read_attributes",
    0x01: "read_attributes_response",
    0x02: "write_attributes_response",
    0x03: "write_attributes_undivided",
    0x04: "write_attributes_response",
    0x05: "write_attributes_no_response",
    0x06: "configure_reporting",
    0x07: "configure_reporting_response",
    0x08: "read_reporting_configuration",
    0x09: "read_reporting_configuration_response",
    0x0a: "report_attributes",
    0x0b: "default_response",
    0x0c: "discover_attributes",
    0x0d: "discover_attributes_response",
    # 0x0e - 0xff Reserved
}

# ZigBee Cluster Library, Table 2.16 Enumerated Status Values
_zcl_enumerated_status_values = {
    0x00: "SUCCESS",
    0x02: "FAILURE",
    # 0x02 - 0x7f Reserved
    0x80: "MALFORMED_COMMAND",
    0x81: "UNSUP_CLUSTER_COMMAND",
    0x82: "UNSUP_GENERAL_COMMAND",
    0x83: "UNSUP_MANUF_CLUSTER_COMMAND",
    0x84: "UNSUP_MANUF_GENERAL_COMMAND",
    0x85: "INVALID_FIELD",
    0x86: "UNSUPPORTED_ATTRIBUTE",
    0x87: "INVALID_VALUE",
    0x88: "READ_ONLY",
    0x89: "INSUFFICIENT_SPACE",
    0x8a: "DUPLICATE_EXISTS",
    0x8b: "NOT_FOUND",
    0x8c: "UNREPORTABLE_ATTRIBUTE",
    0x8d: "INVALID_DATA_TYPE",
    # 0x8e - 0xbf Reserved
    0xc0: "HARDWARE_FAILURE",
    0xc1: "SOFTWARE_FAILURE",
    0xc2: "CALIBRATION_ERROR",
    # 0xc3 - 0xff Reserved
}

# ZigBee Cluster Library, Table 2.15 Data Types
_zcl_attribute_data_types = {
    0x00: "no_data",
    # General data
    0x08: "8-bit_data",
    0x09: "16-bit_data",
    0x0a: "24-bit_data",
    0x0b: "32-bit_data",
    0x0c: "40-bit_data",
    0x0d: "48-bit_data",
    0x0e: "56-bit_data",
    0x0f: "64-bit_data",
    # Logical
    0x10: "boolean",
    # Bitmap
    0x18: "8-bit_bitmap",
    0x19: "16-bit_bitmap",
    0x1a: "24-bit_bitmap",
    0x1b: "32-bit_bitmap",
    0x1c: "40-bit_bitmap",
    0x1d: "48-bit_bitmap",
    0x1e: "56-bit_bitmap",
    0x1f: "64-bit_bitmap",
    # Unsigned integer
    0x20: "Unsigned_8-bit_integer",
    0x21: "Unsigned_16-bit_integer",
    0x22: "Unsigned_24-bit_integer",
    0x23: "Unsigned_32-bit_integer",
    0x24: "Unsigned_40-bit_integer",
    0x25: "Unsigned_48-bit_integer",
    0x26: "Unsigned_56-bit_integer",
    0x27: "Unsigned_64-bit_integer",
    # Signed integer
    0x28: "Signed_8-bit_integer",
    0x29: "Signed_16-bit_integer",
    0x2a: "Signed_24-bit_integer",
    0x2b: "Signed_32-bit_integer",
    0x2c: "Signed_40-bit_integer",
    0x2d: "Signed_48-bit_integer",
    0x2e: "Signed_56-bit_integer",
    0x2f: "Signed_64-bit_integer",
    # Enumeration
    0x30: "8-bit_enumeration",
    0x31: "16-bit_enumeration",
    # Floating point
    0x38: "semi_precision",
    0x39: "single_precision",
    0x3a: "double_precision",
    # String
    0x41: "octet-string",
    0x42: "character_string",
    0x43: "long_octet_string",
    0x44: "long_character_string",
    # Ordered sequence
    0x48: "array",
    0x4c: "structure",
    # Collection
    0x50: "set",
    0x51: "bag",
    # Time
    0xe0: "time_of_day",
    0xe1: "date",
    0xe2: "utc_time",
    # Identifier
    0xe8: "cluster_id",
    0xe9: "attribute_id",
    0xea: "bacnet_oid",
    # Miscellaneous
    0xf0: "ieee_address",
    0xf1: "128-bit_security_key",
    # Unknown
    0xff: "unknown",
}


class ZigbeePayloadField(StrField): # passes the remaining length of the current frame to do a relational offset such as all but the last 4 bytes.
    def __init__(self, name, default, codec=None, fld=None, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from = length_from
    def getfield(self, pkt, s):
        l = self.length_from(pkt, s)
        if l <= 0:
            return s,""
        return s[l:], self.m2i(pkt,s[:l])

class ZigbeeNWK(Packet):
    name = "Zigbee Network Layer"
    fields_desc = [
                    BitField("discover_route", 0, 2),
                    BitField("proto_version", 2, 4),
                    BitEnumField("frametype", 0, 2, {0:'data', 1:'command'}),
                    FlagsField("flags", 0, 8, ['multicast', 'security', 'source_route', 'extended_dst', 'extended_src', 'reserved1', 'reserved2', 'reserved3']),
                    XLEShortField("destination", 0),
                    XLEShortField("source", 0),
                    ByteField("radius", 0),
                    ByteField("seqnum", 1),

                    ConditionalField(ByteField("relay_count", 1), lambda pkt:pkt.flags & 0x04),
                    ConditionalField(ByteField("relay_index", 0), lambda pkt:pkt.flags & 0x04),
                    ConditionalField(FieldListField("relays", [ ], XLEShortField("", 0x0000), count_from = lambda pkt:pkt.relay_count), lambda pkt:pkt.flags & 0x04),

                    #ConditionalField(XLongField("ext_dst", 0), lambda pkt:pkt.flags & 8),
                    ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.flags & 8),
                    #ConditionalField(XLongField("ext_src", 0), lambda pkt:pkt.flags & 16),
                    ConditionalField(dot15d4AddressField("ext_src", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.flags & 16),
                ]

    def guess_payload_class(self, payload):
        if self.flags & 0x02:
            return ZigbeeSecurityHeader
        elif self.frametype == 0:
            return ZigbeeAppDataPayload
        elif self.frametype == 1:
            return ZigbeeNWKCommandPayload
        else:
            return Packet.guess_payload_class(self, payload)

class LinkStatusEntry(Packet):
    name = "ZigBee Link Status Entry"
    fields_desc = [
        # Neighbor network address (2 octets)
        XLEShortField("neighbor_network_address", 0x0000),
        # Link status (1 octet)
        BitField("reserved1", 0, 1),
        BitField("outgoing_cost", 0, 3),
        BitField("reserved2", 0, 1),
        BitField("incoming_cost", 0, 3),
    ]

class ZigbeeNWKCommandPayload(Packet):
    name = "Zigbee Network Layer Command Payload"
    fields_desc = [
        ByteEnumField("cmd_identifier", 1, {
            1:"route request",
            2:"route reply",
            3:"network status",
            4:"leave",
            5:"route record",
            6:"rejoin request",
            7:"rejoin response",
            8:"link status",
            9:"network report",
            10:"network update"
            # 0x0b - 0xff reserved
        }),

        ### Route Request Command ###
        # Command options (1 octet)
        ConditionalField(BitField("reserved", 0, 1), lambda pkt:pkt.cmd_identifier == 1),
        ConditionalField(BitField("multicast", 0, 1), lambda pkt:pkt.cmd_identifier == 1),
        ConditionalField(BitField("dest_addr_bit", 0, 1), lambda pkt:pkt.cmd_identifier == 1),
        ConditionalField(
            BitEnumField("many_to_one", 0, 2, {
                0:"not_m2one", 1:"m2one_support_rrt", 2:"m2one_no_support_rrt", 3:"reserved"}
            ), lambda pkt:pkt.cmd_identifier == 1),
        ConditionalField(BitField("reserved", 0, 3), lambda pkt:pkt.cmd_identifier == 1),
        # Route request identifier (1 octet)
        ConditionalField(ByteField("route_request_identifier", 0), lambda pkt:pkt.cmd_identifier == 1),
        # Destination address (2 octets)
        ConditionalField(XLEShortField("destination_address", 0x0000), lambda pkt:pkt.cmd_identifier == 1),
        # Path cost (1 octet)
        ConditionalField(ByteField("path_cost", 0), lambda pkt:pkt.cmd_identifier == 1),
        # Destination IEEE Address (0/8 octets), only present when dest_addr_bit has a value of 1
        ConditionalField(dot15d4AddressField("ext_dst", 0, adjust=lambda pkt,x: 8),
            lambda pkt:(pkt.cmd_identifier == 1 and pkt.dest_addr_bit == 1)),

        ### Route Reply Command ###
        # Command options (1 octet)
        ConditionalField(BitField("reserved", 0, 1), lambda pkt:pkt.cmd_identifier == 2),
        ConditionalField(BitField("multicast", 0, 1), lambda pkt:pkt.cmd_identifier == 2),
        ConditionalField(BitField("responder_addr_bit", 0, 1), lambda pkt:pkt.cmd_identifier == 2),
        ConditionalField(BitField("originator_addr_bit", 0, 1), lambda pkt:pkt.cmd_identifier == 2),
        ConditionalField(BitField("reserved", 0, 4), lambda pkt:pkt.cmd_identifier == 2),
        # Route request identifier (1 octet)
        ConditionalField(ByteField("route_request_identifier", 0), lambda pkt:pkt.cmd_identifier == 2),
        # Originator address (2 octets)
        ConditionalField(XLEShortField("originator_address", 0x0000), lambda pkt:pkt.cmd_identifier == 2),
        # Responder address (2 octets)
        ConditionalField(XLEShortField("responder_address", 0x0000), lambda pkt:pkt.cmd_identifier == 2),
        # Path cost (1 octet)
        ConditionalField(ByteField("path_cost", 0), lambda pkt:pkt.cmd_identifier == 2),
        # Originator IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("originator_addr", 0, adjust=lambda pkt,x: 8),
            lambda pkt:(pkt.cmd_identifier == 2 and pkt.originator_addr_bit == 1)),
        # Responder IEEE address (0/8 octets)
        ConditionalField(dot15d4AddressField("responder_addr", 0, adjust=lambda pkt,x: 8),
            lambda pkt:(pkt.cmd_identifier == 2 and pkt.responder_addr_bit == 1)),

        ### Network Status Command ###
        # Status code (1 octet)
        ConditionalField(ByteEnumField("status_code", 0, {
            0x00: "No route available",
            0x01: "Tree link failure",
            0x02: "Non-tree link failure",
            0x03: "Low battery level",
            0x04: "No routing capacity",
            0x05: "No indirect capacity",
            0x06: "Indirect transaction expiry",
            0x07: "Target device unavailable",
            0x08: "Target address unallocated",
            0x09: "Parent link failure",
            0x0a: "Validate route",
            0x0b: "Source route failure",
            0x0c: "Many-to-one route failure",
            0x0d: "Address conflict",
            0x0e: "Verify addresses",
            0x0f: "PAN identifier update",
            0x10: "Network address update",
            0x11: "Bad frame counter",
            0x12: "Bad key sequence number",
            # 0x13 - 0xff Reserved
        }), lambda pkt:pkt.cmd_identifier == 3),
        # Destination address (2 octets)
        ConditionalField(XLEShortField("destination_address", 0x0000), lambda pkt:pkt.cmd_identifier == 3),

        ### Leave Command ###
        # Command options (1 octet)
        # Bit 7: Remove children
        ConditionalField(BitField("remove_children", 0, 1), lambda pkt:pkt.cmd_identifier == 4),
        # Bit 6: Request
        ConditionalField(BitField("request", 0, 1), lambda pkt:pkt.cmd_identifier == 4),
        # Bit 5: Rejoin
        ConditionalField(BitField("rejoin", 0, 1), lambda pkt:pkt.cmd_identifier == 4),
        # Bit 0 - 4: Reserved
        ConditionalField(BitField("reserved", 0, 5), lambda pkt:pkt.cmd_identifier == 4),

        ### Route Record Command ###
        # Relay count (1 octet)
        ConditionalField(ByteField("rr_relay_count", 0), lambda pkt:pkt.cmd_identifier == 5),
        # Relay list (variable in length)
        ConditionalField(
            FieldListField("rr_relay_list", [], XLEShortField("", 0x0000), count_from = lambda pkt:pkt.rr_relay_count),
            lambda pkt:pkt.cmd_identifier == 5),

        ### Rejoin Request Command ###
        # Capability Information (1 octet)
        ConditionalField(BitField("allocate_address", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Allocate Address
        ConditionalField(BitField("security_capability", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Security Capability
        ConditionalField(BitField("reserved2", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # bit 5 is reserved
        ConditionalField(BitField("reserved1", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # bit 4 is reserved
        ConditionalField(BitField("receiver_on_when_idle", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Receiver On When Idle
        ConditionalField(BitField("power_source", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Power Source
        ConditionalField(BitField("device_type", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Device Type
        ConditionalField(BitField("alternate_pan_coordinator", 0, 1), lambda pkt:pkt.cmd_identifier == 6), # Alternate PAN Coordinator

        ### Rejoin Response Command ###
        # Network address (2 octets)
        ConditionalField(XLEShortField("network_address", 0xFFFF), lambda pkt:pkt.cmd_identifier == 7),
        # Rejoin status (1 octet)
        ConditionalField(ByteField("rejoin_status", 0), lambda pkt:pkt.cmd_identifier == 7),

        ### Link Status Command ###
        # Command options (1 octet)
        ConditionalField(BitField("reserved", 0, 1), lambda pkt:pkt.cmd_identifier == 8), # Reserved
        ConditionalField(BitField("last_frame", 0, 1), lambda pkt:pkt.cmd_identifier == 8), # Last frame
        ConditionalField(BitField("first_frame", 0, 1), lambda pkt:pkt.cmd_identifier == 8), # First frame
        ConditionalField(BitField("entry_count", 0, 5), lambda pkt:pkt.cmd_identifier == 8), # Entry count
        # Link status list (variable size)
        ConditionalField(
            PacketListField("link_status_list", [], LinkStatusEntry, count_from = lambda pkt:pkt.entry_count),
            lambda pkt:pkt.cmd_identifier == 8),

        ### Network Report Command ###
        # Command options (1 octet)
        ConditionalField(
            BitEnumField("report_command_identifier", 0, 3, {0:"PAN identifier conflict"}), # 0x01 - 0x07 Reserved
            lambda pkt:pkt.cmd_identifier == 9),
        ConditionalField(BitField("report_information_count", 0, 5), lambda pkt:pkt.cmd_identifier == 9),
        # EPID: Extended PAN ID (8 octets)
        ConditionalField(dot15d4AddressField("epid", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.cmd_identifier == 9),
        # Report information (variable length)
        # Only present if we have a PAN Identifier Conflict Report
        ConditionalField(
            FieldListField("PAN_ID_conflict_report", [], XLEShortField("", 0x0000),
                count_from = lambda pkt:pkt.report_information_count),
            lambda pkt:(pkt.cmd_identifier == 9 and pkt.report_command_identifier == 0)
        ),

        ### Network Update Command ###
        # Command options (1 octet)
        ConditionalField(
            BitEnumField("update_command_identifier", 0, 3, {0:"PAN Identifier Update"}), # 0x01 - 0x07 Reserved
            lambda pkt:pkt.cmd_identifier == 10),
        ConditionalField(BitField("update_information_count", 0, 5), lambda pkt:pkt.cmd_identifier == 10),
        # EPID: Extended PAN ID (8 octets)
        ConditionalField(dot15d4AddressField("epid", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.cmd_identifier == 10),
        # Update Id (1 octet)
        ConditionalField(ByteField("update_id", 0), lambda pkt:pkt.cmd_identifier == 10),
        # Update Information (Variable)
        # Only present if we have a PAN Identifier Update
        # New PAN ID (2 octets)
        ConditionalField(XLEShortField("new_PAN_ID", 0x0000),
            lambda pkt:(pkt.cmd_identifier == 10 and pkt.update_command_identifier == 0)),

        #ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)),
    ]

### ZigBee Cluster Library ###

def util_zcl_attribute_value_len(pkt):
    # Calculate the length of the attribute value field
    if ( pkt.attribute_data_type == 0x00 ): # no data
        return 0
    elif ( pkt.attribute_data_type == 0x08 ): # 8-bit data
        return 1
    elif ( pkt.attribute_data_type == 0x09 ): # 16-bit data
        return 2
    elif ( pkt.attribute_data_type == 0x0a ): # 24-bit data
        return 3
    elif ( pkt.attribute_data_type == 0x0b ): # 32-bit data
        return 4
    elif ( pkt.attribute_data_type == 0x0c ): # 40-bit data
        return 5
    elif ( pkt.attribute_data_type == 0x0d ): # 48-bit data
        return 6
    elif ( pkt.attribute_data_type == 0x0e ): # 56-bit data
        return 7
    elif ( pkt.attribute_data_type == 0x0f ): # 64-bit data
        return 8
    elif ( pkt.attribute_data_type == 0x10 ): # boolean
        return 1
    elif ( pkt.attribute_data_type == 0x18 ): # 8-bit bitmap
        return 1
    elif ( pkt.attribute_data_type == 0x19 ): # 16-bit bitmap
        return 2
    elif ( pkt.attribute_data_type == 0x1a ): # 24-bit bitmap
        return 3
    elif ( pkt.attribute_data_type == 0x1b ): # 32-bit bitmap
        return 4
    elif ( pkt.attribute_data_type == 0x1c ): # 40-bit bitmap
        return 5
    elif ( pkt.attribute_data_type == 0x1d ): # 48-bit bitmap
        return 6
    elif ( pkt.attribute_data_type == 0x1e ): # 46-bit bitmap
        return 7
    elif ( pkt.attribute_data_type == 0x1f ): # 64-bit bitmap
        return 8
    elif ( pkt.attribute_data_type == 0x20 ): # Unsigned 8-bit integer
        return 1
    elif ( pkt.attribute_data_type == 0x21 ): # Unsigned 16-bit integer
        return 2
    elif ( pkt.attribute_data_type == 0x22 ): # Unsigned 24-bit integer
        return 3
    elif ( pkt.attribute_data_type == 0x23 ): # Unsigned 32-bit integer
        return 4
    elif ( pkt.attribute_data_type == 0x24 ): # Unsigned 40-bit integer
        return 5
    elif ( pkt.attribute_data_type == 0x25 ): # Unsigned 48-bit integer
        return 6
    elif ( pkt.attribute_data_type == 0x26 ): # Unsigned 56-bit integer
        return 7
    elif ( pkt.attribute_data_type == 0x27 ): # Unsigned 64-bit integer
        return 8
    elif ( pkt.attribute_data_type == 0x28 ): # Signed 8-bit integer
        return 1
    elif ( pkt.attribute_data_type == 0x29 ): # Signed 16-bit integer
        return 2
    elif ( pkt.attribute_data_type == 0x2a ): # Signed 24-bit integer
        return 3
    elif ( pkt.attribute_data_type == 0x2b ): # Signed 32-bit integer
        return 4
    elif ( pkt.attribute_data_type == 0x2c ): # Signed 40-bit integer
        return 5
    elif ( pkt.attribute_data_type == 0x2d ): # Signed 48-bit integer
        return 6
    elif ( pkt.attribute_data_type == 0x2e ): # Signed 56-bit integer
        return 7
    elif ( pkt.attribute_data_type == 0x2f ): # Signed 64-bit integer
        return 8
    elif ( pkt.attribute_data_type == 0x30 ): # 8-bit enumeration
        return 1
    elif ( pkt.attribute_data_type == 0x31 ): # 16-bit enumeration
        return 2
    elif ( pkt.attribute_data_type == 0x38 ): # Semi-precision
        return 2
    elif ( pkt.attribute_data_type == 0x39 ): # Single precision
        return 4
    elif ( pkt.attribute_data_type == 0x3a ): # Double precision
        return 8
    elif ( pkt.attribute_data_type == 0x41 ): # Octet string
        return int(pkt.attribute_value[0]) # defined in first octet
    elif ( pkt.attribute_data_type == 0x42 ): # Character string
        return int(pkt.attribute_value[0]) # defined in first octet
    elif ( pkt.attribute_data_type == 0x43 ): # Long octet string
        return int(pkt.attribute_value[0:2]) # defined in first two octets
    elif ( pkt.attribute_data_type == 0x44 ): # Long character string
        return int(pkt.attribute_value[0:2]) # defined in first two octets
    # TODO implement Ordered sequence & collection
    elif ( pkt.attribute_data_type == 0xe0 ): # Time of day
        return 4
    elif ( pkt.attribute_data_type == 0xe1 ): # Date
        return 4
    elif ( pkt.attribute_data_type == 0xe2 ): # UTCTime
        return 4
    elif ( pkt.attribute_data_type == 0xe8 ): # Cluster ID
        return 2
    elif ( pkt.attribute_data_type == 0xe9 ): # Attribute ID
        return 2
    elif ( pkt.attribute_data_type == 0xea ): # BACnet OID
        return 4
    elif ( pkt.attribute_data_type == 0xf0 ): # IEEE address
        return 8
    elif ( pkt.attribute_data_type == 0xf1 ): # 128-bit security key
        return 16
    elif ( pkt.attribute_data_type == 0xff ): # Unknown
        return 0
    else:
        return 0


class ZCLReadAttributeStatusRecord(Packet):
    name = "ZCL Read Attribute Status Record"
    fields_desc = [
        # Attribute Identifier
        XLEShortField("attribute_identifier", 0),
        # Status
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
        # Attribute data type (0/1 octet), only included if status == 0x00 (SUCCESS)
        ConditionalField(
            ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
            lambda pkt:pkt.status == 0x00
        ),
        # Attribute data (0/variable in size), only included if status == 0x00 (SUCCESS)
        ConditionalField(
            StrLenField("attribute_value", "", length_from=lambda pkt:util_zcl_attribute_value_len(pkt) ),
            lambda pkt:pkt.status == 0x00
        ),
    ]

class ZCLGeneralReadAttributes(Packet):
    name = "General Domain: Command Frame Payload: read_attributes"
    fields_desc = [
        FieldListField("attribute_identifiers", [], XLEShortField("", 0x0000) ),
    ]

class ZCLGeneralReadAttributesResponse(Packet):
    name = "General Domain: Command Frame Payload: read_attributes_response"
    fields_desc = [
        PacketListField("read_attribute_status_record", [], ZCLReadAttributeStatusRecord),
    ]

class ZCLMeteringGetProfile(Packet):
    name = "Metering Cluster: Get Profile Command (Server: Received)"
    fields_desc = [
        # Interval Channel (8-bit Enumeration): 1 octet
        ByteField("Interval_Channel", 0), # 0 == Consumption Delivered ; 1 == Consumption Received
        # End Time (UTCTime): 4 octets
        XLEIntField("End_Time", 0x00000000),
        # NumberOfPeriods (Unsigned 8-bit Integer): 1 octet
        ByteField("NumberOfPeriods", 1), # Represents the number of intervals being requested.
    ]

class ZCLPriceGetCurrentPrice(Packet):
    name = "Price Cluster: Get Current Price Command (Server: Received)"
    fields_desc = [
        BitField("reserved", 0, 7),
        BitField("Requestor_Rx_On_When_Idle", 0, 1),
    ]

class ZCLPriceGetScheduledPrices(Packet):
    name = "Price Cluster: Get Scheduled Prices Command (Server: Received)"
    fields_desc = [
        XLEIntField("start_time", 0x00000000), # UTCTime (4 octets)
        ByteField("number_of_events", 0), # Number of Events (1 octet)
    ]

class ZCLPricePublishPrice(Packet):
    name = "Price Cluster: Publish Price Command (Server: Generated)"
    fields_desc = [
        XLEIntField("provider_id", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        # Rate Label is a UTF-8 encoded Octet String (0-12 octets). The first Octet indicates the length.
        StrLenField("rate_label", "", length_from=lambda pkt:int(pkt.rate_label[0]) ), # TODO verify
        XLEIntField("issuer_event_id", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        XLEIntField("current_time", 0x00000000), # UTCTime (4 octets)
        ByteField("unit_of_measure", 0), # 8 bits enumeration (1 octet)
        XLEShortField("currency", 0x0000), # Unsigned 16-bit Integer (2 octets)
        ByteField("price_trailing_digit", 0), # 8-bit BitMap (1 octet)
        ByteField("number_of_price_tiers", 0), # 8-bit BitMap (1 octet)
        XLEIntField("start_time", 0x00000000), # UTCTime (4 octets)
        XLEShortField("duration_in_minutes", 0x0000), # Unsigned 16-bit Integer (2 octets)
        XLEIntField("price", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        ByteField("price_ratio", 0), # Unsigned 8-bit Integer (1 octet)
        XLEIntField("generation_price", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        ByteField("generation_price_ratio", 0), # Unsigned 8-bit Integer (1 octet)
        XLEIntField("alternate_cost_delivered", 0x00000000), # Unsigned 32-bit Integer (4 octets)
        ByteField("alternate_cost_unit", 0), # 8-bit enumeration (1 octet)
        ByteField("alternate_cost_trailing_digit", 0), # 8-bit BitMap (1 octet)
        ByteField("number_of_block_thresholds", 0), # 8-bit BitMap (1 octet)
        ByteField("price_control", 0), # 8-bit BitMap (1 octet)
    ]

class ZigbeeClusterLibrary(Packet):
    name = "Zigbee Cluster Library (ZCL) Frame"
    fields_desc = [
        # Frame control (8 bits)
        BitField("reserved", 0, 3),
        BitField("disable_default_response", 0, 1), # 0 default response command will be returned
        BitField("direction", 0, 1), # 0 command sent from client to server; 1 command sent from server to client
        BitField("manufacturer_specific", 0, 1), # 0 manufacturer code shall not be included in the ZCL frame
        # Frame Type
        # 0b00 command acts across the entire profile
        # 0b01 command is specific to a cluster
        # 0b10 - 0b11 reserved
        BitField("zcl_frametype", 0, 2),
        # Manufacturer code (0/16 bits) only present then manufacturer_specific field is set to 1
        ConditionalField(XLEShortField("manufacturer_code", 0x0),
            lambda pkt:pkt.getfieldval("manufacturer_specific") == 1
        ),
        # Transaction sequence number (8 bits)
        ByteField("transaction_sequence", 0),
        # Command identifier (8 bits): the cluster command
        ByteEnumField("command_identifier", 0, _zcl_command_frames),
    ]

    def guess_payload_class(self, payload):
        # General Cluster ID Range 0x0000 - 0x00FF
        if self.command_identifier == 0x00 and 0x0000 <= self.cluster <= 0x00FF:
            return ZCLGeneralReadAttributes
        elif self.command_identifier == 0x01 and 0x0000 <= self.cluster <= 0x00FF:
            return ZCLGeneralReadAttributesResponse
        elif self.command_identifier == 0x00 and self.direction == 0 and self.cluster == "price":
            return ZCLPriceGetCurrentPrice
        elif self.command_identifier == 0x01 and self.direction == 0 and self.cluster == "price":
            return ZCLPriceGetScheduledPrices
        elif self.command_identifier == 0x00 and self.direction == 1 and self.cluster == "price":
            return ZCLPricePublishPrice
        else:
            return Packet.guess_payload_class(self, payload)

class ZigbeeDeviceProfile(Packet):
    name = "Zigbee Device Profile (ZDP) frame"
    fields_desc = [
        # sequence number (8 bits)
        ByteField("sequence_number", 0),
        # Device short address
        XLEShortField("device", 0x0000)
    ]

    def guess_payload_class(self, payload):
    	return Packet.guess_payload_class(self, payload)

### Inter-PAN Transmission ###
class ZigbeeNWKStub(Packet):
    name = "Zigbee Network Layer for Inter-PAN Transmission"
    fields_desc = [
        # NWK frame control
        BitField("reserved", 0, 2), # remaining subfields shall have a value of 0
        BitField("proto_version", 2, 4),
        BitField("frametype", 0b11, 2), # 0b11 (3) is a reserved frame type
        BitField("reserved", 0, 8), # remaining subfields shall have a value of 0
    ]

    def guess_payload_class(self, payload):
        if self.frametype == 0b11:
            return ZigbeeAppDataPayloadStub
        else:
            return Packet.guess_payload_class(self, payload)

class ZigbeeAppDataPayloadStub(Packet):
    name = "Zigbee Application Layer Data Payload for Inter-PAN Transmission"
    fields_desc = [
        FlagsField("frame_control", 0, 4, [ 'reserved1', 'security', 'ack_req', 'extended_hdr' ]),
        BitEnumField("delivery_mode", 0, 2, {0:'unicast', 2:'broadcast', 3:'group'}),
        BitField("frametype", 3, 2), # value 0b11 (3) is a reserved frame type
        # Group Address present only when delivery mode field has a value of 0b11 (group delivery mode)
        ConditionalField(
            XLEShortField("group_addr", 0x0), # 16-bit identifier of the group
            lambda pkt:pkt.getfieldval("delivery_mode") == 0b11
        ),
        # Cluster identifier
        EnumField("cluster", 0, _zcl_cluster_identifier, fmt = "<H"), # unsigned short (little-endian)
        # Profile identifier
        EnumField("profile", 0, _zcl_profile_identifier, fmt = "<H"),
        # ZigBee Payload
        ConditionalField(
            ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)),
            lambda pkt:pkt.frametype == 3
        ),
    ]

# PAN ID conflict notification command frame is not necessary, only Dot15d4Cmd with cmd_id = 5 ("PANIDConflictNotify")
# Orphan notification command not necessary, only Dot15d4Cmd with cmd_id = 6 ("OrphanNotify")

class ZigBeeBeacon(Packet):
    name = "ZigBee Beacon Payload"
    fields_desc = [
        # Protocol ID (1 octet)
        ByteField("proto_id", 0),
        # nwkcProtocolVersion (4 bits)
        BitField("nwkc_protocol_version", 0, 4),
        # Stack profile (4 bits)
        BitField("stack_profile", 0, 4),
        # End device capacity (1 bit)
        BitField("end_device_capacity", 0, 1),
        # Device depth (4 bits)
        BitField("device_depth", 0, 4),
        # Router capacity (1 bit)
        BitField("router_capacity", 0, 1),
        # Reserved (2 bits)
        BitField("reserved", 0, 2),
        # Extended PAN ID (8 octets)
        dot15d4AddressField("extended_pan_id", 0, adjust=lambda pkt,x: 8),
        # Tx offset (3 bytes)
        # In ZigBee 2006 the Tx-Offset is optional, while in the 2007 and later versions, the Tx-Offset is a required value.
        BitField("tx_offset", 0, 24),
        # Update ID (1 octet)
        ByteField("update_id", 0),
    ]

class ZigbeeSecurityHeader(Packet):
    name = "Zigbee Security Header"
    fields_desc = [
        # Security control (1 octet)
        HiddenField(FlagsField("reserved1", 0, 2, [ 'reserved1', 'reserved2' ]), True),
        BitField("extended_nonce", 1, 1), # set to 1 if the sender address field is present (source)
        # Key identifier
        BitEnumField("key_type", 1, 2, {
            0:'data_key',
            1:'network_key',
            2:'key_transport_key',
            3:'key_load_key'
        }),
        # Security level (3 bits)
        BitEnumField("nwk_seclevel", 0, 3, {
            0:"None",
            1:"MIC-32",
            2:"MIC-64",
            3:"MIC-128",
            4:"ENC",
            5:"ENC-MIC-32",
            6:"ENC-MIC-64",
            7:"ENC-MIC-128"
        }),
        # Frame counter (4 octets)
        XLEIntField("fc", 0), # provide frame freshness and prevent duplicate frames
        # Source address (0/8 octets)
        ConditionalField(dot15d4AddressField("source", 0, adjust=lambda pkt,x: 8), lambda pkt:pkt.extended_nonce),
        # Key sequence number (0/1 octet): only present when key identifier is 1 (network key)
        ConditionalField(ByteField("key_seqnum", 0), lambda pkt:pkt.getfieldval("key_type") == 1),
        # Payload
        # the length of the encrypted data is the payload length minus the MIC
        ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)-ZigbeeSecurityHeader.util_mic_len(pkt) ),
        # Message Integrity Code (0/variable in size), length depends on nwk_seclevel
        StrLenField("mic", "", length_from=lambda pkt:ZigbeeSecurityHeader.util_mic_len(pkt) ),
    ]

    def util_mic_len(pkt):
        ''' Calculate the length of the attribute value field '''
        if ( pkt.nwk_seclevel == 0 ): # no encryption, no mic
            return 0
        elif ( pkt.nwk_seclevel == 1 ): # MIC-32
            return 4
        elif ( pkt.nwk_seclevel == 2 ): # MIC-64
            return 8
        elif ( pkt.nwk_seclevel == 3 ): # MIC-128
            return 16
        elif ( pkt.nwk_seclevel == 4 ): # ENC
            return 0
        elif ( pkt.nwk_seclevel == 5 ): # ENC-MIC-32
            return 4
        elif ( pkt.nwk_seclevel == 6 ): # ENC-MIC-64
            return 8
        elif ( pkt.nwk_seclevel == 7 ): # ENC-MIC-128
            return 16
        else:
            return 0


class ZigbeeAppDataPayload(Packet):
    name = "Zigbee Application Layer Data Payload (General APS Frame Format)"
    fields_desc = [
        # Frame control (1 octet)
        FlagsField("frame_control", 2, 4, [ 'reserved1', 'security', 'ack_req', 'extended_hdr' ]),
        BitEnumField("delivery_mode", 0, 2, {0:'unicast', 1:'indirect', 2:'broadcast', 3:'group_addressing'}),
        BitEnumField("aps_frametype", 0, 2, {0:'data', 1:'command', 2:'ack'}),
        # Destination endpoint (0/1 octet)
        ConditionalField(ByteField("dst_endpoint", 10), lambda pkt:(pkt.frame_control & 0x04 or pkt.aps_frametype == 0)),
        # Group address (0/2 octets) TODO
        # Cluster identifier (0/2 octets)
        ConditionalField(EnumField("cluster", 0, _zcl_cluster_identifier, fmt = "<H"), # unsigned short (little-endian)
            lambda pkt:(pkt.frame_control & 0x04 or pkt.aps_frametype == 0)
        ),
        # Profile identifier (0/2 octets)
        ConditionalField(EnumField("profile", 0, _zcl_profile_identifier, fmt = "<H"),
            lambda pkt:(pkt.frame_control & 0x04 or pkt.aps_frametype == 0)
        ),
        # Source endpoint (0/1 octets)
        ConditionalField(ByteField("src_endpoint", 10), lambda pkt:(pkt.frame_control & 0x04 or pkt.aps_frametype == 0)),
        # APS counter (1 octet)
        ByteField("counter", 0),
        # optional extended header
        # variable length frame payload: 3 frame types: data, APS command, and acknowledgement
        #ConditionalField(ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)), lambda pkt:pkt.aps_frametype == 0),
    ]

    def guess_payload_class(self, payload):
        if self.frame_control & 0x02: # we have a security header
            return ZigbeeSecurityHeader
        elif self.aps_frametype == 0: # data
	    if self.profile == 0:
		return ZigbeeDeviceProfile
            return ZigbeeClusterLibrary # TODO might also be another frame
        elif self.aps_frametype == 1: # command
            return ZigbeeAppCommandPayload
        else:
            return Packet.guess_payload_class(self, payload)


class ZigbeeAppCommandPayload(Packet):
    name = "Zigbee Application Layer Command Payload"
    fields_desc = [
        ByteEnumField("cmd_identifier", 1, {
            1:"APS_CMD_SKKE_1",
            2:"APS_CMD_SKKE_2",
            3:"APS_CMD_SKKE_3",
            4:"APS_CMD_SKKE_4",
            5:"APS_CMD_TRANSPORT_KEY",
            6:"APS_CMD_UPDATE_DEVICE",
            7:"APS_CMD_REMOVE_DEVICE",
            8:"APS_CMD_REQUEST_KEY",
            9:"APS_CMD_SWITCH_KEY",
            10:"APS_CMD_EA_INIT_CHLNG",
            11:"APS_CMD_EA_RSP_CHLNG",
            12:"APS_CMD_EA_INIT_MAC_DATA",
            13:"APS_CMD_EA_RSP_MAC_DATA",
            14:"APS_CMD_TUNNEL"
        }),
        ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)),
    ]


#bind_layers( Dot15d4Data, ZigbeeNWK)
bind_layers( ZigbeeAppDataPayload, ZigbeeAppCommandPayload, frametype=1)
bind_layers( Dot15d4Beacon, ZigBeeBeacon )
