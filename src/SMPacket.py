import pyshark
import struct

SMP_CODE = {
    0x01: "smp_pairing_req",
    0x02: "smp_pairing_rsp",
    0x03: "smp_pairing_confirm",
    0x04: "smp_pairing_random",
    0x05: "smp_pairing_failed",
    0x06: "smp_encrypt_info",
    0x07: "smp_central_ident",
    0x08: "smp_ident_info",
    0x09: "smp_ident_addr_info",
    0x0a: "smp_signing_info",
    # Peripheral -> Central; The Security Request command is used by the Peripheral to request that the Central initiates security with the requested security properties, see Section 2.4.6. The Security Request command is defined in Figure 3.17.
    0x0b: "smp_security_request",
    # Central -> Peripheral | Peripheral -> Central;
    0x0c: "smp_public_key",
    # Central -> Peripheral | Peripheral -> Central;
    0x0d: "smp_dhkey_check",
    0x0e: "smp_keypress_notif",
}

# TODO: 仅比较resp中非随机数的部分
SMP_COMPARABLE_CODE = {
    0x01: ["io_capability"],
    0x02: [],
    0x03: [],
    0x04: [],
    0x05: [],
    0x06: [],
    0x07: [],
    0x08: [],
    0x09: [],
    0x0a: [],
    # Peripheral -> Central; The Security Request command is used by the Peripheral to request that the Central initiates security with the requested security properties, see Section 2.4.6. The Security Request command is defined in Figure 3.17.
    0x0b: [],
    # Central -> Peripheral | Peripheral -> Central;
    0x0c: [],
    # Central -> Peripheral | Peripheral -> Central;
    0x0d: [],
    0x0e: [],
}

smp_pkt_field = {
    "smp_pairing_req": [
        "io_capability", "oob_data_flags", "authreq", "max_enc_key_size", "initiator_key_distribution",
        "responder_key_distribution"
    ],  # 0x01
    "smp_pairing_rsp": [
        "io_capability",
        "oob_data_flags",
        "authreq",
        "max_enc_key_size",
        "initiator_key_distribution",
        "responder_key_distribution",
    ],  # 0x02
    "smp_pairing_confirm": ["cfm_value",],  # 0x03
    "smp_pairing_random": ["random_value",],  # 0x04
    "smp_encrypt_info": ["long_term_key",],  # 0x06
    "smp_central_ident": [
        "ediv",
        "random_value",
    ],  # 0x07
    "smp_ident_info": ["id_resolving_key",],  # 0x08
    "smp_ident_addr_info": [
        "address_type",
        "bd_addr",
    ],  # 0x09
    "smp_public_key": ["long_term_key",],  # 0x0c
    "smp_dhkey_check": ["dhkey_check",],  # 0x0d
}


#########################
# SMP socket
#########################
class SMPSocket:

    def __init__(self):
        self.socket = 0

    def send(self, data):
        print(f"send {data}")

    def recv(self):
        return "123"

    def close(self):
        pass

    def reset(self):
        pass


# BLE SMP protocol packet class
class SMPacket:

    # def __init__(self, packet_cap):
    #     entire_pkt = pyshark.FileCapture(packet_cap, display_filter='btsmp', use_json=True, include_raw=True)[0]
    #     smp_pkt = entire_pkt.btsmp
    #     opcode = int(smp_pkt.get_field("opcode"), 16)

    #     self.raw_packet = entire_pkt.get_raw_packet()[27:-3]
    #     self.packet_type = SMP_CODE[opcode]
    #     self.content = {}

    #     pkt_fields = smp_pkt_field[self.packet_type]
    #     for item in smp_pkt.field_names:
    #         if item in pkt_fields:
    #             self.content[item] = smp_pkt.get_field(item + "_raw")[0]

    def __init__(self, hex_data):
        # smp_pairing_req = "0104002d100f0f"
        self.raw_packet = bytes.fromhex(hex_data)
        fields = self.parse(self.raw_packet)
        self.content = {"code": fields[0], "data": fields[1]}
        self.packet_type = self.content["code"]

    def parse(self, data):
        code = struct.unpack("<B", data[:1])[0]
        return (code, data[1:])

    # 仅比较resp中非随机数的部分
    def CompareTo(self, packet: SMPSocket):
        if (self.packet_type != packet.packet_type):
            return False
        else:
            for field in SMP_COMPARABLE_CODE[self.packet_type]:
                if (field in list(self.content.keys()) and field in list(packet.content.keys()) and
                        self.content[field] != packet.content[field]):
                    return False
        return True

        # differ = set(self.content.items()) ^ set(packet.content.items())
        # if (differ != set()):
        #     return True
        # else:
        #     return False
