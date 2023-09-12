import pyshark
import struct
import serial
import serial.tools.list_ports
import time

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
    0x0f: "",
}

# TODO: 仅比较resp中非随机数的部分
SMP_COMPARABLE_CODE = {
    0x01: [
        "io_capability", "oob_data_flags", "authreq", "max_enc_key_size", "initiator_key_distribution",
        "responder_key_distribution"
    ],
    0x02: [
        "io_capability", "oob_data_flags", "authreq", "max_enc_key_size", "initiator_key_distribution",
        "responder_key_distribution"
    ],
    0x03: [],
    0x04: [],
    0x05: ["reason"],
    0x06: [],
    0x07: [],
    0x08: [],
    0x09: ["address_type", "bd_addr"],
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
    "smp_pairing_fail": ["reason"],  # 0x05
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
        self.ser = serial.Serial("COM3", 115200, timeout=3)

    def send(self, data):
        write_len = self.ser.write(data)

    def recv(self):
        real_buf = b''
        try:
            while True:
                com_input = self.ser.read()
                if com_input:
                    real_buf += com_input
                    if (real_buf[-4:] == b"fxxk"):
                        real_buf = real_buf[:-4]
                        return real_buf
                else:
                    return b''
                    if (real_buf == b''):
                        continue
                    if (real_buf[-4:] == b"fxxk"):
                        real_buf = real_buf[:-4]
                        return real_buf
        except Exception:
            return b''

    def close(self):
        pass

    def reset(self):
        ser = serial.Serial("COM3", 115200)
        ser.write(b'\x05')
        ser.close()


class SMPSocket_TEST:

    def __init__(self):
        self.socket = 0

    def send(self, data):
        print(f"send {data}")

    def recv(self):
        return b"123"

    def close(self):
        pass

    def reset(self):
        pass


# BLE SMP protocol packet class
class SMPacket:
    raw_packet = None
    content = {}
    packet_type = None

    def __init__(self, hex_data):
        # smp_pairing_req = "0104002d100f0f"
        self.raw_packet = bytes.fromhex(hex_data)
        fields = self.parse(self.raw_packet)
        self.code = fields[0]
        self.data = fields[1]
        self.content = {"code": fields[0]}
        self.packet_type = self.content["code"]
        self.parse_fields(SMP_CODE[self.packet_type])

    def parse(self, data):
        code = struct.unpack("<B", data[:1])[0]
        return (code, data[1:])

    def parse_fields(self, packet_type):
        if packet_type == "smp_pairing_req":
            self.content["io_capability"], self.content["oob_data_flags"], self.content["authreq"], self.content[
                "max_enc_key_size"], self.content["initiator_key_distribution"], self.content[
                    "responder_key_distribution"] = self.parse_pair_req(self.data)
        elif packet_type == "smp_pairing_rsp":
            self.content["io_capability"], self.content["oob_data_flags"], self.content["authreq"], self.content[
                "max_enc_key_size"], self.content["initiator_key_distribution"], self.content[
                    "responder_key_distribution"] = self.parse_pair_rsp(self.data)
        elif packet_type == "smp_pairing_confirm":
            self.content["cfm_value"] = self.parse_pair_confirm(self.data)
        elif packet_type == "smp_pairing_random":
            self.content["random_value"] = self.parse_pair_random(self.data)
        elif packet_type == "smp_encrypt_info":
            self.content["long_term_key"] = self.parse_encrypt_info(self.data)
        elif packet_type == "smp_central_ident":
            self.content["ediv"], self.content["random_value"] = self.parse_central_ident(self.data)
        elif packet_type == "smp_ident_info":
            self.content["id_resolving_key"] = self.parse_ident_info(self.data)
        elif packet_type == "smp_ident_addr_info":
            self.content["address_type"], self.content["bd_addr"] = self.parse_ident_addr_info(self.data)
        elif packet_type == "smp_public_key":
            self.content["long_term_key"] = self.parse_public_key(self.data)
        elif packet_type == "smp_dhkey_check":
            self.content["dhkey_check"] = self.parse_dhkey_check(self.data)

    def parse_pair_req(self, data):
        io_capability, oob_data_flags, authreq, max_enc_key_size, initiator_key_distribution, responder_key_distribution = struct.unpack(
            "<BBBBBB", data[:6])
        return (io_capability, oob_data_flags, authreq, max_enc_key_size, initiator_key_distribution,
                responder_key_distribution)

    def parse_pair_rsp(self, data):
        io_capability, oob_data_flags, authreq, max_enc_key_size, initiator_key_distribution, responder_key_distribution = struct.unpack(
            "<BBBBBB", data[:6])
        return (io_capability, oob_data_flags, authreq, max_enc_key_size, initiator_key_distribution,
                responder_key_distribution)

    def parse_pair_confirm(self, data):
        cfm_value = data
        return cfm_value

    def parse_pair_random(self, data):
        random_value = data
        return random_value

    def parse_encrypt_info(self, data):
        long_term_key = data
        return long_term_key

    def parse_central_ident(self, data):
        ediv, random_value = struct.unpack("<2s8s", data[:10])
        return ediv, random_value

    def parse_ident_info(self, data):
        id_resolving_key = data
        return id_resolving_key

    def parse_ident_addr_info(self, data):
        address_type, bd_addr = struct.unpack("<B6s", data[:7])
        return address_type, bd_addr

    def parse_public_key(self, data):
        long_term_key = data
        return long_term_key

    def parse_dhkey_check(self, data):
        dhkey_check = data
        return dhkey_check

    def get_raw_data(self):
        raw_data = b''
        for key, value in self.content.items():
            if (isinstance(value, bytes)):
                raw_data += bytes(value)
            else:
                t = hex(value)[2:]
                t = t.zfill(len(t) if (len(t) % 2 == 0) else (len(t) // 2 + 1) * 2)
                t = bytes.fromhex(t)
                t = list(t)
                t.reverse()
                raw_data += bytes(t)
        return raw_data

    # 仅比较resp中非随机数的部分
    def CompareTo(self, packet):
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

    def MutatePacket(self, mutation_list):
        mutation_list = mutation_list[self.code]
        ret_packet = SMPacket(self.get_raw_data().hex())
        packet_type = SMP_CODE[ret_packet.content["code"]]
        for mut in mutation_list:
            ret_packet.content[smp_pkt_field[packet_type][mut]] = mutation_list[mut]
        ret_packet.raw_packet = ret_packet.get_raw_data()
        return ret_packet


# [deprecated] update BLE SMP protocol packet class
class SMPacket_V01:

    def __init__(self, entire_pkt, direction):
        smp_pkt = entire_pkt.btsmp
        opcode = int(smp_pkt.get_field("opcode"), 16)

        self.raw_packet = entire_pkt.get_raw_packet()[27:-3]
        self.packet_type = SMP_CODE[opcode]
        self.content = {}
        self.direction = direction

        pkt_fields = smp_pkt_field[self.packet_type]
        # print("pkt field",pkt_fields)
        for item in smp_pkt.field_names:
            if item in pkt_fields:
                self.content[item] = smp_pkt.get_field(item + "_raw")[0]

    # TODO: 仅比较resp中非随机数的部分
    def CompareTo(self, packet):
        return False
        differ = set(self.content.items()) ^ set(packet.content.items())
        if (differ != set()):
            return True
        else:
            return False

    # display the smp packet info
    def PrintSMPacket(self):
        print("SMP type: {}\t SMP content: {}\t SMP direction:{}\t raw:{}".format(self.packet_type, self.content,
                                                                                  self.direction, self.raw_packet))

    def to_raw(self):
        for key, value in SMP_CODE.items():
            if value == self.packet_type:
                opcode = key
        hex_string = "0" + str(opcode)
        for field in smp_pkt_field[self.packet_type]:
            hex_string += self.content[field]
        result = bytearray.fromhex(hex_string)
        return result


# [deprecated]
class SMPacketSequnce:

    def __init__(self, packet_cap):
        self.pkt_sequnce = []
        entire_pkts = pyshark.FileCapture(packet_cap, display_filter='btsmp', use_json=True, include_raw=True)
        for entire_pkt in entire_pkts:
            # print(entire_pkt)
            # print("direction",dir(entire_pkt.nordic_ble.flags_tree.direction))
            direction_value = entire_pkt.nordic_ble.flags_tree.direction
            if direction_value == "0":
                direction = "slave2master"
            else:
                direction = "master2slave"
            self.pkt_sequnce.append(SMPacket(entire_pkt, direction=direction))


if __name__ == '__main__':
    testp = SMPacket("0756be784bc11345c6fb16")
    print(testp.content)
