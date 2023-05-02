import pyshark
import serial
import serial.tools.list_ports
import sys

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
        ser = serial.Serial("COM11", 115200)
        write_len = ser.write(data)
        ser.close()

    def recv(self):
        ser = serial.Serial("COM11", 115200)
        real_buf = ''
        while True:
            com_input = ser.read()
            if com_input:
                real_buf += com_input
            else:
                return real_buf
        ser.close()

    def close(self):
        pass

    def reset(self):
        pass


# # old BLE SMP protocol packet class
"""
class SMPacket:

    def __init__(self, packet_cap):
        entire_pkt = pyshark.FileCapture(packet_cap, display_filter='btsmp', use_json=True, include_raw=True)[0]
        smp_pkt = entire_pkt.btsmp
        opcode = int(smp_pkt.get_field("opcode"), 16)

        self.raw_packet = entire_pkt.get_raw_packet()[27:-3]
        self.packet_type = SMP_CODE[opcode]
        self.content = {}

        pkt_fields = smp_pkt_field[self.packet_type]
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
"""
            
# update BLE SMP protocol packet class
class SMPacket:
    def __init__(self, entire_pkt , direction):
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
        print("SMP type: {}\t SMP content: {}\t SMP direction:{}".format(self.packet_type,self.content,self.direction))

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
            self.pkt_sequnce.append(SMPacket(entire_pkt,direction = direction))
            

# if __name__ == '__main__':
#     smpacket_seq = SMPacketSequnce(sys.path[0] + "/packet_sequence/earphoe_legacy_justwork.pcapng")
#     for smpacket in smpacket_seq.pkt_sequnce:
#         smpacket.PrintSMPacket()
    
