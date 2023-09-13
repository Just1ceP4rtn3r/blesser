#########################
# Mutator & Executor Module
#########################
import random
import string
import sys
import copy

from SMPacket import SMPacketSequnce, SMPacket


class SMPMutator:
    '''
    1. 初始语料库+初始概率
    2. 基于现有的概率，选择method、packet、state等进行真实的变异
    '''

    # TODO: Initiate the mutator with {alphabet/real packet, spec constraints}
    def __init__(self, alphabet=None, spec_constraints=None):
        self.MutateConstraints()

    def MutateConstraints(self):
        # mutate methods probabilities
        self.method_prob = {
            "random": 0.5,
            "increment": 0.5,
            "decrement": 0.5,
            "flip": 0.5,
            "swap": 0.5,
            # "insert": 0.5,
            # "delete": 0.5,
            "replace": 0.5,
            "shuffle": 0.5
        }
        # packet type probabilities
        self.packet_prob = {
            "smp_pairing_req": 0.5,
            "smp_pairing_rsp": 0.5,
            "smp_pairing_confirm": 0.5,
            "smp_pairing_random": 0.5,
            "smp_pairing_failed": 0.5,
            "smp_encrypt_info": 0.5,
            "smp_central_ident": 0.5,
            "smp_ident_info": 0.5,
            "smp_ident_addr_info": 0.5,
            "smp_signing_info": 0.5,
            "smp_security_request": 0.5,
            "smp_public_key": 0.5,
            "smp_dhkey_check": 0.5,
            "smp_keypress_notif": 0.5
        }
        # fieldes probabilities
        self.field_prob = {
            "smp_pairing_req": {
                "io_capability": 0.5,
                "oob_data_flags": 0.5,
                "authreq": 0.5,
                "max_enc_key_size": 0.5,
                "initiator_key_distribution": 0.5,
                "responder_key_distribution": 0.5
            },  # 0x01
            "smp_pairing_rsp": {
                "io_capability": 0.5,
                "oob_data_flags": 0.5,
                "authreq": 0.5,
                "max_enc_key_size": 0.5,
                "initiator_key_distribution": 0.5,
                "responder_key_distribution": 0.5
            },  # 0x02
            "smp_pairing_confirm": {
                "cfm_value": 0.5,
            },  # 0x03
            "smp_pairing_random": {
                "random_value": 0.5,
            },  # 0x04
            "smp_encrypt_info": {
                "long_term_key": 0.5,
            },  # 0x06
            "smp_central_ident": {
                "ediv": 0.5,
                "random_value": 0.5,
            },  # 0x07
            "smp_ident_info": {
                "id_resolving_key": 0.5,
            },  # 0x08
            "smp_ident_addr_info": {
                "address_type": 0.5,
                "bd_addr": 0.5,
            },  # 0x09
            "smp_public_key": {
                "long_term_key": 0.5,
            },  # 0x0c
            "smp_dhkey_check": {
                "dhkey_check": 0.5,
            },  # 0x0d
        }
        self.code_msgtype_map = {
            1: "smp_pairing_req",
            2: "smp_pairing_rsp",
            3: "smp_pairing_confirm",
            4: "smp_pairing_random",
            5: "smp_encrypt_info",
            6: "smp_encrypt_info",
            7: "smp_central_ident",
            8: "smp_ident_info",
            9: "smp_ident_addr_info",
            12: "smp_public_key",
            13: "smp_dhkey_check",
        }
        # # state probabilities, ∑ state probabilities = 1?
        self.state_prob = {}

    def initStateProb(self, states):
        for state in states:
            if state not in self.state_prob:
                # if we achive a new state
                self.state_prob[state] = 0.5

    # TODO: change the probability of packet/state/field
    def calculateStateProb(self, states):
        for state in states:
            if state not in self.state_prob:
                # if we achive a new state
                self.state_prob[state] = 0.99

    # @Input
    # mutation_vector: 见core.py定义,保存需要变异的字段id以及变异的值，e.g., 0x01: [{0x00: value}, {field_id: value}]
    # packet_codes: 允许的变异的packet codes. e.g., {0x01:SMPacket, 0x02:SMPacket}
    # @Output
    # new_mutation_vector: 添加变异后的字段，与mutation_vector格式保持一致
    def mutate(self, mutation_vector, packet_codes):
        # size of each fields of packets. e.g., mut_map[`smp_pairing_req`] = [1, 1, 1, 1, 1, 1]
        mut_map = [[], [1, 1, 1, 1, 1, 1], [1, 1, 1, 1, 1, 1], [16], [16], [1], [16], [2, 8], [16], [1, 6], [16], [1], [32, 32],
                   [16], [1], []]
        new_mutation_vector = copy.deepcopy(mutation_vector)
        chosen_packet = random.choice(list(packet_codes.keys()))

        # get mutation field list according to field probability
        mutation_fields = []
        idx = 0
        for field in self.field_prob[self.code_msgtype_map[chosen_packet]].items():
            if random.random() < field[1]:
                # mutation_fields.append(field[0])
                mutation_fields.append((idx, field[0]))
                break
            idx += 1
        if (len(mutation_fields) == 0):
            fields = self.field_prob[self.code_msgtype_map[chosen_packet]]
            f = random.randint(0, len(fields) - 1)
            mutation_fields.append((f, list(fields.keys())[f]))

        # Selection of mutation method based on probability of mutation methods
        mutation_methods = self.methodSelection(self.method_prob)

        # TODO & TO zc:
        # 使用不同的method对不同的fields进行变异，并保存到new_mutation_vector中，注意，value为byte类型
        # for idx, size in enumerate(mut_map[chosen_packet]):
        #     new_mutation_vector[chosen_packet][idx] = b'\x00'

        # for field, field_size in (zip(new_mutation_vector[chosen_packet].items(), mut_map[chosen_packet])):
        for field in mutation_fields:
            field_type = field[0]
            field_name = field[1]
            field_value = packet_codes[chosen_packet].content[field_name]
            # 根据概率选择一个数据包之中的某些变异字段，需要变异再去选择对应的变异方法
            # * 目前方案，从待选的变异方法之中选出一个来进行变异
            # 可以考虑另一种方法，将选出的变异方法进行组合，对同一个字段进行变异（但是这样未必是更有效的变异）
            mutation_method = random.choice(mutation_methods)

            # print(mutation_method)

            if "random" == mutation_method:
                value = self.mutationRandom(field_value)
            elif "increment" == mutation_method:
                value = self.mutatioIncrement(field_value)
            elif "decrement" == mutation_method:
                value = self.mutationDecrement(field_value)
            elif "flip" == mutation_method:
                value = self.mutationFlip(field_value)
            elif "swap" == mutation_method:
                value = self.mutationSwap(field_value)
            elif "insert" == mutation_method:
                value = self.mutationInsert(field_value)
            elif "delete" == mutation_method:
                value = self.mutationDelete(field_value)
            elif "replace" == mutation_method:
                value = self.mutationReplace(field_value)
            elif "shuffle" == mutation_method:
                value = self.mutationShuffle(field_value)
            # print("value",value)

            new_mutation_vector[chosen_packet][field_type] = value

        return (new_mutation_vector, chosen_packet)

    def mutate_old(self, data):
        mutation_sequence = []

        for pkt in data:
            # get mutation field list according to field probability
            mutation_fields = []
            for field in self.field_prob[pkt.packet_type].items():
                if random.random() < field[1]:
                    mutation_fields.append(field[0])

            for key, value in pkt.content.items():
                if key in mutation_fields:
                    # select mutation method ,now choose from method_prob keys randomly
                    mutation_methods = self.methodSelection(self.method_prob)
                    for mutation_method in mutation_methods:
                        if "random" == mutation_method:
                            value = self.mutationRandom(value)
                        elif "increment" == mutation_method:
                            value = self.mutatioIncrement(value)
                        elif "decrement" == mutation_method:
                            value = self.mutationDecrement(value)
                        elif "flip" == mutation_method:
                            value = self.mutationFlip(value)
                        elif "swap" == mutation_method:
                            value = self.mutationSwap(value)
                        elif "insert" == mutation_method:
                            value = self.mutationInsert(value)
                        elif "delete" == mutation_method:
                            value = self.mutationDelete(value)
                        elif "replace" == mutation_method:
                            value = self.mutationReplace(value)
                        elif "shuffle" == mutation_method:
                            value = self.mutationShuffle(value)
                    pkt.content[key] = value
                else:
                    pkt.content[key] = value
            mutation_sequence.append(pkt)
        return mutation_sequence

    # TODO: translate statemachine path to pkt sequence (pkt type list or SMPacket Oject list)
    # example:
    # pkt_to_state = ["smp_pairing_req","smp_pairing_confirm","smp_pairing_random","smp_encrypt_info"]
    # pkt_wait_mutation = ["smp_central_ident"]
    # pkt_suffixes = []
    # Corpus store SMPacket Objects
    # output example:
    # pkt sequence : ['0142-smp_pairing_req-initiator_key_distribution-0f-max_enc_key_size-10-responder_key_distribution-0f-oob_data_flags-00-authreq-2d-io_capability-04', '0063-smp_pairing_confirm-cfm_value-056cfb62f74f0cc475f81733595cc0bf', '0065-smp_pairing_random-random_value-23e4f061ec00d42c2e5497754a46c804', '0064-smp_encrypt_info-long_term_key-877a5994996da5c26c153d3e9baa9e29']
    # mutation sequence : ['0058-smp_central_ident-random_value-0e37c9196d2e936f-ediv-b2a2']
    # suffixes sequence : []
    def pktSeqenceBuilder(self, corpus, pkt_to_state, pkt_wait_mutation, pkt_suffixes):

        pkt_sequence = []
        mutation_sequence = []
        pkt_suffixes = []

        for pkt in pkt_to_state:
            pkt_seq_str = ""
            for smpkt in corpus:
                if smpkt.packet_type == pkt:

                    key_value_list = []
                    for key, value in smpkt.content.items():
                        if key != "opcode":
                            key_value_list.append(key)
                            key_value_list.append(value)
                    pkt_seq_str = "-".join(key_value_list)
                    pkt_type_str = smpkt.packet_type
            # the length of remain data , length fixed at 4
            pkt_seq_len = '{0:04}'.format(1 + len(pkt_type_str) + 1 + len(pkt_seq_str))
            pkt_seq_str = pkt_seq_len + "-" + pkt_type_str + "-" + pkt_seq_str
            pkt_sequence.append(pkt_seq_str)

        mutation_sequence = self.mutate(pkt_wait_mutation, corpus)

        return pkt_sequence, mutation_sequence, pkt_suffixes

    def stateSelection(self):
        state = ""
        # 通过比较概率大小（item[1]）来选择其中概率最大的状态(item[0])，选择了某个状态后，减少该状态的概率，增加其他状态的概率
        max_prob = 0
        for item in self.state_prob.items():
            if item[1] > max_prob:
                max_prob = item[1]
                state = item[0]
        for item in self.state_prob.items():
            if (item[0] == state):
                self.state_prob[item[0]] = item[1] - 0.02
            else:
                self.state_prob[item[0]] = item[1] + 0.02
            if (self.state_prob[item[0]] > 1):
                self.state_prob[item[0]] = 1
            elif (self.state_prob[item[0]] < 0):
                self.state_prob[item[0]] = 0
        return state

    def methodSelection(self, method_prob):
        mutation_methods = []
        for item in method_prob.items():
            if random.random() < item[1]:
                mutation_methods.append(item[0])
        return mutation_methods

    # e.g  b'\xff\xff\xff\x03\x13' -> b'3\xc3\x86W4_'
    def mutationRandom(self, value):
        res = b""
        for _ in value:
            new_byte = random.randint(0, int('0xff', 16))
            res += bytes.fromhex(hex(new_byte)[2:])
        return res
        # value = value.decode('utf-8')
        # max_value = ""
        # for i in range(len(value)):
        #     max_value = max_value + "f"
        # max_value = "0x" + max_value
        # print(max_value)
        # value = random.randint(0, int(max_value, 16))
        # return chr(value).encode('utf-8')

    # e.g b'\xff\xff\xff\x04\x12' -> b'\xf1\xff\xff\x04\x13'
    def mutatioIncrement(self, value):
        try:
            length = len(value)
            value = int.from_bytes(value, byteorder='big', signed=False)
            value += 1
            return int.to_bytes(value, byteorder='big', length=length, signed=False)
        except:
            value -= 1
            return int.to_bytes(value, byteorder='big', length=length, signed=False)
        # value = ord(value)
        # print(chr((value+1)).encode('utf-8'))
        # max_value = ""
        # for i in range(len(value)):
        #     max_value = max_value + "f"
        # max_value = "0x" + max_value
        # if "0x" + value != max_value:
        #     value = hex(int(value, 16) + 1).replace("0x", "")
        # if len(value) < origin_len:
        #     for i in range(origin_len - len(value)):
        #         value = "0" + value
        # return chr((value+1)).encode('utf-8')

    # e.g b'\xff\xff\xff\x04\x12' -> b'\xf1\xff\xff\x04\x11'
    def mutationDecrement(self, value):
        try:
            length = len(value)
            value = int.from_bytes(value, byteorder='big', signed=False)
            value -= 1
            return int.to_bytes(value, byteorder='big', length=length, signed=False)
        except:
            value += 1
            return int.to_bytes(value, byteorder='big', length=length, signed=False)
        # origin_len = len(value)
        # if int(value, 16) != 0:
        #     value = hex(int(value, 16) - 1).replace("0x", "")

        # if len(value) < origin_len:
        #     for i in range(origin_len - len(value)):
        #         value = "0" + value
        # return value

    # e.g b'\xf1\xff\xff\x04\x12' -> b'\xff\xf1\x04\xff\x12'
    def mutationFlip(self, value):
        length = len(value)
        int_list = [value[i] for i in range(length)]
        if length <= 1:
            return value
        for i in range(1, length, 2):
            int_list[i], int_list[i - 1] = int_list[i - 1], int_list[i]
        new_byte = b""
        for item in int_list:
            new_byte += int.to_bytes(item, byteorder='big', length=1)
        return new_byte
        # output = ""
        # value = value.decode()
        # index = len(value) - 1
        # print(index)
        # while (index >= 0):
        #     output = output + value[index - 1] + value[index]  #每两位反转一次
        #     index = index - 2
        # print(output)
        # print(output.encode('utf-8'))
        # return value

    # this method need two value, pass
    def mutationSwap(self, value):
        return value

    # e.g. b'\xf1\xff\xff\x04\x12' -> b'\xf1\xff\xff\x04\x12C'
    def mutationInsert(self, value):
        length = len(value)
        int_list = [value[i] for i in range(length)]
        insert_idx = random.randint(0, length)
        insert_value = random.randint(0, 255)
        int_list.insert(insert_idx, insert_value)
        new_byte = b""
        for item in int_list:
            new_byte += int.to_bytes(item, byteorder='big', length=1)
        return new_byte
        # characters = "abcdef" + string.digits
        # new_value = ""
        # print(value)
        # for c in value:
        #     randomLetter = "".join(random.choice(characters))
        #     new_value += c
        #     new_value += randomLetter
        # value = new_value
        # return value

    # e.g. b'\xf1\xff\xff\x04\x12' -> b'\xff\xff\x04\x12'
    def mutationDelete(self, value):
        length = len(value)
        int_list = [value[i] for i in range(length)]
        remove_idx = random.randint(0, length - 1)
        int_list.pop(remove_idx)
        new_byte = b""
        for item in int_list:
            new_byte += int.to_bytes(item, byteorder='big', length=1)
        return new_byte
        # origin_len = len(value)
        # output = ''.join([s for s in value if random.random() < 0.7])
        # value = output

        # if len(value) < origin_len:
        #     for i in range(origin_len - len(value)):
        #         value = "0" + value
        # return value

    # e.g. b'\xf1\xff\xff\x04\x12' -> b'\xf1\xff\xff\x04\xc0'
    def mutationReplace(self, value):
        length = len(value)
        int_list = [value[i] for i in range(length)]
        replace_idx = random.randint(0, length - 1)
        replace_value = random.randint(0, 255)
        int_list[replace_idx] = replace_value
        new_byte = b""
        for item in int_list:
            new_byte += int.to_bytes(item, byteorder='big', length=1)
        return new_byte
        # characters = "abcdef" + string.digits
        # origin_len = len(value)
        # index_list = [i for i in range(0, origin_len)]
        # index_num = random.randint(0, origin_len)
        # replace_index_list = random.sample(index_list, index_num)
        # value = list(value)
        # for index in replace_index_list:
        #     randomLetter = "".join(random.choice(characters))
        #     value[index] = randomLetter
        # value = ''.join(value)
        # return value

    # e.g. b'\xf1\xff\xff\x04\x12' -> b'\x12\xf1\xff\x04\xff'
    def mutationShuffle(self, value):
        length = len(value)
        int_list = [value[i] for i in range(length)]
        random.shuffle(int_list)
        new_byte = b""
        for item in int_list:
            new_byte += int.to_bytes(item, byteorder='big', length=1)
        return new_byte
        # origin_len = len(value)
        # l = list(value)
        # random.shuffle(l)
        # value = ''.join(l)
        # if len(value) < origin_len:
        #     for i in range(origin_len - len(value)):
        #         value = "0" + value
        # return value


if __name__ == '__main__':
    smpmutator = SMPMutator()
    mutation_vector = {
        0x01: {
            0: b'\xf1',
            1: b'\x00',
            2: b'\x2d',
            3: b'\x10',
            4: b'\x0f',
            5: b'\x0f'
        },
        0x02: {},
        0x03: {},
        0x04: {},
        0x05: {},
        0x06: {},
        0x07: {},
        0x08: {},
        0x09: {},
        0x0a: {},
        # Peripheral -> Central; The Security Request command is used by the Peripheral to request that the Central initiates security with the requested security properties, see Section 2.4.6. The Security Request command is defined in Figure 3.17.
        0x0b: {},
        # Central -> Peripheral | Peripheral -> Central;
        0x0c: {},
        # Central -> Peripheral | Peripheral -> Central;
        0x0d: {},
        0x0e: {},
    }
    packet_code = {0x02: SMPacket("0104002d100f0f")}
    smpmutator.mutate(mutation_vector, packet_code)

# seed = SMPacketSequnce(sys.path[0] + "/packet_sequence/earphoe_legacy_justwork.pcapng")
# pkt_to_state = [seed.pkt_sequnce[0],seed.pkt_sequnce[2],seed.pkt_sequnce[4],seed.pkt_sequnce[6]]
# pkt_wait_mutation = [seed.pkt_sequnce[8]]

# print("------------------------------------------before mutatation------------------------------------------")
# for smpacket in pkt_wait_mutation:
#     smpacket.PrintSMPacket()

# print("------------------------------------------after mutatation------------------------------------------")
# mutation_sequence  = smpmutator.mutate_old(pkt_wait_mutation)
# for smpacket in mutation_sequence:
#     smpacket.raw_packet = smpacket.to_raw()
#     smpacket.PrintSMPacket()
