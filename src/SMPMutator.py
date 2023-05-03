#########################
# Mutator & Executor Module
#########################
import random
import string
import sys

from SMPacket import SMPacketSequnce


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
            "insert": 0.5,
            "delete": 0.5,
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
        # # state probabilities, ∑ state probabilities = 1?
        self.state_prob = {}

    def calculateStateProb(self, states):
        for state in states:
            if state not in self.state_prob:
                # if we achive a new state
                self.state_prob[state] = 0.99

    # old mutate
    """
    def mutate(self, data, corpus):

        mutation_sequence = []

        for pkt in data:
            # get mutation field list according to field probability
            mutation_fields = []
            for field in self.field_prob[pkt.packet_type].items():
                if random.random() < field[1]:
                    mutation_fields.append(field[0])

            for smpkt in corpus:
                if smpkt.packet_type == pkt.packet_type:
                    key_value_list = []
                    for key, value in smpkt.items():
                        if key in mutation_fields:
                            key_value_list.append(key)
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
                            key_value_list.append(value)
                        else:
                            key_value_list.append(key)
                            key_value_list.append(value)
                    pkt_seq_str = "-".join(key_value_list)
                    pkt_type_str = smpkt.packet_type
                pkt_seq_len = '{0:04}'.format(1 + len(pkt_type_str) + 1 + len(pkt_seq_str))
                pkt_seq_str = pkt_seq_len + "-" + pkt_type_str + "-" + pkt_seq_str
                mutation_sequence.append(pkt_seq_str)
            return mutation_sequence
    """

    def mutate(self, data):
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

    def mutationRandom(self, value):
        max_value = ""
        for i in range(len(value)):
            max_value = max_value + "f"
        max_value = "0x" + max_value
        value = random.randint(0, int(max_value, 16))
        return hex(value).replace("0x", "")

    def mutatioIncrement(self, value):
        origin_len = len(value)
        max_value = ""
        for i in range(len(value)):
            max_value = max_value + "f"
        max_value = "0x" + max_value
        if "0x" + value != max_value:
            value = hex(int(value, 16) + 1).replace("0x", "")
        if len(value) < origin_len:
            for i in range(origin_len - len(value)):
                value = "0" + value
        return value

    def mutationDecrement(self, value):
        origin_len = len(value)
        if int(value, 16) != 0:
            value = hex(int(value, 16) - 1).replace("0x", "")

        if len(value) < origin_len:
            for i in range(origin_len - len(value)):
                value = "0" + value
        return value

    def mutationFlip(self, value):
        output = ""
        index = len(value) - 1
        while (index >= 0):
            output = output + value[index - 1] + value[index]  #每两位反转一次
            index = index - 2
        return value

    # this method need two value , pass
    def mutationSwap(self, value):
        return value

    # len(value) has been changed
    def mutationInsert(self, value):
        characters = "abcdef" + string.digits
        new_value = ""
        for c in value:
            randomLetter = "".join(random.choice(characters))
            new_value += c
            new_value += randomLetter
        value = new_value
        return value

    def mutationDelete(self, value):
        origin_len = len(value)
        output = ''.join([s for s in value if random.random() < 0.7])
        value = output

        if len(value) < origin_len:
            for i in range(origin_len - len(value)):
                value = "0" + value
        return value

    def mutationReplace(self, value):
        characters = "abcdef" + string.digits
        origin_len = len(value)
        index_list = [i for i in range(0, origin_len)]
        index_num = random.randint(0, origin_len)
        replace_index_list = random.sample(index_list, index_num)
        value = list(value)
        for index in replace_index_list:
            randomLetter = "".join(random.choice(characters))
            value[index] = randomLetter
        value = ''.join(value)
        return value

    def mutationShuffle(self, value):
        origin_len = len(value)
        l = list(value)
        random.shuffle(l)
        value = ''.join(l)
        if len(value) < origin_len:
            for i in range(origin_len - len(value)):
                value = "0" + value
        return value


# if __name__ == '__main__':
#     smpmutator = SMPMutator()

#     seed = SMPacketSequnce(sys.path[0] + "/packet_sequence/earphoe_legacy_justwork.pcapng")
#     pkt_to_state = [seed.pkt_sequnce[0],seed.pkt_sequnce[2],seed.pkt_sequnce[4],seed.pkt_sequnce[6]]
#     pkt_wait_mutation = [seed.pkt_sequnce[8]]

#     print("------------------------------------------before mutatation------------------------------------------")
#     for smpacket in pkt_wait_mutation:
#         smpacket.PrintSMPacket()

#     print("------------------------------------------after mutatation------------------------------------------")
#     mutation_sequence  = smpmutator.mutate(pkt_wait_mutation)
#     for smpacket in mutation_sequence:
#         smpacket.raw_packet = smpacket.to_raw()
#         smpacket.PrintSMPacket()
