from SMPMutator import SMPMutator
from SMPStateMachine import SMPStateMachine
from SMPacket import SMPSocket, SMPSocket_TEST, SMPacket
from config import *
import time
import random
import threading
import os
import sys

from copy import deepcopy



#########################
# Sanitizer Module
#########################
def Sanitizer(current_state, req, resp):
    pass


def socket_wait_recv(fuzzer):
    while (True):
        packet = fuzzer.socket.recv()
        print(packet)


#########################
# Feedback Module
#########################
class SMPFuzzer():
    # 0x01: [{0x00: value}, {field_id: value}]
    mutation_vector = {
        0x01: {},
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

    def __init__(self):

        ini_mutation_vec = deepcopy(self.mutation_vector)
        ini_mutation_vec[0x01] = {0: smp_pairing_request.content['io_capability'], 1: smp_pairing_request.content['oob_data_flags'], 2: smp_pairing_request.content['authreq'] , 
                                   3: smp_pairing_request.content['max_enc_key_size'], 4: smp_pairing_request.content['initiator_key_distribution'], 5: smp_pairing_request.content['responder_key_distribution']}
        ini_mutation_bytes = self.vec_to_bytes(ini_mutation_vec)

        self.socket = SMPSocket()
        self.state_machine = SMPStateMachine("SMP.dot", self.socket, b'')
        self.mutator = SMPMutator()
        self.mutator.initStateProb(list(self.state_machine.toState_path_map.keys()))

    def vec_to_bytes(self, vec):
        mutation_bytes = b''
        for packet_code in vec:
            if (vec[packet_code] != {}):
                for field_id, mut_value in vec[packet_code].items():
                    mutation_bytes += bytes([packet_code])
                    mutation_bytes += bytes([field_id])
                    mutation_bytes += mut_value
        return mutation_bytes

    def bytes_to_vec(self, mutation_bytes):
        vec = deepcopy(self.mutation_vector)
        mut_map = [[], [1, 1, 1, 1, 1, 1], [1, 1, 1, 1, 1, 1], [16], [16], [1], [16], [2, 8], [16], [1, 6], [16], [1], [64],
                   [16], [1], []]
        idx = 0
        while (1):
            if (idx == len(mutation_bytes)):
                break
            packet_code = mutation_bytes[idx]
            idx += 1
            field_id = mutation_bytes[idx]
            idx += 1
            value_size = mut_map[packet_code][field_id]
            value = mutation_bytes[idx:idx + value_size]
            idx += value_size
            vec[packet_code][field_id] = value
        return vec

    def process_fuzzing(self):
        with open("output.log", 'a+') as out_f:
            sys.stdout = sys.__stdout__
            # reset the socket
            self.socket.reset()
            self.state_machine.reset()
            round = 1
            print("---------------------Begin Fuzzing---------------------")
            time.sleep(8)
            while (True):
                print(f"---------------------Round {round}---------------------")
                round += 1
                state_name = self.mutator.stateSelection()
                # state_name = "receive_pairing_rsp_state"
                # state_name = "not_pair_state"
                print("[DEBUG]: Chosen State:\n", state_name)
                tostate_bytes, last_transition = self.state_machine.get_tostate_path(state_name)
                packets_mutatable = {}
                for transition in self.state_machine.stateName_map[state_name].transitions:
                    req = self.state_machine.transition_map[transition.event][0]
                    if (req is not None):
                        req_packet = self.state_machine.corpus[req.code]
                        assert (req_packet != '')
                        packets_mutatable[req.code] = req_packet
                if (len(packets_mutatable) == 0 and last_transition and
                        self.state_machine.transition_map[last_transition.event][1] is not None):
                    rsp = self.state_machine.transition_map[last_transition.event][1]
                    if (rsp.code == 0x02):
                        packets_mutatable[0x0c] = self.state_machine.corpus[0x0c]
                    if (rsp.code == 0x03):
                        packets_mutatable[0x04] = self.state_machine.corpus[0x04]
                    if (rsp.code == 0x0c):
                        packets_mutatable[0x04] = self.state_machine.corpus[0x04]
                    if (rsp.code == 0x04):
                        packets_mutatable[0x0d] = self.state_machine.corpus[0x0d]

                if (len(packets_mutatable) == 0):
                    continue

                mutation_vec, mutation_packet_code = self.mutator.mutate(self.bytes_to_vec(tostate_bytes), packets_mutatable)
                print("[DEBUG]: Mutation Vector:\n", mutation_vec)
                mutation_bytes = self.vec_to_bytes(mutation_vec)
                corpus = self.state_machine.corpus[mutation_packet_code]
                assert (corpus != '')
                mutation_packet = corpus.MutatePacket(mutation_vec)
                # mutation_bytes = b'\x0c\x00\xbf\xae\x0f\xecu\\qW\x8d-\x8e\x17\x1bX\x1e\x82\xfc\x08\xf8\x80\xee8-+\xcf\x12\xab\x90{\xd0F\xfe\xb0\xa1>L\x153\xf0+\x10\xcb\xc3\xcf\x9f\xb8\xd5"\x0e\x11\x84\x01a\xb0\xc8\x10'
                self.socket.send(mutation_bytes)
                # send \xff for receving responses
                time.sleep(2)
                self.socket.wait_for_resp()
                while (True):
                    packet = fuzzer.socket.recv()
                    if (packet == b''):
                        break
                    self.state_machine.ALLRESP.insert(0, packet)


                # self.state_machine.goto_state(state_name, tostate_bytes, mutation_bytes, mutation_packet)

                # self.mutator.calculateStateProb(list(self.state_machine.toState_path_map.keys()))
                # # reset the socket
                # self.socket.reset()
                # self.state_machine.reset()

                # with open("test.dot", "w") as f:
                #     f.write(self.state_machine._graph().__str__())
                # os.system("dot -Tpng test.dot -o test.png")
                try:
                    self.state_machine.goto_state(state_name, tostate_bytes, mutation_bytes, mutation_packet)

                    self.mutator.calculateStateProb(list(self.state_machine.toState_path_map.keys()))
                    # reset the socket
                    self.socket.reset()
                    self.state_machine.reset()

                    with open("test.dot", "w") as f:
                        f.write(self.state_machine._graph().__str__())
                    os.system("dot -Tpng test.dot -o test.png")
                except Exception as e:
                    print("[ERROR]: ",e)
                    # reset the socket
                    self.socket.reset()
                    self.state_machine.reset()
                
                print(f"**Find States: {self.state_machine.new_state_size}**")
                print(f"**Find Bugs: {self.state_machine.new_bug}**")
                out_f.flush()
                time.sleep(8)
            


    def test_fuzzing(self):
        while (True):
            state_name = self.mutator.stateSelection()
            print("[DEBUG]: Chosen State:\n", state_name)
            tostate_bytes, last_transition = self.state_machine.get_tostate_path(state_name)
            packets_mutatable = {}
            for transition in self.state_machine.stateName_map[state_name].transitions:
                req = self.state_machine.transition_map[transition.event][0]
                if (req is not None):
                    req_packet = self.state_machine.corpus[req.code]
                    assert (req_packet != '')
                    packets_mutatable[req.code] = req_packet
            if (len(packets_mutatable) == 0 and last_transition and
                    self.state_machine.transition_map[last_transition.event][1] is not None):
                rsp = self.state_machine.transition_map[last_transition.event][1]
                if (rsp.code == 0x02):
                    packets_mutatable[0x0c] = self.state_machine.corpus[0x0c]
                if (rsp.code == 0x03):
                    packets_mutatable[0x04] = self.state_machine.corpus[0x04]
                if (rsp.code == 0x0c):
                    packets_mutatable[0x04] = self.state_machine.corpus[0x04]
                if (rsp.code == 0x04):
                    packets_mutatable[0x0d] = self.state_machine.corpus[0x0d]

            if (len(packets_mutatable) == 0):
                continue

            mutation_vec, mutation_packet_code = self.mutator.mutate(self.bytes_to_vec(tostate_bytes), packets_mutatable)
            print("[DEBUG]: Mutation Vector:\n", mutation_vec)
            mutation_bytes = self.vec_to_bytes(mutation_vec)
            corpus = self.state_machine.corpus[mutation_packet_code]
            assert (corpus != '')
            mutation_packet = corpus.MutatePacket(mutation_vec)

            self.state_machine.goto_state(state_name, tostate_bytes, mutation_bytes, mutation_packet)

            self.mutator.calculateStateProb(list(self.state_machine.toState_path_map.keys()))
            # reset the socket
            self.socket.reset()
            self.state_machine.reset()

if __name__ == '__main__':
    fuzzer = SMPFuzzer()
    # fuzzer.socket.send(b'\x01\x00\x04\x01\x01\x00\x01\x02-\x01\x03\x10\x01\x04\x0f\x01\x05\x0f')
    # while (1):
    #     res = fuzzer.socket.recv()
    #     print(res)
    # fuzzer.state_machine.ALLRESP = [bytes.fromhex("0104002d100f0f")] * 10
    fuzzer.process_fuzzing()

    # fuzzer.test_fuzzing()

    # testp = SMPacket("0756be784bc11345c6fb16")
    # vec = fuzzer.bytes_to_vec(bytes.fromhex("0300102030405060708090a0b0c0d0e0f000"))
    # testp_mut = testp.MutatePacket(vec)
    # print(testp.content, testp_mut.content)

    # with open("../test/testcase.txt") as f:
    #     cases = f.read().split('\n')
    #     for i in cases:
    #         if (i != ''):
    #             vec = fuzzer.bytes_to_vec(bytes.fromhex(i))
    #             mut_bytes = fuzzer.vec_to_bytes(vec)
    #             print(i, mut_bytes.hex())
    #             assert (len(mut_bytes) == len(bytes.fromhex(i)))
