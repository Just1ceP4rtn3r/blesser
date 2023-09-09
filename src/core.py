from SMPMutator import SMPMutator
from SMPStateMachine import SMPStateMachine
from SMPacket import SMPSocket, SMPSocket_TEST, SMPacket
import random
from copy import deepcopy


#########################
# Sanitizer Module
#########################
def Sanitizer(current_state, req, resp):
    pass


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
        self.socket = SMPSocket()
        self.state_machine = SMPStateMachine("SMP.dot", self.socket)
        self.mutator = SMPMutator()
        self.mutator.calculateStateProb(list(self.state_machine.toState_path_map.keys()))

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
        while (True):
            state_name = self.mutator.stateSelection()
            tostate_bytes = self.state_machine.get_tostate_path(state_name)
            packets_mutatable = []
            for transition in self.state_machine.stateName_map[state_name].transitions:
                req = self.state_machine.transition_map[transition.event][0]
                if (req is not None):
                    packets_mutatable.append(req.code)
            mutation_vec, mutation_packet_code = self.mutator.mutate(self.bytes_to_vec(tostate_bytes), packets_mutatable)
            mutation_bytes = self.vec_to_bytes(mutation_vec)
            corpus = self.state_machine.corpus[mutation_packet_code]
            assert (corpus != '')
            mutation_packet = corpus.MutatePacket(mutation_vec)
            #self.socket.send(mutation_bytes)
            self.state_machine.goto_state(state_name, tostate_bytes, mutation_bytes, mutation_packet)

            self.mutator.calculateStateProb(list(self.state_machine.toState_path_map.keys()))
            # reset the socket
            self.socket.reset()
            self.state_machine.reset()

    def test_fuzzing(self):
        state_name = "not_pair_state"
        tostate_bytes = self.state_machine.get_tostate_path(state_name)
        packets_mutatable = []
        for transition in self.state_machine.stateName_map[state_name].transitions:
            req = self.state_machine.transition_map[transition.event][0]
            if (req is not None):
                packets_mutatable.append(req.code)
        mutation_vec, mutation_packet_code = self.mutator.mutate(self.bytes_to_vec(tostate_bytes), packets_mutatable)
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
    #fuzzer.process_fuzzing()
    fuzzer.test_fuzzing()

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
