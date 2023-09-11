import os
import sys
from statemachine import StateMachine, State
from statemachine.transition import Transition
import re
import networkx as nx
import warnings
import random

import SMPSanitizer
from SMPacket import SMPacket, SMPSocket
from SMPSanitizer import SMPSanitizer


#########################
# State Machine
#########################
class SMPStateMachine(StateMachine):
    current_req: SMPacket = None
    current_rsp: SMPacket = None

    # {tranisition.event: (req_1, rsp_1)}
    transition_map = {}

    # {state1: [ ("mutation_hex", [transitions,...]), ]}
    toState_path_map = {}
    state_count = 0

    ######################################################## States ########################################################
    # Entrypoint, now we have a L2CAP connection
    not_pair_state = State('not_pair_state', initial=True)

    toState_path_map = {not_pair_state.name: {b"": []}}
    stateName_map = {}
    # End, close the L2CAP connection
    final_state = State('final_state')

    #### code:0x05 Pairing Failed ####
    # receive_pairing_failed_state = State('Receive Pairing Failed State')

    #### code:0x02 Pairing Response ####
    receive_pairing_rsp_state = State('receive_pairing_rsp_state')

    #### code:0x03 Pairing Confirm ####
    receive_pairing_confirm_state = State('receive_pairing_confirm_state')

    #### code:0x04 Pairing Random ####
    receive_pairing_random_state = State('receive_pairing_random_state')

    #### code:0x0c Pairing Public Key ####
    receive_pairing_public_key_state = State('receive_pairing_public_key_state')

    #### code:0x0d Pairing DHKey Check ####
    receive_pairing_dhkey_check_state = State('receive_pairing_dhkey_check_state')

    ######################################################## Transitions ########################################################

    TESTPACKET = SMPacket("0104002d100f0f")
    smp_pairing_request = SMPacket("0104002d100f0f")
    smp_pairing_response = SMPacket("02030009100707")
    smp_sent_pairing_public_key = SMPacket(
        "0cf801bfeefe59107b2d672b61ecf017c810825857c3389fb890a11571800908755c09fc2ad0468db08e2233ae11983e84d50eb42b1bcf2d124cb0cb1e0fcf02ab"
    )
    smp_rcvd_pairing_public_key = SMPacket(
        "0c259ab29dd53b256c79b127296ee58518fdd25b958870ff4718013bb056a6dfb863fe7294b220def877ea7858617de1e314cae98891472625fbeb55db3977152d"
    )
    smp_rcvd_pairing_confirm = SMPacket("0302b5c6f970394a385fc54f1c7cd527b7")
    smp_sent_pairing_random = SMPacket("0422744b1273a328ab19f50b4b21646ad6")
    smp_rcvd_pairing_random = SMPacket("043381d61f4192b61113c5291e0e6dd63d")
    smp_sent_DHKey_check = SMPacket("0da583413f2b8f75ce73de42a8a5bff0be")
    smp_rcvd_DHKey_check = SMPacket("0dda53ef23954c2f84fc5f6f42048bf088")
    # TODO: complete the corpus
    corpus = {
        0x01: smp_pairing_request,
        0x02: smp_pairing_response,
        0x03: smp_rcvd_pairing_confirm,
        0x04: smp_sent_pairing_random,
        0x05: "",
        0x06: "",
        0x07: "",
        0x08: "",
        0x09: "",
        0x0a: "",
        # Peripheral -> Central; The Security Request command is used by the Peripheral to request that the Central initiates security with the requested security properties, see Section 2.4.6. The Security Request command is defined in Figure 3.17.
        0x0b: "",
        # Central -> Peripheral | Peripheral -> Central;
        0x0c: smp_sent_pairing_public_key,
        # Central -> Peripheral | Peripheral -> Central;
        0x0d: smp_sent_DHKey_check,
        0x0e: "",
    }

    not_pair_state.to(receive_pairing_rsp_state, event="not_pair_to_receive_pairing_rsp")
    # parse
    # smp_pairing_request = SMPacket(sys.path[0] + "/packet_sequence/miband_pairing_request.pcapng")
    # smp_pairing_response = SMPacket(sys.path[0] + "/packet_sequence/miband_pairing_response.pcapng")
    transition_map["not_pair_to_receive_pairing_rsp"] = (smp_pairing_request, smp_pairing_response)

    receive_pairing_rsp_state.to(receive_pairing_public_key_state, event="receive_pairing_rsp_to_receive_pairing_public_key")
    # TODO: how to get pairing public key
    # smp_sent_pairing_public_key = SMPacket(sys.path[0]+"/packet_sequence/miband_sent_pairing_public_key.pcapng")
    # smp_rcvd_pairing_public_key = SMPacket(sys.path[0] + "/packet_sequence/miband_rcvd_pairing_public_key.pcapng")
    transition_map["receive_pairing_rsp_to_receive_pairing_public_key"] = (smp_sent_pairing_public_key,
                                                                           smp_rcvd_pairing_public_key)

    receive_pairing_public_key_state.to(receive_pairing_confirm_state,
                                        event="receive_pairing_public_key_to_receive_pairing_confirm_state")
    # smp_rcvd_pairing_confirm = SMPacket(sys.path[0] + "/packet_sequence/miband_pairing_confirm.pcapng")
    transition_map["receive_pairing_public_key_to_receive_pairing_confirm_state"] = (None, smp_rcvd_pairing_confirm)

    receive_pairing_confirm_state.to(receive_pairing_random_state,
                                     event="receive_pairing_confirm_state_to_receive_pairing_random_state")
    # smp_sent_pairing_random = SMPacket(sys.path[0] + "/packet_sequence/miband_sent_pairing_random.pcapng")
    # smp_rcvd_pairing_random = SMPacket(sys.path[0] + "/packet_sequence/miband_rcvd_pairing_random.pcapng")
    transition_map["receive_pairing_confirm_state_to_receive_pairing_random_state"] = (smp_sent_pairing_random,
                                                                                       smp_rcvd_pairing_random)

    receive_pairing_random_state.to(receive_pairing_dhkey_check_state,
                                    event="receive_pairing_random_state_to_receive_pairing_dhkey_check_state")
    # smp_sent_DHKey_check = SMPacket(sys.path[0] + "/packet_sequence/miband_sent_DHKey_check.pcapng")
    # smp_rcvd_DHKey_check = SMPacket(sys.path[0] + "/packet_sequence/miband_rcvd_DHKey_check.pcapng")
    transition_map["receive_pairing_random_state_to_receive_pairing_dhkey_check_state"] = (smp_sent_DHKey_check,
                                                                                           smp_rcvd_DHKey_check)

    # receive_pairing_dhkey_check_state.to(receive_pairing_failed_state,
    #                                      cond="receive_pairing_failed",
    #                                      event="receive_pairing_dhkey_check_state_to_receive_pairing_failed_state")
    # transition_map["receive_pairing_dhkey_check_state_to_receive_pairing_failed_state"] = (None, None)

    # receive_pairing_failed_state.to(final_state, event="receive_pairing_failed_state_to_final_state")
    # transition_map["receive_pairing_failed_state_to_final_state"] = (None, None)
    receive_pairing_dhkey_check_state.to(final_state, event="receive_pairing_dhkey_check_state_to_final_state")
    transition_map["receive_pairing_dhkey_check_state_to_final_state"] = (TESTPACKET, TESTPACKET)

    final_state.to(not_pair_state, event="final_state_to_not_pair_state")
    transition_map["final_state_to_not_pair_state"] = (None, None)

    def __init__(self, dot, socket: SMPSocket):
        # self.translate(dot)
        self.socket = socket
        # state_array: the state that has been traversed
        state_array = []

        for state in self.states:
            self.stateName_map[state.name] = state

        self.traverse_state_machine(self.not_pair_state, state_array)
        for key, value in self.toState_path_map.items():
            print("to state:", key, "\npath:", value)
            print("\n\n")
        super().__init__(self)

    # def traverse_state_machine(self):
    #     all_transitions_dict = {}
    #     all_transitions = []

    #     for state in self.states:
    #         for transition in state.transitions:
    #             all_transitions.append((transition.source, transition.target))
    #             all_transitions_dict[(transition.source, transition.target)] = transition

    #     G = nx.MultiDiGraph()
    #     G.add_edges_from(all_transitions)
    #     for state in self.states:
    #         if state.name == self.not_pair_state.name:
    #             continue
    #         self.toState_path_map[state.name] = []
    #         paths = nx.all_simple_paths(G, self.not_pair_state, state)
    #         for path in paths:
    #             i = 0
    #             while i + 1 < len(path):
    #                 transition = all_transitions_dict[(path[i], path[i + 1])]
    #                 self.toState_path_map[state.name].append(transition)
    #                 i = i + 1

    #[can only be called with a state machine] traverse the initial state machine to generate the transition_map & toState_path_map
    def traverse_state_machine(self, state: State, state_array):
        for transition in state.transitions:
            # if the target state has been traversed, then skip it
            if (transition.target in state_array):
                continue
            if transition.target.name not in self.toState_path_map:
                self.toState_path_map[transition.target.name] = {}
            for mut, path in self.toState_path_map[state.name].items():
                p = path + [transition]
                if (mut not in self.toState_path_map[transition.target.name]):
                    self.toState_path_map[transition.target.name][mut] = p

            state_array.append(transition.target)
            self.traverse_state_machine(transition.target, state_array)

    # TODO: translate the dot file to a state machine with "StateMachine" library)
    def translate(self, dot):
        self.states = []
        self.transitions = []
        self.states.append(State(name="__start0", initial=True))
        dot_file = open(dot, "r")
        lines = dot_file.readlines()
        dot_file.close()
        state_pattern = re.compile(r'\s*([a-z0-9]+) \[shape="([a-z]+)" label="([0-9]+)"\]')
        transition_pattern = re.compile(r'\s*([a-z0-9]+) -> ([a-z0-9\.]+) \[label="([a-zA-Z0-9\.]+) / ([a-zA-Z0-9\.]+)"\]')
        for line in lines:
            state_match_res = state_pattern.match(line)
            transition_match_res = transition_pattern.match(line)
            if state_match_res != None and transition_match_res == None:
                # State matched
                self.states.append(
                    State(name=state_match_res[1], value={
                        "shape": state_match_res[2],
                        "label": state_match_res[3]
                    }))
            elif state_match_res == None and transition_match_res != None:
                # Transition matched
                self.transitions.append(
                    Transition(source=State(name=transition_match_res[1]),
                               target=State(name=transition_match_res[2]),
                               event=[transition_match_res[3], transition_match_res[4]]))
            elif state_match_res == None and transition_match_res == None:
                # both not matched
                transition_match_res = re.match(r'__start0 -> ([a-zA-Z0-9]+);', line)
                if transition_match_res != None:
                    self.transitions.append(
                        Transition(source=State(name="__start0"), target=State(name=transition_match_res[1])))
            else:
                # both matched
                assert (False)

    # From the current state, check if the req/rsp indicates a new state
    # TODO: Refine logic
    def is_newstate(self, current_mutation_bytes, current_transitions):
        for transition in self.current_state.transitions:
            if (self.current_req is None):
                if (self.transition_map[transition.event][0] is not None):
                    return True
                else:
                    if (self.current_rsp == self.transition_map[transition.event][1] or
                            self.current_rsp.CompareTo(self.transition_map[transition.event][1])):
                        return False
            if (self.current_rsp is None):
                if (self.transition_map[transition.event][1] is not None):
                    return True
                else:
                    if (self.current_req == self.transition_map[transition.event][0] or
                            self.current_req.CompareTo(self.transition_map[transition.event][0])):
                        return False
            if (self.current_req is not None and self.current_rsp is not None and
                    self.transition_map[transition.event][0] is not None and
                    self.transition_map[transition.event][1] is not None and
                    self.current_rsp.CompareTo(self.transition_map[transition.event][1])):
                return False

        self.create_state(f"state_{self.state_count}", f"{self.current_state.name}_to_state_{self.state_count}",
                          current_mutation_bytes, current_transitions)
        self.state_count += 1
        return True

    # TODO: How to merge the same state?
    def create_state(self, name, event, current_mutation_bytes, current_transitions):
        new_state = State(name)
        transition = self.current_state.to(new_state, event=event)[0]
        self.states.append(new_state)
        self.transition_map[event] = (self.current_req, self.current_rsp)
        self.stateName_map[new_state.name] = new_state
        self.toState_path_map[new_state.name] = {current_mutation_bytes: current_transitions + [transition]}

    def step_with_mutation(self, mutation_packet):
        self.current_req = mutation_packet
        if (self.current_req != None):
            self.socket.send(self.current_req.raw_packet)
        resp = self.socket.recv()
        self.current_rsp = SMPacket(resp.hex())
        print(self.current_rsp.content)

        # if self.current_state == self.not_pair_state:
        #     if (len(self.current_rsp.content["data"]) >= 5) and  (self.current_rsp.content["data"][2] & 0b00000011 == 0 ) and (self.current_rsp.content["data"][5] != 0):
        #         print('error')

        # TODO: if found new state or sanitizer() == true
        if (not self.is_newstate()):
            print("Found new state\n\n\n")

    # step the statemachine to the next state with an existing transition
    def step_with_transition(self, transition):
        self.current_req = self.transition_map[transition.event][0]
        # TODO: send the real packet to the device with SMPsocket; And receive the response
        # if (self.current_req != None):
        #     self.socket.send(self.current_req.raw_packet)
        resp = self.socket.recv()
        self.current_rsp = SMPacket(resp.hex())
        print(self.current_rsp.content)
        if (not self.is_newstate()):
            self.send(transition.event)

    def get_tostate_path(self, state_name):
        idx = random.randint(0, len(self.toState_path_map[state_name]) - 1)
        path = list(self.toState_path_map[state_name].keys())[idx]
        return path

    # move the statemachine to the specified state
    def goto_state(self, state_name, tostate_bytes, mutation_bytes, mutation_packet):
        current_mutation_bytes = mutation_bytes
        current_transitions = self.toState_path_map[state_name][tostate_bytes]
        assert (self.current_state == self.not_pair_state)
        for transition in current_transitions:
            self.step_with_transition(transition)
            assert (self.current_state == transition.target)
        assert (self.current_state.name == state_name)

        # wait for the response of the mutation packet
        self.current_req = mutation_packet
        resp = self.socket.recv()
        self.current_rsp = SMPacket(resp.hex())
        print(self.current_rsp.content)

        # TODO: if found new state or sanitizer() == true
        analyse = SMPSanitizer().messageAnalyse(self.current_req.content, self.current_rsp.content)
        if analyse == False:
            print("Contrary to documents!")
            
        if (not self.is_newstate(current_mutation_bytes, current_transitions)):
            print("Found new state\n\n\n")

    def reset(self):
        if (self.current_state.name == self.not_pair_state.name):
            return
        elif (self.current_state.name != self.final_state.name):
            events = [t.event for t in self.current_state.transitions]
            if (f"{self.current_state.name}_to_{self.final_state.name}" in events):
                self.send(f"{self.current_state.name}_to_{self.final_state.name}")
            else:
                self.current_state.to(self.final_state, event=f"{self.current_state.name}_to_{self.final_state.name}")
                self.transition_map[f"{self.current_state.name}_to_{self.final_state.name}"] = (None, None)
                self.send(f"{self.current_state.name}_to_{self.final_state.name}")
        self.send("final_state_to_not_pair_state")


# if __name__ == '__main__':
#     smp_state_machine = SMPStateMachine("123")
#     with open("test.dot", "w") as f:
#         f.write(smp_state_machine._graph().__str__())

if __name__ == '__main__':
    socket = SMPSocket()
    smp_state_machine = SMPStateMachine("../example1.dot", socket)

    x = smp_state_machine.not_pair_state.to(smp_state_machine.receive_pairing_dhkey_check_state, event="asdfdsfa")

    # for state in smp_state_machine.states:
    #     print(state)
    # with open("test.dot", "w") as f:
    #     f.write(smp_state_machine._graph().__str__())
