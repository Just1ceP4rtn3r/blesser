import os
import sys
from statemachine import StateMachine, State
from statemachine.transition import Transition
import re
import networkx as nx
import warnings

from SMPacket import SMPacket


#########################
# State Machine
#########################
class SMPStateMachine(StateMachine):

    current_req = None
    current_rsp = None
    # {tran_1: (req_1, rsp_1)}
    transition_map = {}
    # {state1: [[tran_1, tran_2]], state2: [[tran_3, tran_4]]}
    toState_path_map = {}

    ######################################################## States ########################################################
    # Entrypoint, now we have a L2CAP connection
    not_pair_state = State('Not Pair State', initial=True)
    toState_path_map = {not_pair_state: []}
    # End, close the L2CAP connection
    final_state = State('Final State', final=True)

    #### code:0x05 Pairing Failed####
    """
    # reason:0x01; Passkey Entry Failed
    receive_pairing_failed_state_1 = State('Receive Pairing Failed State;Passkey Entry Failed', value=0x0501)
    # reason:0x02; OOB Not Available
    receive_pairing_failed_state_2 = State('Receive Pairing Failed State;OOB Not Available', value=0x0502)
    # reason:0x03; Authentication Requirements
    receive_pairing_failed_state_3 = State('Receive Pairing Failed State;Authentication Requirements', value=0x0503)
    # reason:0x04; Confirm Value Failed
    receive_pairing_failed_state_4 = State('Receive Pairing Failed State;Confirm Value Failed', value=0x0504)
    # reason:0x05; Pairing Not Supported
    receive_pairing_failed_state_5 = State('Receive Pairing Failed State;Pairing Not Supported', value=0x0505)
    # reason:0x06; Encryption Key Size
    receive_pairing_failed_state_6 = State('Receive Pairing Failed State;Encryption Key Size', value=0x0506)
    # reason:0x07; Command Not Supported
    receive_pairing_failed_state_7 = State('Receive Pairing Failed State;Command Not Supported', value=0x0507)
    # reason:0x08; Unspecified Reason
    receive_pairing_failed_state_8 = State('Receive Pairing Failed State;Unspecified Reason', value=0x0508)
    # reason:0x09; Repeated Attempts
    receive_pairing_failed_state_9 = State('Receive Pairing Failed State;Repeated Attempts', value=0x0509)
    # reason:0x0a; Invalid Parameters
    receive_pairing_failed_state_10 = State('Receive Pairing Failed State;Invalid Parameters', value=0x050a)
    # reason:0x0b; DHKey Check Failed
    receive_pairing_failed_state_11 = State('Receive Pairing Failed State;DHKey Check Failed', value=0x050b)
    # reason:0x0c; Numeric Comparison Failed
    receive_pairing_failed_state_12 = State('Receive Pairing Failed State;Numeric Comparison Failed', value=0x050c)
    # reason:0x0d; BR/EDR Pairing In Progress
    receive_pairing_failed_state_13 = State('Receive Pairing Failed State;BR/EDR Pairing In Progress', value=0x050d)
    # reason:0x0e; Cross Transport Key Derivation/Generation Not Allowed
    receive_pairing_failed_state_14 = State('Receive Pairing Failed State;Cross Transport Key Derivation/Generation Not Allowed',
                                         value=0x050e)
    """
    #### code:0x05 Pairing Failed ####
    # receive_pairing_failed_state = State('Receive Pairing Failed State')

    #### code:0x02 Pairing Response ####
    receive_pairing_rsp_state = State('Receive Pairing Response State')
    
    #### code:0x03 Pairing Confirm ####
    receive_pairing_confirm_state = State('Receive Pairing Confirm State')
    
    #### code:0x04 Pairing Random ####
    receive_pairing_random_state = State('Receive Pairing Random State')

    #### code:0x0c Pairing Public Key ####
    receive_pairing_public_key_state = State('Receive Pairing Public Key')

    #### code:0x0d Pairing DHKey Check ####
    receive_pairing_dhkey_check_state = State('Receive Pairing DHKey State')

    ######################################################## Transitions ########################################################
    not_pair_state.to(receive_pairing_rsp_state, cond="receive_pairing_rsp", event="not_pair_to_receive_pairing_rsp")
    # parse 
    smp_pairing_request = SMPacket(sys.path[0]+"/packet_sequence/miband_pairing_request.pcapng")
    smp_pairing_response = SMPacket(sys.path[0]+"/packet_sequence/miband_pairing_response.pcapng")
    transition_map["not_pair_to_receive_pairing_rsp"] = (smp_pairing_request, smp_pairing_response)

    receive_pairing_rsp_state.to(receive_pairing_public_key_state,
                                cond="receive_pairing_public_key",
                                event="receive_pairing_rsp_to_receive_pairing_public_key")
    # TODO: how to get pairing public key
    # smp_sent_pairing_public_key = SMPacket(sys.path[0]+"/packet_sequence/miband_sent_pairing_public_key.pcapng")
    smp_rcvd_pairing_public_key = SMPacket(sys.path[0]+"/packet_sequence/miband_rcvd_pairing_public_key.pcapng")
    transition_map["receive_pairing_rsp_to_receive_pairing_public_key"] = (None, smp_rcvd_pairing_public_key)

    receive_pairing_public_key_state.to(receive_pairing_confirm_state,
                                cond="receive_pairing_confirm",
                                event="receive_pairing_public_key_to_receive_pairing_confirm_state")
    smp_rcvd_pairing_confirm = SMPacket(sys.path[0]+"/packet_sequence/miband_pairing_confirm.pcapng")
    transition_map["receive_pairing_public_key_to_receive_pairing_confirm_state"] = (None, smp_rcvd_pairing_confirm)

    receive_pairing_confirm_state.to(receive_pairing_random_state,
                                     cond="receive_pairing_random",
                                     event="receive_pairing_confirm_state_to_receive_pairing_random_state")
    smp_sent_pairing_random = SMPacket(sys.path[0]+"/packet_sequence/miband_sent_pairing_random.pcapng")
    smp_rcvd_pairing_random = SMPacket(sys.path[0]+"/packet_sequence/miband_rcvd_pairing_random.pcapng")
    transition_map["receive_pairing_confirm_state_to_receive_pairing_random_state"] = (smp_sent_pairing_random, smp_rcvd_pairing_random)

    receive_pairing_random_state.to(receive_pairing_dhkey_check_state,
                                    cond="receive_pairing_dhkey_check",
                                    event="receive_pairing_random_state_to_receive_pairing_dhkey_check_state")
    smp_sent_DHKey_check = SMPacket(sys.path[0]+"/packet_sequence/miband_sent_DHKey_check.pcapng")
    smp_rcvd_DHKey_check = SMPacket(sys.path[0]+"/packet_sequence/miband_rcvd_DHKey_check.pcapng")
    transition_map["receive_pairing_random_state_to_receive_pairing_dhkey_check_state"] = (smp_sent_DHKey_check, smp_rcvd_DHKey_check)

    # receive_pairing_dhkey_check_state.to(receive_pairing_failed_state,
    #                                      cond="receive_pairing_failed",
    #                                      event="receive_pairing_dhkey_check_state_to_receive_pairing_failed_state")
    # transition_map["receive_pairing_dhkey_check_state_to_receive_pairing_failed_state"] = (None, None)

    # receive_pairing_failed_state.to(final_state, event="receive_pairing_failed_state_to_final_state")
    # transition_map["receive_pairing_failed_state_to_final_state"] = (None, None)
    receive_pairing_dhkey_check_state.to(final_state, event="receive_pairing_dhkey_check_state_to_final_state")
    transition_map["receive_pairing_dhkey_check_state_to_final_state"] = (None, None)

    def __init__(self, dot):
        # self.translate(dot)
        # state_array: the state that has been traversed
        state_array = []
        # self.traverse_state_machine(self.not_pair_state, state_array)
        self.traverse_state_machine()
        for key,value in self.toState_path_map.items():
            print("to state:",key,"\npath:",value)
            print("\n\n")
        super().__init__(self)


    def traverse_state_machine(self):
        all_transitions_dict = {}
        all_transitions = []

        for state in self.states:
            for transition in state.transitions:
                all_transitions.append((transition.source,transition.target))
                all_transitions_dict[(transition.source,transition.target)] = transition.event
        
        G = nx.MultiDiGraph()
        G.add_edges_from(all_transitions)
        for state in self.states:
            if state.name == self.not_pair_state.name:
                continue
            self.toState_path_map[state] = []
            paths = nx.all_simple_paths(G,self.not_pair_state,state)
            for path in paths:
                i = 0
                while i+1 < len(path):
                    event = all_transitions_dict[(path[i],path[i+1])]
                    self.toState_path_map[state].append(self.transition_map[event])
                    i = i + 1

    # [can only be called with a state machine] traverse the initial state machine to generate the transition_map & toState_path_map
    # def traverse_state_machine(self, state: State, state_array):
    #     for transition in state.transitions:
    #         # if the target state has been traversed, then skip it
    #         if (transition.target in state_array):
    #             continue
    #         if transition.target not in self.toState_path_map:
    #             self.toState_path_map[transition.target] = []
    #         for path in self.toState_path_map[state]:
    #             p = path + [transition]
    #             if (p not in self.toState_path_map[transition.target]):
    #                 self.toState_path_map[transition.target].append(path + [transition])

    #         state_array.append(transition.target)
    #         self.traverse_state_machine(transition.target, state_array)

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

    def find_counterexample(self):
        new_state = State('new state')
        trans = self.current_state.to(new_state, event="test/test")
        pass

    def goto_state(self, state):
        assert (self.current_state == self.not_pair_state)
        for transition in self.toState_path_map[state]:
            self.send(transition.event)
        assert (self.current_state == state)

    def process_fuzzing(self):
        for state in self.states:
            self.goto_state(state)
            for mutated_req in range(100):
                self.current_req = mutated_req
                self.current_rsp = None
                self.find_counterexample()

    #### Conditions/Callbacks ####
    def receive_pairing_rsp(self):
        # TODO：need more detailed packet comparison
        if (self.current_req.packet_type == "smp_pairing_req" and self.current_rsp.packet_type == "smp_pairing_rsp"):
            return True
        else:
            return False

    def receive_pairing_public_key(self):
        # TODO：need more detailed packet comparison
        if (self.current_req.packet_type == "smp_pairing_public_key" and self.current_rsp.packet_type == "smp_pairing_confirm"):
            return True
        else:
            return False

    def receive_pairing_confirm(self):
        # TODO：need more detailed packet comparison
        if (self.current_req.packet_type == "smp_pairing_confirm" and self.current_rsp.packet_type == "smp_pairing_confirm"):
            return True
        else:
            return False

    def receive_pairing_random(self):
        # TODO：need more detailed packet comparison
        if (self.current_req.packet_type == "smp_pairing_random" and self.current_rsp.packet_type == "smp_pairing_random"):
            return True
        else:
            return False

    def receive_pairing_dhkey_check(self):
        # TODO：need more detailed packet comparison
        if (self.current_req.packet_type == "smp_dhkey_check" and self.current_rsp.packet_type == "smp_dhkey_check"):
            return True
        else:
            return False

    def receive_pairing_failed(self):
        # TODO：need more detailed packet comparison
        if (self.current_rsp.packet_type == "smp_pairing_failed"):
            return True
        else:
            return False


if __name__ == '__main__':
    smp_state_machine = SMPStateMachine("123")
    with open("test.dot", "w") as f:
        f.write(smp_state_machine._graph().__str__())

# if __name__ == '__main__':
#     smp_state_machine = SMPStateMachine("../example1.dot")
#     for state in smp_state_machine.states:
#         print(state)
#     for transition in smp_state_machine.transitions:
#         print(transition)