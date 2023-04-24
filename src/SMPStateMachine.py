from statemachine import StateMachine, State
from statemachine.transition import Transition
import re

#########################
# State Machine
#########################
class SMPStateMachine(StateMachine):
    ######################################################## States ########################################################
    # Entrypoint, now we have a L2CAP connection
    not_pair_state = State('Not Pair State', initial=True)
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
                                         
    #### code:0x02 Pairing Response ####
    receive_paring_rsp_state = State('Receive Paring Response State')
    #### code:0x0c Pairing Confirm ####
    receive_pairing_confirm_state = State('Receive Paring Confirm State')
    #### code:0x04 Pairing Random ####
    receive_pairing_random_state = State('Receive Paring Random State')
    #### code:0x0c Pairing DHKey Check ####
    receive_pairing_dhkey_check_state = State('Receive Paring DHKey State')

    ######################################################## Transitions ########################################################
    not_pair_to_receive_paring_rsp = not_pair_state.to(receive_paring_rsp_state, cond="receive_paring_rsp")
    
    receive_paring_rsp_to_receive_pairing_confirm_state = receive_paring_rsp_state.to(receive_pairing_confirm_state,cond="receive_pairing_confirm")
    
    receive_pairing_confirm_state_to_receive_pairing_random_state = receive_pairing_confirm_state.to(receive_pairing_random_state,cond="receive_pairing_random")
    
    receive_pairing_random_state_to_receive_pairing_dhkey_check_state = receive_pairing_random_state.to(receive_pairing_dhkey_check_state,cond="receive_pairing_dhkey_check")
    
    receive_pairing_dhkey_check_state_to_final_state = receive_pairing_dhkey_check_state.to(final_state)

    '''
    1. 由dot文件生成状态机
    2. 保存mapper（state->packet）
    '''

    def __init__(self, dot):
        self.current_req = None
        self.current_rsp = None
        # {tran_1: (req_1, rsp_1)}
        self.transition_map = {}
        # {state1: [(tran_1, tran_2)], state2: [(tran_3, tran_4)]}
        self.toState_path_map = {}
        self.translate(dot)

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
                self.states.append(State(
                    name=state_match_res[1],
                    value={
                        "shape": state_match_res[2],
                        "label": state_match_res[3]
                    }
                ))
            elif state_match_res == None and transition_match_res != None:
                # Transition matched
                self.transitions.append(Transition(
                    source=State(name=transition_match_res[1]),
                    target=State(name=transition_match_res[2]),
                    event=[transition_match_res[3], transition_match_res[4]]
                ))
            elif state_match_res == None and transition_match_res == None:
                # both not matched
                transition_match_res = re.match(r'__start0 -> ([a-zA-Z0-9]+);', line)
                if transition_match_res != None:
                    self.transitions.append(Transition(
                        source=State(name="__start0"),
                        target=State(name=transition_match_res[1])
                    ))
            else:
                # both matched
                assert(False)

    def find_counterexample(self):
        new_state = State('new state')
        trans = self.current_state.to(new_state, event="test/test")
        pass

    def goto_state(self, state):
        pass

    def process_fuzzing(self):
        for state in self.states:
            self.goto_state(state)
            for mutated_req in range(100):
                self.current_req = mutated_req
                self.current_rsp = None
                self.find_counterexample()

    #### Conditions/Callbacks ####
    def receive_paring_rsp(self):
        # TODO：need more detailed packet comparison       
        if (self.current_req.packet_type == "smp_pairing_req" and self.current_rsp.packet_type == "smp_pairing_rsp"):
            return True
        else:
            return False
    
    def receive_pairing_confirm(self):
        # TODO：need more detailed packet comparison
        if (self.current_req.packet_type == "smp_pairing_req" and self.current_rsp.packet_type == "smp_pairing_rsp"):
            return True
        else:
            return False

    def receive_pairing_random(self):
        # TODO：need more detailed packet comparison
        if (self.current_req.packet_type == "smp_pairing_req" and self.current_rsp.packet_type == "smp_pairing_rsp"):
            return True
        else:
            return False

    def receive_pairing_dhkey_check(self):
        # TODO：need more detailed packet comparison
        if (self.current_req.packet_type == "smp_pairing_req" and self.current_rsp.packet_type == "smp_pairing_rsp"):
            return True
        else:
            return False

if __name__ == '__main__':
    smp_state_machine = SMPStateMachine("../example1.dot")
    for state in smp_state_machine.states:
        print(state)
    for transition in smp_state_machine.transitions:
        print(transition)