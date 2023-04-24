from statemachine import StateMachine, State
import pydot
import re


#########################
# State Machine
#########################
class SMPStateMachine(StateMachine):
    ######################################################## States ########################################################
    # Entrypoint, now we have a L2CAP connection
    '''
    not_pair_state = State('Not Pair State', initial=True)
    # End, close the L2CAP connection
    final_state = State('Final State', final=True)

    #### code:0x05 Pairing Failed####
    # reason:0x01; Passkey Entry Failed
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x0501)
    # reason:0x02; OOB Not Available
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x0502)
    # reason:0x03; Authentication Requirements
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x0503)
    # reason:0x04; Confirm Value Failed
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x0504)
    # reason:0x05; Pairing Not Supported
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x0505)
    # reason:0x06; Encryption Key Size
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x0506)
    # reason:0x07; Command Not Supported
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x0507)
    # reason:0x08; Unspecified Reason
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x0508)
    # reason:0x09; Repeated Attempts
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x0509)
    # reason:0x0A; Invalid Parameters
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x050a)
    # reason:0x0B; DHKey Check Failed
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x050b)
    # reason:0x0C; Numeric Comparison Failed
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x050c)
    # reason:0x0D; BR/EDR Pairing In Progress
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x050d)
    # reason:0x0E; Cross Transport Key Derivation Generation Not Allowed
    receive_pairing_failed_state = State('Receive Pairing Failed State', value=0x050e)


    #### code:0x02 Pairing Response ####
    receive_paring_rsp_state = State('Receive Paring Response State')


    ######################################################## Transitions ########################################################
    not_pair_to_receive_paring_rsp = not_pair_state.to(receive_paring_rsp_state, cond="receive_paring_rsp")
    '''





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
        dot_file = open(dot, "r")
        lines = dot_file.readlines()
        dot_file.close()
        state_pattern = re.compile(r'\s*([a-z0-9]+) \[shape="([a-z]+)" label="([0-9]+)"\]')
        s = 's2 [shape="circle" label="2"];'
        res = state_pattern.findall(s)
        if res:
            print(res)
        else:
            print("Not matched")
            #print("")
            

    def find_counterexample(self):
        new_state = State('new state')
        trans = self.current_state.to(new_state,event="test/test")
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
        pass


if __name__ == "__main__":
    dfa = SMPStateMachine("../example1.dot")
