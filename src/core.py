from statemachine import StateMachine, State

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


#########################
# State Machine
#########################
class SMPStateMachine(StateMachine):
    '''
    1. 由dot文件生成状态机
    2. 保存mapper（state->packet）
    '''

    def __init__(self, dot):
        self.translate(dot)

    # TODO: translate the dot file to a state machine with "StateMachine" library)
    def translate(self, dot):
        self.closed_state = State('Not Pair State', initial=True)  # Start

    #### States ####

    # Basic States
    closed_state = State('Not Pair State', initial=True)  # Start

    open_state = State('Open State')  # End
    wait_config_state = State('Wait Config State')
    wait_connect_state = State('Wait Connect State')
    wait_connect_rsp_state = State('Wait Connect Rsp State')
    wait_disconnect_state = State('Wait Disconnect State')

    # Optional States (Alternative MAC/PHY enabled operation)
    wait_create_state = State('Wait Create State')
    wait_create_rsp_state = State('Wait Create Rsp State')
    wait_move_confirm_state = State('Wait Move Confirm State')
    wait_move_state = State('Wait Move State')
    wait_move_rsp_state = State('Wait Move Rsp State')
    wait_confirm_rsp_state = State('Wait Confirm Rsp State')

    # Configurateion States
    wait_send_config_state = State('Wait Send Config State')
    wait_config_req_rsp_state = State('Wait Config Req Rsp State')
    wait_config_req_state = State('Wait Config Req State')
    wait_config_rsp_state = State('Wait Config Rsp State')
    wait_control_ind_state = State('Wait Control Ind State')
    wait_final_rsp_state = State('Wait Final Rsp State')
    wait_ind_final_rsp_state = State('Wait Ind Final Rsp State')

    #### Transitions ####

    # from open_state
    open_to_w_discon = open_state.to(wait_disconnect_state)
    open_to_closed = open_state.to(closed_state)
    open_to_w_conf = open_state.to(wait_config_state)
    open_to_w_move = open_state.to(wait_move_state)
    open_to_w_move_rsp = open_state.to(wait_move_rsp_state)
    open_to_w_move_confirm = open_state.to(wait_move_confirm_state)


#########################
# SMP socket
#########################
class SMPSocket:

    def __init__(self):
        self.socket = 0

    def send(self, data):
        self.socket.send(data)

    def recv(self):
        return self.socket.recv(1024)

    def close(self):
        self.socket.close()

    def reset(self):
        pass


#########################
# Mutator & Executor Module
#########################
class SMPMutator:
    '''
    1. 初始语料库+初始概率
    2. 基于现有的概率，选择method、packet、state等进行真实的变异
    '''

    # TODO: Initiate the mutator with {alphabet/real packet, spec constraints}
    def __init__(self, alphabet, spec_constraints):
        self.socket = socket

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
                "oob_data_flag": 0.5,
                "auth_req": 0.5,
                "max_enc_key_size": 0.5,
                "init_key_dist": 0.5,
                "resp_key_dist": 0.5
            },
            "smp_pairing_rsp": {
                "io_capability": 0.5,
                "oob_data_flag": 0.5,
                "auth_req": 0.5,
                "max_enc_key_size": 0.5,
                "init_key_dist": 0.5,
                "resp_key_dist": 0.5
            },
        }
        # state probabilities
        self.state_prob = {
            "Not Pair State": 0.5,
        }

    def mutate(self, data):
        return data


#########################
# Sanitizer Module
#########################
def Sanitizer(current_state, req, resp):
    pass


#########################
# Feedback Module
#########################
def FeedBack():
    pass


def SMPFuzzer():
    state_machine = SMPStateMachine("SMP.dot")
