from SMPStateMachine import SMPStateMachine


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
        pass
        # self.socket = socket

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


def SMPFuzzer():
    state_machine = SMPStateMachine("SMP.dot")
