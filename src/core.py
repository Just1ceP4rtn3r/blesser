from SMPMutator import SMPMutator
from SMPStateMachine import SMPStateMachine


#########################
# SMP socket
#########################
class SMPSocket:

    def __init__(self):
        self.socket = 0

    def send(self, data):
        print(f"send {data}")

    def recv(self):
        return "123"

    def close(self):
        pass

    def reset(self):
        pass


#########################
# Sanitizer Module
#########################
def Sanitizer(current_state, req, resp):
    pass


#########################
# Feedback Module
#########################
class SMPFuzzer():

    def __init__(self):
        self.socket = SMPSocket()
        self.state_machine = SMPStateMachine("SMP.dot", self.socket)
        self.mutator = SMPMutator(self.state_machine)

        self.process_fuzzing(self.state_machine, self.mutator)

    def process_fuzzing(self):
        while (True):
            state = self.mutator.stateSelection()
            self.state_machine.goto_state(state)
            # generate a muated request

            self.socket.send("muated request")