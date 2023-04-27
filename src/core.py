from SMPMutator import SMPMutator
from SMPStateMachine import SMPStateMachine
from SMPacket import SMPSocket


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

    def process_fuzzing(self):
        while (True):
            state = self.mutator.stateSelection()
            self.state_machine.goto_state(state)
            # generate a muated request

            self.socket.send("muated request")


if __name__ == '__main__':
    fuzzer = SMPFuzzer()
    fuzzer.process_fuzzing()