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
        self.mutator = SMPMutator()
        self.mutator.calculateStateProb(self.state_machine.states)

    def process_fuzzing(self):
        while (True):
            state = self.mutator.stateSelection()
            self.state_machine.goto_state(state)
            break
            # TODO: generate a muated request



            self.state_machine.step_with_mutation()
            self.mutator.calculateStateProb(self.state_machine.states)
            # reset the socket
            self.socket.reset()


if __name__ == '__main__':
    fuzzer = SMPFuzzer()
    fuzzer.process_fuzzing()