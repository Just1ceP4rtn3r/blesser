from SMPMutator import SMPMutator
from SMPStateMachine import SMPStateMachine
from SMPacket import SMPSocket, SMPSocket_TEST
import random


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
            # TODO: generate a muated request
            req = random.choice(self.state_machine.corpus)
            self.state_machine.step_with_mutation(req)
            self.mutator.calculateStateProb(self.state_machine.states)
            # reset the socket
            self.socket.reset()
            self.state_machine.reset()


if __name__ == '__main__':
    fuzzer = SMPFuzzer()
    fuzzer.process_fuzzing()