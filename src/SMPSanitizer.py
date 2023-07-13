#########################
# sanitizer Module
#########################

import sys
import time
import re

import logging
import pylink

from statemachine import StateMachine, State
from statemachine.transition import Transition

# TODO 存在的bug很多，主要接口没法对应
RTT_BUFFER_SIZE = 1024

# smp sstatus code
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
    0x0A: "smp_signing_info",
    0x0B: "smp_security_request",
    0x0C: "smp_public_key",
    0x0D: "smp_dhkey_check",
    0x0E: "smp_keypress_notif",
}

# # error code
# ERROR_CODE = {
#     0x01: "",
# }

# pairing failed code for detect
FAILED_CODE = {
    0x01: "Passkey Entry Failed",
    0x02: "OOB Not Available",
    0x03: "Authentication Requirements",
    0x04: "Confirm Value Failed",
    0x05: "Pairing Not Supported",
    0x06: "Encryption Key Size",
    0x07: "Command Not Supported",
    0x08: "Unspecified Reason",
    0x09: "Repeated Attempts",
    0x0A: "Invalid Parameters",
    0x0B: "DHKey Check Failed",
    0x0C: "Numeric Comparison Failed",
    0x0D: "BR/EDR pairing in progress",
    0x0E: "Cross-transport Key Derivation/Generation not allowed",
    0x0F: "Key Rejected",
}

BOND_FLAGS = {
    0x00: "No Bonding",
    0x01: "Bonding",
}

# todo 加入 failed code等信息
DETECT_WORDS = [
    'error',
    'err',
    'exception',
    'warning',
    'warn',
    'failed',
    'timeout',
]


class SMPSanitizer:
    '''
    1. 分析jlink RTT LOG文件，提取感兴趣数据
    2. 检测state变化数据
    '''

    #Todo rtt read bugs
    def __init__(self, currentState, send, recv, log):
        self.sanitizer(currentState, stateMachine, send, recv)

    def sanitizer(self, currentState, stateMachine, send, recv):
        pass

    # jlink rtt log read
    # connectDevice = 'nRF52840_xxAA'
    def jlinkRttLog(self, connectDevice, readBufSize):
        # start jlink and rtt
        jlink = pylink.JLink()
        jlink.open()

        # param about nrf52840
        readBufSize = RTT_BUFFER_SIZE  # RTT_BUFFER_SIZE=1024
        jlink.set_tif(pylink.enums.JLinkInterfaces.SWD)
        # connectDevice = 'nRF52840_xxAA'
        jlink.connect(connectDevice)
        jlink.rtt_start()

        # while(1):
        # for i in range(5):
        # rawData = jlink.rtt_read(0, RTT_BUFFER_SIZE)
        # if rawData:
        #     decodeData = ''.join([chr(x) for x in jlink.rtt_read(0, len(rawData))])
        #     print(decodeData)

        for i in range(5):
            # while(1):
            decodeData = ''.join([chr(x) for x in jlink.rtt_read(0, len(readBufSize))])
            print(decodeData)
            # sleep
            time.sleep(0.05)

        # stop rtt and jlink
        # todo 可能需要一个多线程
        jlink.rtt_stop()
        jlink.close()

    #find intersting log report from RttLog
    # return extract interesting info
    def logAnalyse(logPath, extractPath):
        # rtt log file
        logFile = open(logPath, encoding='utf-8')

        # storge extract info
        extract = []

        for line_data in logFile:
            error = re.search('err', line_data, re.IGNORECASE)  # re.IGNORECASE
            warning = re.search('warn', line_data, re.IGNORECASE)
            # deviceFound = re.search('Device found', line_data, re.IGNORECASE)
            pairingFailed = re.search('Pairing failed', line_data, re.IGNORECASE)
            exception = re.search('exception', line_data, re.IGNORECASE)

            if error or warning or pairingFailed or exception:
                # if error or warning or deviceFound or pairingFailed or exception :
                log_str = line_data
                extract.append(log_str)

            # todo: 统一转移到使用DETECT_WORDS 表
            # if any(re.search(keyword, line_data) for keyword in DETECT_WORDS):
            #     log_str = line_data
            #     extract.append(log_str)

        # todo: 对接的输出接口
        # extractPath = './logError.txt'
        extractPath = './logError.txt'

        extractFile = open(extractPath, 'w')
        extractFile.writelines(extract)
        extractFile.flush()
        extractFile.close()

        logFile.close()

        # print("log error warn func done.")
        # return "error log done"
        return extract

    # jlink rtt log read Test
    def jlinkReadTest(self):
        jlink = pylink.JLink()
        jlink.open()
        jlink.set_tif(pylink.enums.JLinkInterfaces.SWD)
        jlink.connect('nRF52840_xxAA')

        jlink.rtt_start()

        print('Please enter rtt write data and click ENTER:')
        writedata = input()
        jlink.rtt_write(0, [ord(x) for x in list(writedata)])

        print()

        print('Echo data:')
        readdata = ''.join([chr(x) for x in jlink.rtt_read(0, len(writedata))])
        print(readdata)

        jlink.rtt_stop()
        jlink.close()

    # 通过状态机变化检测有趣的信息
    def stateAnalyse(self, stateMachine, curState):

        # 判断的具体条件存疑，
        if (curState == final_state):
            # if (curState.compare(init_state)):
            print("state machine over")
            feedbackReport(self, StateMachine, curState, sent, recv)
            reSetReport()
            pass

        # def is_newstate(self): 这个函数参数非curState
        if (is_newstate(curState) == True):
            # if ( is_newstate(StateMachine) == True):
            print("new state appear")
            feedbackReport(self, StateMachine, curState, sent, recv)
            pass

        if (curState.compare(init_state)):
            print("return to init state")
            feedbackReport(self, StateMachine, curState, sent, recv)
            pass

        # # 状态转移的问题
        # if (curState.transitions.compare()):

        # for state in self.states:
        #     for transition in state.transitions:
        # transition.source, transition.target

        for transition in curState.transitions:
            src = transition.source
            dest = transition.target

            if (recv.compare(dest) != True):
                feedbackReport(self, StateMachine, curState, sent, recv)
            pass

        # 具体的例子

    # 将现在的状态发回XXX
    def feedbackReport(self, StateMachine=None, curState=None, sent=None, recv=None):
        #todo 对接给哪个函数
        pass

    # 需要重置的情况
    def reSetReport(self, StateMachine=None, curState=None, sent=None, recv=None):

        reSetFuzzer()
        resetLog()
        pass
