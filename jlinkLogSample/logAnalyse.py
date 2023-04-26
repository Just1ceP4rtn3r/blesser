# -*- coding: utf-8 -*-
"""
Created on 2304

@author: 
"""

import sys
import time
import re

import sys
import threading
import time
import logging
import pylink



BUFFER_SIZE_UP = 1024

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
    0x0a: "smp_signing_info",
    # Peripheral -> Central; The Security Request command is used by the Peripheral to request that the Central initiates security with the requested security properties, see Section 2.4.6. The Security Request command is defined in Figure 3.17.
    0x0b: "smp_security_request",
    # Central -> Peripheral | Peripheral -> Central;
    0x0c: "smp_public_key",
    # Central -> Peripheral | Peripheral -> Central;
    0x0d: "smp_dhkey_check",
    0x0e: "smp_keypress_notif",
}

# # error code
# ERROR_CODE = {
#     0x01: "",
# }

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
    0x00 : "No Bonding",
    0x01 : "Bonding",
}

# device info
# Nordic Semi
# nRF52840_xxAA
# Cortex-M4

#find error
def find_error_log(log_name):
    original_file = open(log_name, encoding='utf-8')
    extract = []
    for line_data in original_file:
        error = re.search('err', line_data, re.IGNORECASE) # re.IGNORECASE 
        warning = re.search('warn', line_data, re.IGNORECASE)
        # deviceFound = re.search('Device found', line_data, re.IGNORECASE)
        pairingFailed = re.search('Pairing failed', line_data, re.IGNORECASE)
        exception = re.search('exception', line_data, re.IGNORECASE)

        if error or warning or pairingFailed or exception :
        # if error or warning or deviceFound or pairingFailed or exception :
            log_str = line_data
            extract.append(log_str)
            
   
    errlog = './catalinaError.txt'
    new_file = open(errlog, 'w')
    new_file.writelines(extract)
    new_file.flush()
    new_file.close()
    original_file.close()
    print("log error warn func done.")
    #return "error log done"
    return extract


# jlink rtt log read
def jlinkRead():
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

    # while(1):
    for i in range(5):
    rawData = jlink.rtt_read(0, 2048)
    if rawData:     
        decodeData = ''.join([chr(x) for x in jlink.rtt_read(0, len(rawData))])
        print(decodeData)


    jlink.rtt_stop()

    jlink.close()








