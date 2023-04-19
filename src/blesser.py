import bluetooth
import sys, os, re
import datetime, json

from scapy.all import *
from OuiLookup import OuiLookup
from collections import OrderedDict

ChoosenDevice = {}


def bluetooth_classic_scan():
    """
    This scan finds ONLY Bluetooth Classic (non-BLE) devices
    """
    print('Performing classic bluetooth inquiry scan...')

    nearby_devices = bluetooth.discover_devices(duration=8,
                                                lookup_names=True,
                                                flush_cache=True,
                                                lookup_class=False)

    print("Found {} devices".format(len(nearby_devices)))

    for addr, name in nearby_devices:
        try:
            print("   {} - {}".format(addr, name))
        except UnicodeEncodeError:
            print("   {} - {}".format(addr, name.encode("utf-8", "replace")))

    while (True):
        user_input = int(input("\nChoose Device : "))
        if user_input < len(nearby_devices) or user_input > -1:
            idx = user_input
            break
        else:
            print("[-] Out of range.")

    addr_chosen = nearby_devices[idx][0]

    return addr_chosen


# main
if __name__ == '__main__':
    addr_chosen = bluetooth_classic_scan()
    print(addr_chosen)

    # with open('device.json', 'w') as outfile:
    #     json.dump(ChoosenDevice, outfile)

    print("Done")