from bluepy.btle import Scanner
from OuiLookup import OuiLookup

ChoosenDevice = {}


def BluetoothScan():
    """
    This scan finds ONLY Bluetooth Classic (non-BLE) devices
    """
    print('Performing classic bluetooth inquiry scan...')

    choosen_device = ''
    while True:
        try:
            #10.0 sec scanning
            ble_list = Scanner().scan(3.0)
            for dev in ble_list:
                oui = OuiLookup().query(dev.addr)
                name = ""
                for (adtype, desc, value) in dev.getScanData():
                    if (desc == "Complete Local Name"):
                        name = value
                        break
                print(f"Device {name}, oui {oui}, MAC {dev.addr} ({dev.addrType}), RSSI={dev.rssi} dB")
            IN = input()
            if (len(IN) != 17):
                continue
            else:
                choosen_device = IN
        except:
            raise Exception("Error occured")


# main
if __name__ == '__main__':
    BluetoothScan()

    # with open('device.json', 'w') as outfile:
    #     json.dump(ChoosenDevice, outfile)

    print("Done")