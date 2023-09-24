import serial
import serial.tools.list_ports
import time

ser = serial.Serial("COM5", 115200)


def send(c):
    # a = input("byte: ")
    c += bytes([0x66, 0x78, 0x78, 0x6b])
    ser.write(c)


def reset():
    reset_data = b'\x01'
    reset_data += bytes([0x66, 0x78, 0x78, 0x6b])
    # a = input("byte: ")
    ser.write(reset_data)

def recv():
    com_input = b''
    lent = 0
    while True:
        com_input = ser.read_all()
        lent += len(com_input)
        # print(lent)
        if (com_input != b""):
            print(com_input.hex())


if __name__ == "__main__":
    #reset()
    send(b'\x00')
    # time.sleep(2)
    # send(b'\xff')
    # recv()
    
