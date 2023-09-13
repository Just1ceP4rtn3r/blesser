import serial
import serial.tools.list_ports

ser = serial.Serial("COM5", 115200)


def send():
    # a = input("byte: ")
    ser.write(bytes.fromhex("0100f00101f1"))


def recv():
    com_input = b''
    while True:
        com_input = ser.read_all()
        if (com_input != b""):
            print(com_input.hex())


if __name__ == "__main__":
    send()
    recv()
