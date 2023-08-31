import serial
import serial.tools.list_ports

ser = serial.Serial("COM3", 115200)


def send():
    a = input("byte: ")
    ser.write(bytes.fromhex("0400000102030405060708090a0b0c0d0e0f0100ff"))


def recv():
    com_input = b''
    while True:
        com_input = ser.read_all()
        if (com_input != b""):
            print(com_input)


if __name__ == "__main__":
    send()
    recv()
