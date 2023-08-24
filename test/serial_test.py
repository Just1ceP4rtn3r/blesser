import serial
import serial.tools.list_ports

ser = serial.Serial("COM3", 115200)
a = 0
while (input(a)):
    ser.write(bytes.fromhex("0400000102030405060708090a0b0c0d0e0f0100ff"))
