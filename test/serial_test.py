import serial
import serial.tools.list_ports

ser = serial.Serial("COM3", 115200)
a = 0
while (input(a)):
    ser.write(bytes.fromhex("0201000101ffee"))
