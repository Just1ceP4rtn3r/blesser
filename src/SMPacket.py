import pyshark


# BLE SMP protocol packet class
class SMPacket:

    def __init__(self, packet_cap):
        self.raw_packet = None
        self.packet_type = None
        self.content = []

    def CompareTo(self, packet):
        if (self.content == packet.content):
            return True
        else:
            return False
