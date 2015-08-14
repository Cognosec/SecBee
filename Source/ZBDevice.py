from Tkinter import *


class ZBDevice():
    
    def __init__(self):
        self.short_address = None
        self.ext_address = None
        self.mac_address = None
        self.frame_counter = None
        self.zb_nwk_seqnumber = None
        self.dot15d4_seqnumber = None
        self.zb_zadp_counter = None
        self.zb_zcl_trans_seq = None
        self.endpoints = None
        self.pan_id = None
        self.destinations = []
        self.scheduled_packet = None
    
    def print_device(self, T):
        T.insert(END,"Short Address: " + str(self.short_address)+"\n")
        T.insert(END,"Ext Address: " +str(self.ext_address)+"\n")
        T.insert(END,"MAC address: " +str(self.mac_address)+"\n")
        T.insert(END,"Frame Counter: "+str(self.frame_counter)+"\n")
        T.insert(END,"ZB NWK Seqnumber: "+str(self.zb_nwk_seqnumber)+"\n")
        T.insert(END,"IEEE Seqnumber: "+str(self.dot15d4_seqnumber)+"\n")
        T.insert(END,"ZigBee AppDataPayload Counter: "+str(self.zb_zadp_counter)+"\n")
        T.insert(END,"ZigBee ZCL Trans Seqnumber: "+str(self.zb_zcl_trans_seq)+"\n")
        if self.scheduled_packet != None:
            T.insert(END,"Scheduled Packet set: \n")
        else:
            T.insert(END,"NO scheduled packet set: \n")

    def print_destinations(self, T):
        i = 0
        for dest in self.destinations:
            T.insert(END,"-- Destination: "+str(i)+"\n")
            dest.print_device(T)
            i = i + 1






