from ZBDevice import *
from Tkinter import *
import pickle
import tkFileDialog
import scapy.killerbee
from scapy.all import *
from argparse import ArgumentParser
import sys
import copy
import scapy.layers.zigbee
import threading
import atexit
import os
import socket
import zigbee_transkey
from subprocess import call
import ConfigParser

known_devices = []
network_keys = []
seen_packets = []
source_choices = []
send_packet = False
send_acks = False
acknowledged = []
#beacon_dot15d4_seqnum = 23
#active_networkkey = "144221a817f284c7e6e1f000cd80ff0f".decode('hex')
#active_networkkey = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".decode('hex')
i = 0

zb_defaultkey = ""
networkkeys_file = ""
knowndevices_file = ""


#defaultkey = '5a6967426565416c6c69616e63653039'.decode('hex')
zb_defaultkey = "ZigBeeAlliance09"

class MyThread(threading.Thread):
 
    def run(self):
        _seen = dict()
        sniffradio( radio="Zigbee", prn=lambda p, se=_seen: self.handle_packets(p, se), lfilter=lambda x: x.haslayer(Dot15d4Data))

    def extract_infos(self, packet):
        global known_devices
        global active_networkkey

        for dev in known_devices:
            #check if dev is in knowndevies
            if packet.src_addr == dev.short_address:
                #check if ext address exists
                #otherwise search for extended address
                if dev.ext_address == None:
                    if packet.haslayer(scapy.layers.zigbee.ZigbeeSecurityHeader):
                        if packet.getlayer(scapy.layers.zigbee.ZigbeeSecurityHeader).source is not None:
                            dev.ext_address = copy.deepcopy(packet.getlayer(scapy.layers.zigbee.ZigbeeSecurityHeader).source)
                dev.dot15d4_seqnumber = copy.deepcopy(packet.getlayer(Dot15d4FCS).seqnum)

                #check for broadcast
                if packet.dest_addr == 65535:
                    for dest in dev.destinations:
                        dest = self.update_counter(dest,packet)
                    return

                #search for destination and update the counters
                for dest in dev.destinations:
                    #destination already existing
                    if dest.short_address == packet.dest_addr:
                        #update the counters
                        dest = self.update_counter(dest,packet)
                        #destination found and updated
                        return

                #destination new
                #create new destination and update counter
                new_destination = ZBDevice()

                if packet.haslayer(Dot15d4Data):
                    new_destination.pan_id = copy.deepcopy(packet.getlayer(Dot15d4Data).dest_panid)

                new_destination.short_address = copy.deepcopy(packet.dest_addr)
                #update the counters
                new_destination.dot15d4_seqnumber = copy.deepcopy(packet.seqnum)

                new_destination = self.update_counter(new_destination, packet)

                dev.destinations.append(new_destination)

                return



        print "New device found"
        new_device = ZBDevice()
        new_device.short_address = copy.deepcopy(packet.src_addr)
        new_device.dot15d4_seqnumber = copy.deepcopy(packet.getlayer(Dot15d4FCS).seqnum)
        if packet.haslayer(scapy.layers.zigbee.ZigbeeSecurityHeader):
            if packet.getlayer(scapy.layers.zigbee.ZigbeeSecurityHeader).source is not None:
                new_device.ext_address = copy.deepcopy(packet.getlayer(scapy.layers.zigbee.ZigbeeSecurityHeader).source)

        #check for braodcast
        if packet.dest_addr == 65535:
            known_devices.append(new_device)
            return

        #destination new
        #create new destination and update counter
        new_destination = ZBDevice()

        if packet.haslayer(Dot15d4Data):
            new_destination.pan_id = copy.deepcopy(packet.getlayer(Dot15d4Data).dest_panid)

        new_destination.short_address = copy.deepcopy(packet.dest_addr)
        #update the counters
        
        new_destination = self.update_counter(new_destination,packet)

        new_device.destinations.append(new_destination)

        known_devices.append(new_device)
        source_choices.append(str(len(source_choices))+" ("+str(new_device.short_address)+")")
        return 

    def update_counter(self,device,packet):

        if packet.haslayer(ZigbeeNWK):
            device.zb_nwk_seqnumber = copy.deepcopy(packet.getlayer(ZigbeeNWK).seqnum)
        if packet.haslayer(ZigbeeSecurityHeader):
            device.frame_counter = copy.deepcopy(packet.getlayer(ZigbeeSecurityHeader).fc)
            
            if str(packet.getlayer(ZigbeeSecurityHeader).source) is not 'None':
                dec_payload = scapy.killerbee.kbdecrypt(packet, active_networkkey,1)
                if dec_payload.haslayer(ZigbeeAppDataPayload):

                    #check for ACK -> no update
                    if dec_payload.aps_frametype == 2L:
                        return device

                    print "Source " + str(packet.src_addr)
                    print "Counter " +str(dec_payload.getlayer(ZigbeeAppDataPayload).counter)
                    device.zb_zadp_counter = copy.deepcopy(dec_payload.getlayer(ZigbeeAppDataPayload).counter)
                    if dec_payload.cluster==1280:
                        print "Motion trans seq " +str(int(dec_payload.load[1].encode('hex'),16))
                        device.zb_zcl_trans_seq = copy.deepcopy(int(dec_payload.load[1].encode('hex'),16))
                    elif dec_payload.haslayer(ZigbeeDeviceProfile):
                        print "ZDP Seqnumber"+str(dec_payload.sequence_number)
                        device.zb_zcl_trans_seq = copy.deepcopy(dec_payload.sequence_number)
                    else:
                        if dec_payload.haslayer(ZigbeeClusterLibrary):
                            print "trans seq " +str(dec_payload.getlayer(ZigbeeClusterLibrary).transaction_sequence)
                            device.zb_zcl_trans_seq = copy.deepcopy(dec_payload.getlayer(ZigbeeClusterLibrary).transaction_sequence)

        return device

    def extract_networkkey(self, packet):
        global known_devices
        global network_keys
        global zb_defaultkey

        #check if source device is known and get the extended source
        #otherwise the decryption is not possible

        for dev in known_devices:
            if dev.short_address == packet.src_addr:
                if dev.ext_address is not None:
                    packet.getlayer(scapy.layers.zigbee.ZigbeeSecurityHeader).source = dev.ext_address
                else:
                    print "No extended address for device with source "+str(dev.short_address)+" registered -> No decryption of networkkey possible"
                    return False
                break

        #calculate the key for the networkkey encrayption. key transport key
        key = zigbee_transkey.calc_transkey(zb_defaultkey)

        decrypted = scapy.killerbee.kbdecrypt(packet,key,5)

        #workaround
        #the key transport packet is missing in the zigbee layer of scapy -> should be integrated
        networkkey = decrypted.do_build().encode('hex')[4:36].decode('hex')
        
        print ""
        print ""
        print ""
        print "####################################"
        print "" 
        print "NEW NETWORKKEY DETECTED: "+networkkey.encode('hex')
        print ""
        print ""+networkkey.encode('hex')
        print ""
        print "####################################"
        if networkkey not in network_keys:
            network_keys.append(networkkey)

        return True

    def is_beacon_request(self, packet):

        global beacon_dot15d4_seqnum

        if packet.haslayer(Dot15d4Cmd):
            if packet.cmd_id == 7:
                #packet is beacon req. send own beacon as answer

                dot15d4 = Dot15d4FCS() / Dot15d4Beacon()

                #Fill Dot15d4FCS
                dot15d4.fcf_reserved_1 = 0L
                dot15d4.fcf_panidcompress = 0L
                dot15d4.fcf_ackreq= 0L
                dot15d4.fcf_pending = 0L
                dot15d4.fcf_security = 0L
                dot15d4.fcf_frametype = 0L
                dot15d4.fcf_srcaddrmode = 2L 
                dot15d4.fcf_framever=0L
                dot15d4.fcf_destaddrmode = 0L 
                dot15d4.fcf_reserved_2 = 0L
                
                dot15d4.seqnum = beacon_dot15d4_seqnum
                beacon_dot15d4_seqnum = beacon_dot15d4_seqnum + 1

                dot15d4.src_panid = 4291 
                dot15d4.src_addr = 0 
                dot15d4.aux_sec_header  = None 
                dot15d4.sf_sforder = 15L
                dot15d4.sf_beaconorder = 15L
                dot15d4.sf_assocpermit = 1L
                dot15d4.sf_pancoord = 1L
                dot15d4.sf_reserved = 0L
                dot15d4.sf_battlifeextend = 0L
                dot15d4.sf_finalcapslot = 15L
                dot15d4.gts_spec_permit = 0L
                dot15d4.gts_spec_reserved = 0L
                dot15d4.gts_spec_desccount  = 0L
                dot15d4.gts_dir_reserved = None
                dot15d4.gts_dir_mask = None
                dot15d4.pa_num_short = 0L
                dot15d4.pa_reserved_1 = 0L
                dot15d4.pa_num_long = 0L
                dot15d4.pa_reserved_2 = 0L

                zb_beacon = ZigBeeBeacon()

                proto_id = 0
                nwkc_protocol_version  = 2L
                stack_profile = 2L
                end_device_capacity  = 1L
                device_depth = 0L
                router_capacity  = 1L
                reserved  = 0L
                extended_pan_id = 9103511905611026439
                tx_offset = 16777215L
                update_id = 0

                new_beacon = dot15d4 / zb_beacon
                print "Beacon sent"
                time.sleep(0.05)
                send(new_beacon)
                return True

        return False

    def is_data_request(self, packet):

        global scheduled_cmd
        global known_devices
        global send_packet
        global acknowledged

        if packet.haslayer(Dot15d4Cmd):
            print "CMD detected"

            for device in known_devices:
                if packet.src_addr == device.short_address:
                    device.dot15d4_seqnumber = packet.seqnum


            #PAcket is data request
            if packet.getlayer(Dot15d4Cmd).cmd_id == 4:

                #search for target device and check if a packet is available

                for device in known_devices:
                    if device.short_address == packet.dest_addr:

                        #targeted device found now search if a packet is available for this destination
                        for destination in device.destinations:
                            if destination.short_address == packet.src_addr:
                                #device found now check for packet
                                if packet.seqnum in acknowledged:
                                    #already acknowledged
                                    return
                                if destination.scheduled_packet:
                                    #packet available
                                    #send ack with FP flag set and send scheduled packet
                                    ack = Dot15d4FCS()

                                    #Fill Dot15d4FCS
                                    ack.fcf_reserved_1 = 0L
                                    ack.fcf_panidcompress = 0L
                                    ack.fcf_ackreq= 0L
                                    ack.fcf_pending = 1L
                                    ack.fcf_security = 0L
                                    ack.fcf_frametype = 2L
                                    ack.fcf_srcaddrmode = 0L 
                                    ack.fcf_framever=0L
                                    ack.fcf_destaddrmode = 0L 
                                    ack.fcf_reserved_2 = 0L
                                    ack.seqnum = packet.seqnum
                                    
                                    packets = []
                                    packets.append(ack)
                                    acknowledged.append(ack.seqnum)
                                    packets.append(destination.scheduled_packet)
                                    send(packets)
                                    send_packet = False
                                    destination.scheduled_packet = None
                                    print "ACK with FP and scheduled CMD sending"
                                else:
                                    #no packet scheduled
                                    #send ack without fp set
                                    ack = Dot15d4FCS()

                                    #Fill Dot15d4FCS
                                    ack.fcf_reserved_1 = 0L
                                    ack.fcf_panidcompress = 0L
                                    ack.fcf_ackreq= 0L
                                    ack.fcf_pending = 0L
                                    ack.fcf_security = 0L
                                    ack.fcf_frametype = 2L
                                    ack.fcf_srcaddrmode = 0L 
                                    ack.fcf_framever=0L
                                    ack.fcf_destaddrmode = 0L 
                                    ack.fcf_reserved_2 = 0L
                                    ack.seqnum = packet.seqnum
                                    send(ack)
                                    acknowledged.append(ack.seqnum)
                                    print "ACK without FP set"
                                    
                                return


    def check_for_keytransport(self,packet):
        if packet.haslayer(scapy.layers.zigbee.ZigbeeSecurityHeader) and str(packet.getlayer(scapy.layers.zigbee.ZigbeeSecurityHeader).key_type) == '2':
            print "Key transport detected"
            self.extract_networkkey(packet)
            return True
        return False

    def handle_packets(self,packet, seen):

        global known_devices
        global network_keys
        global send_packet
        global send_acks
        
        #self.relay(packet)
        #if send_packet or send_acks:
        #    self.is_data_request(packet)
        if not self.check_for_keytransport(packet):
            self.extract_infos(packet)
        #check if source device is already known
        #if packet.haslayer(Dot15d4Data):
        
            #check_for_keytransport
        
    def relay(self, packet):
        global seen_packets

        if packet in seen_packets:
            pass
        else:
            print "relayed"
            send(packet)
            seen_packets.append(packet)


class Gui:

    global source_choices
        
    window = Tk()
    #window.resizable(0, 0)
    x = DoubleVar() # special Tkinter variables. DoubleVar object wraps integers and redraws the gui on change.
    y = DoubleVar()
    unit = StringVar()
    source_value = StringVar()
    destination_value = StringVar()
    
    destination_choices = []
    source_om = None
    dest_om = None
    window.option_add("*Label.Font", "centurygothic 10 bold")
    window.option_add("*Button.Font", "centurygothic 10")
    window.option_add("*Checkbutton.Font", "centurygothic 10")
    window.option_add("*Label.foreground", "white")
    window.option_add("*Button.foreground", "black")
    window.option_add("*Checkbutton.foreground", "black")
    window.option_add("*Label.Background", "grey15")
    #Global offsets
    xoff=0
    yoff=0

    rowPadding=100 #y where to start
    rowOffset=35
    rowLabelOffset=5 #Used for labels to be centered

    #columnPading=160
    #columnOffset=340
    #columnLabelOffset=90

    #Command Block offsets
    xCommandsBlockOff=-60
    yCommandsBlockOff=65
    #Parameters offset
    xParametersBlockOff=0
    yParametersBlockOff=65
    #Device List Block offset
    xDeviceBlockOff=0
    yDeviceBlockOff=0
    def __init__(self):

        self.read_config_file('secbee.conf')

        self.stopped = [False,]

        ##self.lock = threading.Lock()
        #Das Lock-System wird benoetigt um Race-Conditions zu verhindern.
        self.unit.set(UNITS[0]) # the standard unit is centimeter


        #creation of Gui element
        self.window.title("SecBee - Tobias Zillner")  # change titel
        self.window.geometry("1185x720") # change geometry
        self.window.configure(background = 'grey15') # change background color
        
        photo = PhotoImage(file = "cognosec_logo.gif") #absolute path
        label = Label(self.window, image = photo)
        label.image = photo
        label.place(x=495+self.xoff+self.xParametersBlockOff,y=15+self.yoff)
        
        Label(self.window, text = "SecBee", font = "centurygothic 24 bold" ).place(x=370+self.xoff+self.xDeviceBlockOff,y=27+self.yoff+self.yDeviceBlockOff)
        Label(self.window, text = "Commands", font = "centurygothic 15 bold" ).place(x=125+self.xoff+self.xCommandsBlockOff,y=30+self.yoff+self.yCommandsBlockOff)
        Label(self.window, text = "Parameters", font = "centurygothic 15 bold" ).place(x=920+self.xoff+self.xParametersBlockOff,y=30+self.yoff+self.yParametersBlockOff)
        
        ##OptionMenu(self.window,self.unit, *UNITS ).grid(row= 4, column=2)

        ##Entry(self.window, textvariable = self.x).grid(row = 4,column =1)
        ##Entry(self.window, textvariable = self.y).grid(row = 5,column =1)

        ##Button(self.window, text = "Load State" , width = 10, command = self.load_state).grid(row = 4, column = 4)
        #Button(self.window, text = "List known devices",width = 15, command = self.list_devices).grid(row = 7, column = 2)
        #Button(self.window, text = "List known networkkeys",width = 20, command = self.list_keys).grid(row = 8, column = 2)


        #########--->Commands<---#########

        self.source_value.set('') #Initial Value
        self.source_om = OptionMenu(self.window, self.source_value, '')
        self.source_om.config(width = 14)
        self.source_om.place(x=180+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*0)+self.yoff+self.yCommandsBlockOff)
        Label(self.window, text="Source").place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*0)+self.rowLabelOffset+self.yoff+self.yCommandsBlockOff)

        self.destination_value.set('') #Initial Value
        self.dest_om = OptionMenu(self.window, self.destination_value, '')
        self.dest_om.config(width = 14)
        self.dest_om.place(x=180+self.xoff+self.xCommandsBlockOff, y=(self.rowPadding+self.rowOffset*1)+self.rowLabelOffset+self.yoff+self.yCommandsBlockOff)
        Label(self.window, text="Destiantion").place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*1)+self.rowLabelOffset+self.yoff+self.yCommandsBlockOff)

        Label(self.window, text = "Lock Control").place(x=130+self.xoff+self.xCommandsBlockOff,y=2+(self.rowPadding+self.rowOffset*2)+self.yoff+self.yCommandsBlockOff)
        Button(self.window,  text = "Unlock Lock", width = 22, command = self.unlock_lock).place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*3)+self.yoff+self.yCommandsBlockOff)
        Button(self.window, text = "Lock Lock", width = 22, command = self.lock_lock).place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*4)+self.yoff+self.yCommandsBlockOff)
        Label(self.window, text = "Motion Control").place(x=130+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*5)+self.yoff+self.yCommandsBlockOff)
        Button(self.window, text = "Send Motion", width = 22, command = lambda: self.send_motion('motion')).place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*6)+self.yoff+self.yCommandsBlockOff)
        Button(self.window, text = "Send No Motion", width = 22, command = lambda: self.send_motion('nomotion')).place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*7)+self.yoff+self.yCommandsBlockOff)
        Label(self.window, text = "Light Control").place(x=130+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*8)+self.yoff+self.yCommandsBlockOff)
        Button(self.window, text = "Send On", width = 22, command = lambda: self.send_on_off('On')).place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*9)+self.yoff+self.yCommandsBlockOff)
        Button(self.window, text = "Send Off", width = 22, command = lambda: self.send_on_off('Off')).place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*10)+self.yoff+self.yCommandsBlockOff)
        Label(self.window, text = "Information Gathering").place(x=95+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*11)+self.yoff+self.yCommandsBlockOff)
        Button(self.window, text = "Active Endpoint Request", width = 22, command = self.send_active_endpoint_request).place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*12)+self.yoff+self.yCommandsBlockOff)
        Button(self.window, text = "Data Request", width = 22, command = self.send_data_request).place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*13)+self.yoff+self.yCommandsBlockOff)
        Button(self.window, text = "Dummy5", width = 10, command = self.send_data_request).place(x=70+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*14)+self.yoff+self.yCommandsBlockOff)
        Button(self.window, text = "Dummy6", width = 9, command = self.send_data_request).place(x=200+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*14)+self.yoff+self.yCommandsBlockOff)

        self.source_value.trace('w',self.destination_updater)

        #########--->Parameters<---#########
        
        Label(self.window, text="Frame counter offset", width = 30).place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*0)+self.yoff+self.yParametersBlockOff)
        Label(self.window, text="zb_nwk_seqnumber offset", width = 30).place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*2)+self.yoff+self.yParametersBlockOff)
        Label(self.window, text="dot15d4_seqnumber offset", width = 30).place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*4)+self.yoff+self.yParametersBlockOff)
        Label(self.window, text="zb_zadp_counter offset", width = 30).place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*6)+self.yoff+self.yParametersBlockOff)
        Label(self.window, text="zb_zcl_trans_seq offset", width = 30).place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*8)+self.yoff+self.yParametersBlockOff)

        self.frame_counter_absolute = IntVar()
        Checkbutton(self.window, text="Absolute value", variable=self.frame_counter_absolute).place(x=1030+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*1)+self.yoff+self.yParametersBlockOff+2)
        self.zb_nwk_absolute = IntVar()
        Checkbutton(self.window, text="Absolute value", variable=self.zb_nwk_absolute).place(x=1030+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*3)+self.yoff+self.yParametersBlockOff+2)
        self.dot15d4_absolute = IntVar()
        Checkbutton(self.window, text="Absolute value", variable=self.dot15d4_absolute).place(x=1030+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*5)+self.yoff+self.yParametersBlockOff+2)
        self.zb_zadp_absolute = IntVar()
        Checkbutton(self.window, text="Absolute value", variable=self.zb_zadp_absolute).place(x=1030+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*7)+self.yoff+self.yParametersBlockOff+2)
        self.zb_zcl_absolute = IntVar()
        Checkbutton(self.window, text="Absolute value", variable=self.zb_zcl_absolute).place(x=1030+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*9)+self.yoff+self.yParametersBlockOff+2)
#.grid(row=13, column = 8, sticky=W)
        default = IntVar()
        default.set(0)
        self.frame_counter = Spinbox(self.window, from_=self.framecounter_from, to=self.framecounter_to, textvariable = default)
        self.zb_nwk_seqnumber = Spinbox(self.window, from_=0, to=255)
        self.dot15d4_seqnumber = Spinbox(self.window, from_=0, to=255)
        self.zb_zadp_counter = Spinbox(self.window, from_=0, to=255)
        self.zb_zcl_trans_seq = Spinbox(self.window, from_=0, to=255)

        self.frame_counter.place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*1)+self.yoff+self.yParametersBlockOff)
        self.zb_nwk_seqnumber.place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*3)+self.yoff+self.yParametersBlockOff)
        self.dot15d4_seqnumber.place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*5)+self.yoff+self.yParametersBlockOff)
        self.zb_zadp_counter.place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*7)+self.yoff+self.yParametersBlockOff)
        self.zb_zcl_trans_seq.place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*9)+self.yoff+self.yParametersBlockOff)

        Label(self.window, text="Data Control").place(x=935+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*10)+self.yoff+self.yParametersBlockOff)
        Button(self.window,  text = "Start sniffing", width = 14, command = self.start_sniffing).place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*11)+self.yoff+self.yParametersBlockOff)
        Button(self.window, text = "Stop sniffing", width = 14, command = self.stop_sniffing).place(x=1013+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*11)+self.yoff+self.yParametersBlockOff)
        Button(self.window, text = "Send ACKs", width = 14, command = self.send_acks).place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*12)+self.yoff+self.yParametersBlockOff)
        Button(self.window, text = "Stop ACKs", width = 14, command = self.stop_acks).place(x=1013+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*12)+self.yoff+self.yParametersBlockOff)
        Button(self.window, text = "Dummy1", width = 14, command = self.send_acks).place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*13)+self.yoff+self.yParametersBlockOff)
        Button(self.window, text = "Dummy2", width = 14, command = self.stop_acks).place(x=1013+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*13)+self.yoff+self.yParametersBlockOff)
        Button(self.window, text = "Dummy3", width = 14, command = self.send_acks).place(x=840+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*14)+self.yoff+self.yParametersBlockOff)
        Button(self.window, text = "Dummy4", width = 14, command = self.stop_acks).place(x=1013+self.xoff+self.xParametersBlockOff,y=(self.rowPadding+self.rowOffset*14)+self.yoff+self.yParametersBlockOff)

        #########--->Devices List<---#########

        Label(self.window, text="Sources", width = 19).place(x=275+self.xoff+self.xDeviceBlockOff,y=(self.rowPadding+self.rowOffset*11)+self.yoff+self.yDeviceBlockOff)
        Label(self.window, text="Source Details", width = 25).place(x=430+self.xoff+self.xDeviceBlockOff,y=(self.rowPadding+self.rowOffset*11)+self.yoff+self.yDeviceBlockOff)
        Label(self.window, text="Destination Details", width = 19).place(x=635+self.xoff+self.xDeviceBlockOff,y=(self.rowPadding+self.rowOffset*11)+self.yoff+self.yDeviceBlockOff)
        self.listbox = Listbox(self.window, selectmode=SINGLE, width = 25)
        self.listbox.place(x=280+self.xoff+self.xDeviceBlockOff,y=(self.rowPadding+self.rowOffset*12)+self.yoff+self.yDeviceBlockOff)
        self.listbox.bind('<<ListboxSelect>>', self.listbox_trace)
        self.detailbox = Listbox(self.window, selectmode=SINGLE, width = 25)
        self.detailbox.place(x=456+self.xoff+self.xDeviceBlockOff,y=(self.rowPadding+self.rowOffset*12)+self.yoff+self.yDeviceBlockOff)
        self.detailbox.bind('<<ListboxSelect>>', self.detailbox_trace)
        self.destinationbox = Listbox(self.window, selectmode=SINGLE, width = 25)
        self.destinationbox.place(x=632+self.xoff+self.xDeviceBlockOff,y=(self.rowPadding+self.rowOffset*12)+self.yoff+self.yDeviceBlockOff)
        #configure text area
        scrollbar = Scrollbar(self.window)
        scrollbar.place(x=280+self.xoff+self.xDeviceBlockOff,y=(self.rowPadding+self.rowOffset*0)+self.yoff+self.yDeviceBlockOff)

        self.T = Text(self.window, wrap=WORD, yscrollcommand=scrollbar.set, width =75)
        ##self.T.grid(column=12, row=1,columnspan=4, rowspan=4)
        self.T.place(x=280+self.xoff+self.xDeviceBlockOff,y=(self.rowPadding+self.rowOffset*0)+self.yoff+self.yDeviceBlockOff)
        scrollbar.config(command=self.T.yview)

        #create filemenu
        menu = Menu(self.window)
        self.window.config(menu=menu)
        filemenu = Menu(menu)
        formatmenu = Menu(menu)
        listmenu = Menu(menu)
        menu.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="Load Default State", command=self.load_state)
        filemenu.add_command(label="Save Default State", command=self.save_state)
        filemenu.add_command(label="Save State as", command=self.save_state_as)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.destroy)
        #create formatmenu
        menu.add_cascade(label="Format", menu=formatmenu)
        formatmenu.add_command(label="Clear Text", command=self.clear_text)
        menu.add_cascade(label="List", menu=listmenu)
        listmenu.add_command(label="List known devices", command=self.list_devices)
        listmenu.add_command(label="List known networkkeys", command=self.list_keys)


        ##Button(self.window, text = "Clear text", width = 20, command = self.clear_text).grid(row = 8, column = 2)


        self.window.protocol("WM_DELETE_WINDOW", self.destroy)
        self.window.mainloop()


    def send_data_request(self):

        global known_devices

        source = known_devices[int(self.source_value.get().split(" ")[0])]
        destination = known_devices [int(self.source_value.get().split(" ")[0])].destinations[int(self.destination_value.get().split(" ")[0])]

        dot15d4 = Dot15d4FCS() / Dot15d4Cmd()

        #Fill Dot15d4FCS
        dot15d4.fcf_reserved_1 = 0L
        dot15d4.fcf_panidcompress = 1L
        dot15d4.fcf_ackreq= 1L
        dot15d4.fcf_pending = 0L
        dot15d4.fcf_security = 0L
        dot15d4.fcf_frametype = 3L
        dot15d4.fcf_srcaddrmode = 2L 
        dot15d4.fcf_framever=0L
        dot15d4.fcf_destaddrmode = 2L 
        dot15d4.fcf_reserved_2 = 0L
        new_dot15d4_seqnum = (source.dot15d4_seqnumber + int(self.dot15d4_seqnumber.get()))%255
        if new_dot15d4_seqnum == 0:
            new_dot15d4_seqnum = 1
        dot15d4.seqnum = new_dot15d4_seqnum

        #Fill Dot15d4Data
        dot15d4.dest_panid = destination.pan_id
        dot15d4.dest_addr = destination.short_address
        dot15d4.src_panid = None
        dot15d4.src_addr = source.short_address
        dot15d4.aux_sec_header = None
        dot15d4.cmd_id = 4
        print "data request sent with seq sequence_number "+str(new_dot15d4_seqnum)+" and cmd "+str(dot15d4.cmd_id) 
        print str(dot15d4.do_build().encode('hex'))
        send(dot15d4)
        return True

    def send_active_endpoint_request(self):
        #select device
        global known_devices
        global network_keys
        global active_networkkey

        source = known_devices[int(self.source_value.get())]
        destination = known_devices [int(self.source_value.get())].destinations[int(self.destination_value.get())]

        #create packet
        packet = self.create_dot15d4_packet(source, destination)

        zbnwk = ZigbeeNWK()

        zbnwk.discover_route = 0L 
        zbnwk.proto_version = 2L
        zbnwk.frametype = 0L
        zbnwk.flags  =  2L
        zbnwk.destination   = destination.short_address
        zbnwk.source = source.short_address
        zbnwk.radius = 30
        new_zbnwk_seqnum = (destination.zb_nwk_seqnumber + int(self.zb_nwk_seqnumber.get()))%255
        if new_zbnwk_seqnum == 0:
            new_zbnwk_seqnum = 1
        zbnwk.seqnum = new_zbnwk_seqnum
        zbnwk.relay_count  = None
        zbnwk.relay_index  = None
        zbnwk.relays  = None
        zbnwk.ext_dst  = None
        zbnwk.ext_src  = None

        #create ZigBeeSecurityHeader
        zbsec = ZigbeeSecurityHeader()

        zbsec.reserved1 = 0L
        zbsec.extended_nonce = 1L 
        zbsec.key_type = 1L
        zbsec.nwk_seclevel = 0L 
        zbsec.fc = destination.frame_counter + int(self.frame_counter.get())
        zbsec.source = source.ext_address
        zbsec.key_seqnum = 0
        zbsec.mic = ''

        #crate ZigbeeAppdataPayload
        zbappdata = ZigbeeAppDataPayload()

        zbappdata.frame_control = 4L
        zbappdata.delivery_mode = 0L
        zbappdata.aps_frametype = 0L
        zbappdata.dst_endpoint = 0
        zbappdata.cluster = 5
        zbappdata.profile = 0
        zbappdata.src_endpoint = 0
        zbappdata.counter = (destination.zb_zadp_counter + int(self.zb_zadp_counter.get()))%255

        if zbappdata.counter == 0:
            zbappdata.counter = 1

        #create ZigbeeDeviceProfile
        zdp = ZigbeeDeviceProfile()
        zdp.sequence_number = (destination.zb_zcl_trans_seq + int(self.zb_zcl_trans_seq.get()))%255
        if zdp.sequence_number == 0:
            zdp.sequence_number = 1
        zdp.device = destination.short_address

        #encrypt and build the packet
        packet = packet / zbnwk / zbsec 
        dec_payload =  zbappdata / zdp
        print "Packet"
        print str(packet.do_build()).encode('hex')
        print "dec payload"
        print str(dec_payload.do_build()).encode('hex')

        #send packet
        encpacket = scapy.killerbee.kbencrypt(packet,dec_payload, active_networkkey, 5)
        print "encpacket"
        print str(encpacket.do_build()).encode('hex')
        send(encpacket)

        return True

    def unlock_lock(self):
         #select device
        global known_devices
        global network_keys
        global active_networkkey
        global scheduled_cmd
        global send_packet

        source = known_devices[int(self.source_value.get().split(" ")[0])]
        destination = known_devices [int(self.source_value.get().split(" ")[0])].destinations[int(self.destination_value.get().split(" ")[0])]

        #create packet
        packet = self.create_dot15d4_packet(source, destination)

        packet = self.add_zb_nwk_layer(packet, source, destination)

        #create ZigBeeSecurityHeader
        zbsec = ZigbeeSecurityHeader()

        zbsec.reserved1 = 0L
        zbsec.extended_nonce = 1L 
        zbsec.key_type = 1L
        zbsec.nwk_seclevel = 0L 
        zbsec.fc = destination.frame_counter + int(self.frame_counter.get())
        zbsec.source = source.ext_address
        zbsec.key_seqnum = 0
        zbsec.mic = ''

        #crate ZigbeeAppdataPayload
        zbappdata = ZigbeeAppDataPayload()

        zbappdata.frame_control = 0L
        zbappdata.delivery_mode = 0L
        zbappdata.aps_frametype = 0L
        zbappdata.dst_endpoint = 1
        zbappdata.cluster = 257
        zbappdata.profile = 260
        zbappdata.src_endpoint = 1
        zbappdata.counter = destination.zb_zadp_counter + int(self.zb_zadp_counter.get())

        #create ZigbeeClusterLibrary
        zbclusterlib = ZigbeeClusterLibrary()
        
        zbclusterlib.reserved = 0L
        zbclusterlib.disable_default_response = 0L
        zbclusterlib.direction = 0L
        zbclusterlib.manufacturer_specific = 0L
        zbclusterlib.zcl_frametype = 1L
        zbclusterlib.manufacturer_code = None

        #seqeunce number
        zbclusterlib.transaction_sequence = destination.zb_zcl_trans_seq + int(self.zb_zcl_trans_seq.get())

        #the actual command
        zbclusterlib.command_identifier = 1

        #encrypt and build the packet
        packet = packet / zbsec 
        dec_payload =  zbappdata / zbclusterlib
        print "Packet"
        print str(packet.do_build()).encode('hex')
        print "dec payload"
        print str(dec_payload.do_build()).encode('hex')
        print "active network"
        #send packet
        encpacket = scapy.killerbee.kbencrypt(packet,dec_payload, active_networkkey, 5)
        print "encpacket"
        print str(encpacket.do_build()).encode('hex')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.connect(("192.168.1.10",40000))

        sock.send('x'+chr(len(encpacket))+encpacket.do_build())
       
        sock.close()
        
        #send(encpacket)

        return True

    def request_key(self):
        #select device
        global known_devices
        global network_keys
        global active_networkkey
        global scheduled_cmd
        global send_packet

        source = known_devices[int(self.source_value.get().split(" ")[0])]
        destination = known_devices [int(self.source_value.get().split(" ")[0])].destinations[int(self.destination_value.get().split(" ")[0])]

        #create packet
        packet = self.create_dot15d4_packet(source, destination)

        packet = self.add_zb_nwk_layer(packet, source, destination)

        #create ZigBeeSecurityHeader
        zbsec = ZigbeeSecurityHeader()

        zbsec.reserved1 = 0L
        zbsec.extended_nonce = 1L 
        zbsec.key_type = 1L
        zbsec.nwk_seclevel = 0L 
        zbsec.fc = destination.frame_counter + int(self.frame_counter.get())
        zbsec.source = source.ext_address
        zbsec.key_seqnum = 0
        zbsec.mic = ''

        #crate ZigbeeAppdataPayload
        zbappdata = ZigbeeAppDataPayload()

        zbappdata.frame_control = 0L
        zbappdata.delivery_mode = 1L
        zbappdata.aps_frametype = 1L
        zbappdata.dst_endpoint = None
        zbappdata.cluster = None
        zbappdata.profile = None
        zbappdata.src_endpoint = None
        zbappdata.counter = destination.zb_zadp_counter + int(self.zb_zadp_counter.get())


        #encrypt and build the packet
        packet = packet / zbsec 
        dec_payload =  zbappdata / '0802'.decode('hex')
        print "Packet"
        print str(packet.do_build()).encode('hex')
        print "dec payload"
        print str(dec_payload.do_build()).encode('hex')
        print "active network"
        #send packet
        encpacket = scapy.killerbee.kbencrypt(packet,dec_payload, active_networkkey, 5)
        print "encpacket"
        print str(encpacket.do_build()).encode('hex')

        send(packet / dec_payload)

        return True


    def lock_lock(self):
        #select device
        global known_devices
        global network_keys
        global active_networkkey
        global scheduled_cmd
        global send_packet

        source = known_devices[int(self.source_value.get().split(" ")[0])]
        destination = known_devices [int(self.source_value.get().split(" ")[0])].destinations[int(self.destination_value.get().split(" ")[0])]

        #create packet
        packet = self.create_dot15d4_packet(source, destination)

        packet = self.add_zb_nwk_layer(packet, source, destination)

        #create ZigBeeSecurityHeader
        zbsec = ZigbeeSecurityHeader()

        zbsec.reserved1 = 0L
        zbsec.extended_nonce = 1L 
        zbsec.key_type = 1L
        zbsec.nwk_seclevel = 0L 
        zbsec.fc = destination.frame_counter + int(self.frame_counter.get())
        zbsec.source = source.ext_address
        zbsec.key_seqnum = 0
        zbsec.mic = ''

        #crate ZigbeeAppdataPayload
        zbappdata = ZigbeeAppDataPayload()

        zbappdata.frame_control = 0L
        zbappdata.delivery_mode = 0L
        zbappdata.aps_frametype = 0L
        zbappdata.dst_endpoint = 1
        zbappdata.cluster = 257
        zbappdata.profile = 260
        zbappdata.src_endpoint = 1
        zbappdata.counter = destination.zb_zadp_counter + int(self.zb_zadp_counter.get())

        #create ZigbeeClusterLibrary
        zbclusterlib = ZigbeeClusterLibrary()
        
        zbclusterlib.reserved = 0L
        zbclusterlib.disable_default_response = 0L
        zbclusterlib.direction = 0L
        zbclusterlib.manufacturer_specific = 0L
        zbclusterlib.zcl_frametype = 1L
        zbclusterlib.manufacturer_code = None

        #seqeunce number
        zbclusterlib.transaction_sequence = destination.zb_zcl_trans_seq + int(self.zb_zcl_trans_seq.get())

        #the actual command
        zbclusterlib.command_identifier = 0

        #encrypt and build the packet
        packet = packet / zbsec 
        dec_payload =  zbappdata / zbclusterlib
        print "Packet"
        print str(packet.do_build()).encode('hex')
        print "dec payload"
        print str(dec_payload.do_build()).encode('hex')
        print "active network"
        #send packet
        encpacket = scapy.killerbee.kbencrypt(packet,dec_payload, active_networkkey, 5)
        print "encpacket"
        print str(encpacket.do_build()).encode('hex')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.connect(("192.168.1.100",40000))

        sock.send('x'+chr(len(encpacket))+encpacket.do_build())
        
        sock.close()
        
        

        return True

    def send_motion(self, cmd):


        #select device
        global known_devices
        global network_keys
        global active_networkkey

        source = known_devices[int(self.source_value.get())]
        destination = known_devices [int(self.source_value.get())].destinations[int(self.destination_value.get())]


        #create packet
        packet = self.create_dot15d4_packet(source, destination)

        zbnwk = ZigbeeNWK()

        zbnwk.discover_route = 0L 
        zbnwk.proto_version = 2L
        zbnwk.frametype = 0L
        zbnwk.flags  =  2L
        zbnwk.destination   = destination.short_address
        zbnwk.source = source.short_address
        zbnwk.radius = 30
        new_zbnwk_seqnum = (destination.zb_nwk_seqnumber + int(self.zb_nwk_seqnumber.get()))%255
        if new_zbnwk_seqnum == 0:
            new_zbnwk_seqnum = 1
        zbnwk.seqnum = new_zbnwk_seqnum
        zbnwk.relay_count  = None
        zbnwk.relay_index  = None
        zbnwk.relays  = None
        zbnwk.ext_dst  = None
        zbnwk.ext_src  = None

        packet = packet / zbnwk

        #create ZigBeeSecurityHeader
        zbsec = ZigbeeSecurityHeader()

        zbsec.reserved1 = 0L
        zbsec.extended_nonce = 1L 
        zbsec.key_type = 1L
        zbsec.nwk_seclevel = 0L 
        zbsec.fc = destination.frame_counter + int(self.frame_counter.get())
        zbsec.source = source.ext_address
        zbsec.key_seqnum = 0
        zbsec.mic = ''

        #crate ZigbeeAppdataPayload
        zbappdata = ZigbeeAppDataPayload()

        zbappdata.frame_control = 0L
        zbappdata.delivery_mode = 0L
        zbappdata.aps_frametype = 0L
        zbappdata.dst_endpoint = 1
        zbappdata.cluster = 1280
        zbappdata.profile = 260
        zbappdata.src_endpoint = 1
        zbappdata.counter = (destination.zb_zadp_counter + int(self.zb_zadp_counter.get()))%255
        if zbappdata.counter == 0:
            zbappdata.counter = 1

        #create ZigbeeClusterLibrary
        zbclusterlib = ZigbeeClusterLibrary()
        
        zbclusterlib.reserved = 0L
        zbclusterlib.disable_default_response = 1L
        zbclusterlib.direction = 1L
        zbclusterlib.manufacturer_specific = 0L
        zbclusterlib.zcl_frametype = 1L
        zbclusterlib.manufacturer_code = None

        new_transaction_seq = (destination.zb_zcl_trans_seq + int(self.zb_zcl_trans_seq.get()))%255

        if new_transaction_seq  == 0:
            new_transaction_seq = 1

        zbclusterlib.transaction_sequence = new_transaction_seq
        zbclusterlib.command_identifier = 0

        raw = Raw()

        #actual command for smartthings motion sensor
        if cmd == 'motion':
            raw.load ='310000'.decode('hex')
        elif cmd == 'nomotion':
            raw.load = '300000'.decode('hex')
        else:
            print 'Unknown motion command'
            return False

        #encrypt and build the packet
        packet = packet / zbsec 
        dec_payload =  zbappdata / zbclusterlib / raw
        print "Packet"
        print str(packet.do_build()).encode('hex')
        print "dec payload"
        print str(dec_payload.do_build()).encode('hex')

        #send packet
        encpacket = scapy.killerbee.kbencrypt(packet,dec_payload, active_networkkey, 5)
        print "encpacket"
        print str(encpacket.do_build()).encode('hex')
        send(encpacket)

        return True

    def send_on_off(self,cmd):

        #select device
        global known_devices
        global network_keys
        global active_networkkey

        source = known_devices[int(self.source_value.get())]
        destination = known_devices [int(self.source_value.get())].destinations[int(self.destination_value.get())]


        #create packet
        packet = self.create_dot15d4_packet(source, destination)
        packet= self.add_zb_nwk_layer(packet,source,destination)

        #create ZigBeeSecurityHeader
        zbsec = ZigbeeSecurityHeader()

        zbsec.reserved1 = 0L
        zbsec.extended_nonce = 1L 
        zbsec.key_type = 1L
        zbsec.nwk_seclevel = 0L 
        zbsec.fc = destination.frame_counter + int(self.frame_counter.get())
        zbsec.source = source.ext_address
        zbsec.key_seqnum = 0
        zbsec.mic = ''

        #crate ZigbeeAppdataPayload
        zbappdata = ZigbeeAppDataPayload()

        zbappdata.frame_control = 0L
        zbappdata.delivery_mode = 0L
        zbappdata.aps_frametype = 0L
        zbappdata.dst_endpoint = 11
        zbappdata.cluster = 6
        zbappdata.profile = 260
        zbappdata.src_endpoint = 1
        zbappdata.counter = (destination.zb_zadp_counter + int(self.zb_zadp_counter.get()))%255
        if zbappdata.counter == 0:
            zbappdata.counter = 1

        #create ZigbeeClusterLibrary
        zbclusterlib = ZigbeeClusterLibrary()
        
        zbclusterlib.reserved = 0L
        zbclusterlib.disable_default_response = 0L
        zbclusterlib.direction = 0L
        zbclusterlib.manufacturer_specific = 0L
        zbclusterlib.zcl_frametype = 1L
        zbclusterlib.manufacturer_code = None
        zbclusterlib.transaction_sequence = (destination.zb_zcl_trans_seq + int(self.zb_zcl_trans_seq.get()))%255
        if zbclusterlib.transaction_sequence == 0:
            zbclusterlib.transaction_sequence = 1

        if cmd == 'On':
            zbclusterlib.command_identifier =1
        elif cmd == 'Off':
            zbclusterlib.command_identifier=0
        else:
            print "Unknown On/Off command"
            return false

        #encrypt and build the packet
        packet = packet / zbsec 
        dec_payload =  zbappdata / zbclusterlib
        print "Packet"
        print str(packet.do_build()).encode('hex')
        print "dec payload"
        print str(dec_payload.do_build()).encode('hex')

        #send packet
        encpacket = scapy.killerbee.kbencrypt(packet,dec_payload, active_networkkey, 5)
        print "encpacket"
        print str(encpacket.do_build()).encode('hex')
        send(encpacket)

        return True

    def create_dot15d4_packet(self, source, destination):
        dot15d4 = Dot15d4FCS() / Dot15d4Data()

        #Fill Dot15d4FCS
        dot15d4.fcf_reserved_1 = 0L
        dot15d4.fcf_panidcompress = 1L
        dot15d4.fcf_ackreq= 1L
        dot15d4.fcf_pending = 0L
        dot15d4.fcf_security = 0L
        dot15d4.fcf_frametype = 1L
        dot15d4.fcf_srcaddrmode = 2L 
        dot15d4.fcf_framever=0L
        dot15d4.fcf_destaddrmode = 2L 
        dot15d4.fcf_reserved_2 = 0L
        new_dot15d4_seqnum = (source.dot15d4_seqnumber + int(self.dot15d4_seqnumber.get()))%255
        if new_dot15d4_seqnum == 0:
            new_dot15d4_seqnum = 1
        dot15d4.seqnum = new_dot15d4_seqnum

        #Fill Dot15d4Data
        dot15d4.dest_panid = destination.pan_id
        dot15d4.dest_addr = destination.short_address
        dot15d4.src_panid = None
        dot15d4.src_addr = source.short_address
        dot15d4.aux_sec_header = None

        return dot15d4

    def add_zb_nwk_layer(self, packet, source, destination):

        zbnwk = ZigbeeNWK()

        zbnwk.discover_route = 1L 
        zbnwk.proto_version = 2L
        zbnwk.frametype = 0L
        zbnwk.flags  =  2L
        zbnwk.destination   = destination.short_address
        zbnwk.source = source.short_address
        zbnwk.radius = 30
        new_zbnwk_seqnum = (destination.zb_nwk_seqnumber + int(self.zb_nwk_seqnumber.get()))%255
        if new_zbnwk_seqnum == 0:
            new_zbnwk_seqnum = 1
        zbnwk.seqnum = new_zbnwk_seqnum
        zbnwk.relay_count  = None
        zbnwk.relay_index  = None
        zbnwk.relays  = None
        zbnwk.ext_dst  = None
        zbnwk.ext_src  = None

        return packet / zbnwk

    def clear_text(self):
        self.T.delete(1.0,END)
        return

    def list_devices(self):
        global known_devices
        i = 0

        self.T.insert(END,"ZigBee device list:\n\n")
        self.listbox.delete(0, END)
        
        for device in known_devices:
            self.T.insert(END, "##############\n")
            self.T.insert(END, "Device "+str(i)+"\n")
            self.listbox.insert(END, str(i) + " (" + str(device.short_address) + ")")
            device.print_device(self.T)
            device.print_destinations(self.T)
            i = i + 1
        self.T.see(END)
        return

    def list_keys(self):
        global network_keys
        i = 0

        self.T.insert(END,"ZB Key: " + zb_defaultkey +"\n")
        self.T.insert(END,"Active networkkey: " + str(active_networkkey.encode('hex')) +  "\n")
        self.T.insert(END, "Network Keys detected: \n\n")

        for key in network_keys:
            self.T.insert(END, "##############\n")
            self.T.insert(END, "Key "+str(i)+"\n")
            self.T.insert(END, str(key.encode('hex'))+"\n")
            i = i + 1
        return

    def load_state(self):
        global network_keys
        global known_devices
        global networkkeys_file
        global knowndevices_file
        global source_choices

        network_keys = pickle.load(open(networkkeys_file,"rb"))
        known_devices = pickle.load(open(knowndevices_file,"rb"))
        source_choices = list()
        i = 0
        for device in known_devices:
            source_choices.append(str(i) + " ("+str(device.short_address)+")")
            i = i + 1
        self.source_value.set('') #Initial Value
        self.source_om.destroy()
        self.source_om = OptionMenu(self.window, self.source_value, *source_choices)
        self.source_om.config(width = 14)
        self.source_om.place(x=180+self.xoff+self.xCommandsBlockOff,y=(self.rowPadding+self.rowOffset*0)+self.yoff+self.yCommandsBlockOff)
        self.list_devices()
        #dir = tkFileDialog.askdirectory(parent=window,initialdir=".",title='Choose a directory')
        #if dir != None:
        #    network_keys = pickle.load(open(dir+'/'+networkkeys_file,"rb"))
        #    known_devices = pickle.load(open(dir+'/'+knowndevices_file,"rb"))
        return

    def save_state(self):
        global network_keys
        global known_devices
        pickle.dump(network_keys,open("networkkeys.p","wb"))
        pickle.dump(known_devices,open("knowndevices.p","wb"))
        return

    def save_state_as(self):
        global network_keys
        global known_devices
        myFormats = [
            ('P file','*.p'),
        ]

        fileName = tkFileDialog.asksaveasfilename(parent=self.window,filetypes=myFormats ,title="Save the network keys as...")
        if len(fileName ) > 0:
            pickle.dump(network_keys,open(fileName,"wb"))
        fileName = tkFileDialog.asksaveasfilename(parent=self.window,filetypes=myFormats ,title="Save the known devices as...")
        if len(fileName ) > 0:
            pickle.dump(known_devices,open(fileName,"wb"))
        return
    def start_sniffing(self):
                   
        self.sniff = MyThread()
        self.sniff.start()

    def read_config_file(self, config_file_name):
        global active_networkkey
        global zb_defaultkey
        global networkkeys_file
        global knowndevices_file

        # read configuration
        config_file = open(config_file_name, 'r')
        config = ConfigParser.RawConfigParser(False)
        config.readfp(config_file)
        # general conf
        active_networkkey = config.get('keys', 'active_networkkey')
        active_networkkey = active_networkkey.decode('hex')
        zb_defaultkey = config.get('keys', 'zb_defaultkey')
        networkkeys_file = config.get('files', 'networkkeys_file')
        knowndevices_file = config.get('files', 'knowndevices_file')
        self.framecounter_from = config.get('values', 'framecounter_from')
        self.framecounter_to = config.get('values', 'framecounter_to')
        #print "Active network key" + active_networkkey.encode('hex')
        config_file.close()

    def destination_updater(self, *args):
        global network_keys
        global known_devices
        try:
            device = known_devices[int(self.source_value.get().split(" ")[0])]
        except ValueError:
            device = None
        if device:
            self.dest_om.destroy()
            self.destination_choices = []
            i = 0
            for destinations in device.destinations:
                self.destination_choices.append(str(i) + " ("+str(device.short_address)+")")
                i = i + 1
            self.destination_value.set('') #Initial Value
            if self.destination_choices:
                self.dest_om = OptionMenu(self.window, self.destination_value, *self.destination_choices)
                self.dest_om.config(width = 14)
                self.dest_om.place(x=180+self.xoff+self.xCommandsBlockOff, y=(self.rowPadding+self.rowOffset*1)+self.rowLabelOffset+self.yoff+self.yCommandsBlockOff)
            else:
                self.dest_om = OptionMenu(self.window, self.destination_value, '')
                self.dest_om.config(width = 14)
                self.dest_om.place(x=180+self.xoff+self.xCommandsBlockOff, y=(self.rowPadding+self.rowOffset*1)+self.rowLabelOffset+self.yoff+self.yCommandsBlockOff)


    def listbox_trace(self, evt):
        self.detailbox.delete(0, END)
        self.device_index = int(self.listbox.curselection()[0])
        device = known_devices[self.device_index]
        #self.detailbox.insert(END, device.short_address)
        self.detailbox.insert(END, "Short Address: " + str(device.short_address))
        self.detailbox.insert(END, "Ext Address: " + str(device.ext_address))
        self.detailbox.insert(END, "MAC Address: " + str(device.mac_address))
        self.detailbox.insert(END, "")
        self.detailbox.insert(END, "DESTINATIONS:" )
        i = 0
        for destination in device.destinations:
            self.detailbox.insert(END, "Destination " + str(i)+ " (" + str(destination.short_address) + ")")
            i = i + 1

    def detailbox_trace(self, evt):
        self.destinationbox.delete(0, END)
        w = evt.widget
        index = int(w.curselection()[0])
        value = w.get(index)
        if value.startswith("Destination"):
            destination_offset = value.split(" ")[1]
            device = known_devices[self.device_index]
            destination = device.destinations[int(destination_offset)]
            self.destinationbox.insert(END, "Short Address: " + str(destination.short_address))
            self.destinationbox.insert(END, "Ext Address: " + str(destination.ext_address))
            self.destinationbox.insert(END, "MAC Address: " + str(destination.mac_address))

    def send_acks(self):
        global send_acks

        send_acks = True

    def stop_acks(self):
        global send_acks

        send_acks = False

    def stop_sniffing(self):
        
        self.sniff._Thread__stop()
        #sleep(1000)
    
    def destroy(self):
        #self.sniff._Thread__stop()
        print "destroy"
        call(["pkill","-f","top_block.py"])
        call(["pkill","-f","SecBee.py"])
        call(["echo","test"])
        
        #sleep(1000)
        sys.exit()

    
    #gui.T.insert(END,"New packet seen")

def main():
    load_module('gnuradio')
    load_layer('zigbee')

    gui = Gui()
    print "GUI created"
    #switch_radio_protocol("Zigbee")
    print "exit"

if  __name__ =='__main__':main()




