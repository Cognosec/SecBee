# SecBee

SecBee is a ZigBee security testing tool developed by Cognosec. The goal is to enable developers and security testers to test ZigBee implementations for security issues.


#############
Installation
#############

SecBee is based on killerbee and scapy-radio.

Scapy-radio 
https://bitbucket.org/cybertools/scapy-radio/src

Killerbee
https://github.com/riverloopsec/killerbee

GNU Radio block
https://github.com/bastibl/gr-ieee802-15-4

After installing both tools please copy the files located in the Scapy folder and copy it to your local scapy directory.

#############
Hardware Requirements
#############
For the tool usage a SDR is required. Our GNU radio block is designed for the usage with USRP but can be easily modified to support other SDR as well. For the indirect data transfer feature we use Raspberry Pi with Raspbee.

#############
RaspBee Setup
#############
The firmware for the RaspBee is based on uracoli, the source package can be downloaded here:
http://download.savannah.nongnu.org/releases/uracoli/uracoli-src-0.4.2.zip

For compiling the firmware, you need a toolchain which can be downloaded from Atmel:
http://www.atmel.com/tools/ATMELAVRTOOLCHAINFORLINUX.aspx (avr8-gnu-toolchain-linux_x86_64)

Build (and upload,flash and reset) using the make.sh script.

#############
Execution
#############

python SecBee.py


##############
Next steps
##############
We will work on the code to make it stable and setup an installation script for all required tools.
We are also looking in implementing new commands for testing.

# FAQ / Known Issues

- To update the device list the current state has to be saved and reloaded. This is known issue and will be fixed.
