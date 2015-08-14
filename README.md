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

After installing both tools please copy the files located in the Scapy folder and copy it to your local scapy directory.

#############
Hardware Requirements
#############
For the tool usage a SDR is required. Our GNU radio block is designed for the usage with USRP but can be easily modified to support other SDR as well. For the indirect data transfer feature we use Raspberry Pi with Raspbee.


#############
Execution
#############

python SecBee.py


##############
Next steps
##############
We will work on the code to make it stable and setup an installation script for all required tools.
We are also looking in implementing new commands for testing.

