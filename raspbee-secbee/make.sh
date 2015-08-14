#!/bin/sh
export PATH=$PATH:/opt/avr8-gnu-toolchain-linux_x86_64/bin
make -f raspbee-secbee.mk raspbee
avr-objcopy -I ihex -O binary bin/raspbee-secbee_raspbee.hex bin/raspbee.bin
if [ "$#" -eq 1 ]; then
scp bin/raspbee.bin pi@$1:/tmp
ssh pi@$1 'sudo GCFFlasher -f /tmp/raspbee.bin && sudo GCFFlasher -r'
fi
