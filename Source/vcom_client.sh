while true; do socat pty,link=/dev/vcom0,raw,echo=0,waitslave tcp:192.168.1.66:40000;done

