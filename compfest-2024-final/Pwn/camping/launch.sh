#!/bin/bash

/usr/bin/qemu-system-x86_64 \
    -kernel $PWD/bzImage \
    -m 256M \
    -initrd $PWD/initramfs.cpio.gz \
    -nographic \
    -monitor none \
    -no-reboot \
    -cpu kvm64,+smep \
    -append "console=ttyS0 kaslr nosmap kpti=1 quiet panic=1 oops=panic" \
    -smp 2