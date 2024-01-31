#!/bin/sh

exec 2>/dev/null
cd /home/ret2libc
timeout 60 /home/ret2libc/ret2libc
