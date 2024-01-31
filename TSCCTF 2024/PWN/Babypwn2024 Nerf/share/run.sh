#!/bin/bash

exec 2>/dev/null
cd /home/babypwn2024-nerf
python3 -u /home/babypwn2024-nerf/pow.py
valid_hash=$?
if [ $valid_hash -eq 1 ]; then
    timeout 60 /home/babypwn2024-nerf/babypwn2024-nerf
else
    echo 'Proof of work failed! Are you a robot?'
fi
