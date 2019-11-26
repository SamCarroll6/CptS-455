#!/bin/bash

sudo mn -c
sudo mn --mac --switch ovsk --controller=remote,ip=0.0.0.0,port=6633
