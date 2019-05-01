#!/usr/bin/env python
# Author: Ian Simons
# Version 0.92 - Finally fixed GTK-Warnings. Fuck you GTK-Warnings. Moved all output over to subprocess.communicate()
# Licence: WTFPL - wtfpl.net
# thanks to @info_dox for python advice and @clappymonkey for general encouragement.
# thanks also to @pelicancoder for code sanity

import subprocess
import sys
import argparse
import time
import netifaces

__version__ = "0.92"

clear = "\x1b[0m"
red = "\x1b[1;31m"
green = "\x1b[1;32m"
cyan = "\x1b[1;36m"

def banner():
    print """\x1b[0;33m
     _            _                   _ _
 ___| | __ _  ___| | ____      ____ _| | |
/ __| |/ _` |/ __| |/ /\ \ /\ / / _` | | |
\__ \ | (_| | (__|   <  \ V  V / (_| | | |
|___/_|\__,_|\___|_|\_\  \_/\_/ \__,_|_|_|
A lazy bastard's firewall test, Version: %s

\x1b[0m""" %__version__

def openTCPDump():

    #grab local ip address to filter out crap in tcpdump window
    #determine default gateway (and thus adapter id)
    def_gw = netifaces.gateways()['default'][netifaces.AF_INET][1]
    #get ip address from default adapter
    address = netifaces.ifaddresses(def_gw)[2][0]['addr']

    #check for tcpdump running, if not, spawn new one
    proc = subprocess.Popen(args=['ps', '-e', '-f'], stdout=subprocess.PIPE)
    stdout_data = proc.communicate()
    #output = proc.stdout.read()
    if address in stdout_data:
        print red + "{!} TCPDump already running in terminal window" + clear
	pass
    else:
        print green + "{+} TCPDump results will appear in separate terminal window" + clear
        tcpdumpcmd = "tcpdump -i eth0 -n host %s" % address
        #print tcpdumpcmd
        pid = subprocess.Popen(args=['gnome-terminal', '--geometry=140x16+20+20', '--profile=tcpdump', '--name=TCPDUMP', '-e', tcpdumpcmd], stderr=subprocess.PIPE)
        stderr_data = pid.communicate()
    print green + "{*} Reminder: TCPDump represents ACK as a dot :)" + clear

#cycles through ip address/port arrays and hpings 'em
def doPing(switch1='',switch2='',switch3=''):

    openTCPDump()
    time.sleep(.5)

    for i_index in range(len(ip_array)):
        for p_index in range(len(port_array)):
            i_val = ip_array[i_index]
            p_val = port_array[p_index]
            print green
            default_args = ['-q', '-c', '1', '-s', '5151', '-p', p_val, i_val]
            if switch3:
                hping_args = ['hping3', switch1, switch2, switch3]
                hproc = subprocess.Popen(args=hping_args + default_args, stdout=subprocess.PIPE)
                houtput = hproc.stdout.read()
            elif switch2:
                hping_args = ['hping3', switch1, switch2]
                hproc = subprocess.Popen(args=hping_args + default_args, stdout=subprocess.PIPE)
                houtput = hproc.stdout.read()
            elif switch1:
                hping_args = ['hping3', switch1]
                hproc = subprocess.Popen(args=hping_args + default_args, stdout=subprocess.PIPE)
                houtput = hproc.stdout.read()
            else:
                hping_args = ['hping3']
                hproc = subprocess.Popen(args=hping_args + default_args, stdout=subprocess.PIPE)
                houtput = hproc.stdout.read()
            print clear

#populate switch variables for flow control in function doPing
def sendSYN():
    print cyan + "{+} Sending SYN packet..." + clear
    switch1='-S'
    doPing(switch1)

def sendACK():
    print cyan + "{+} ACK flag set - expect RST if host there..." + clear
    switch1='-A'
    doPing(switch1)

def sendFIN():
    print cyan + "{+} FIN flag set - no reply if port is open; RA if no port. FW should reply RA if rules set correctly" + clear
    switch1='-F'
    doPing(switch1)

def sendNULL():
    print cyan + "{+} No flags set..." + clear
    doPing()

def sendXMAS():
    print cyan + "{+} xmas scan - if TCP port closed, sends RST" + clear
    switch1='-M'
    switch2='0'
    switch3='-UPF'
    doPing(switch1,switch2,switch3)

def sendICMP():
    print cyan + "{+} Sending single ICMP packet..." + clear
    switch1='-1'
    doPing(switch1)

def sendICMPTime():
    print cyan  + "{+} Sending ICMP Timestamp..." + clear
    switch1='-C'
    switch2='13'
    doPing(switch1,switch2)

def sendICMPAddress():
    print cyan + "{+} Sending ICP Address Mask ping... Only useful to identify old TCP/IP stacks" + clear
    switch1='-C'
    switch2='17'
    doPing(switch1,switch2)

def main():

    banner()
#declare global arrays for argparse

    global ip_array
    ip_array = []
    global port_array
    port_array = []
    global p_array
    p_array = []

#declare mutually exclusive argparse flags - will force either -P or -p AND -I or -i and the functional switches

    parser = argparse.ArgumentParser(description=green + 'Uses hping to decipher fw rules' + clear)
    ports = parser.add_mutually_exclusive_group(required=True)
    ports.add_argument('-P', help='Port list from file')
    ports.add_argument('-p', help='Single Port')
    ports.add_argument('-sp', type=int, help="Increment port, supply start port, requires -ep end port")
    ip = parser.add_mutually_exclusive_group(required=True)
    ip.add_argument('-I', help='IP list from file')
    ip.add_argument('-i', help="Single IP")

#declare functional switches
    parser.add_argument('-s', help='SYN Scan', action='store_true')
    parser.add_argument('-a', help='ACK Scan', action='store_true')
    parser.add_argument('-f', help='FIN Scan', action='store_true')
    parser.add_argument('-n', help='Null Scan', action='store_true')
    parser.add_argument('-x', help='XMAS Scan', action='store_true')
    parser.add_argument('-m', help='ICMP Scan', action='store_true')
    parser.add_argument('-t', help='ICMP Timestamp Scan', action='store_true')
    parser.add_argument('-d', help='ICMP Address Mask Scan', action='store_true')
    parser.add_argument('-ep', type=int, help='End port. To be used with -sp')
    args = parser.parse_args()

#main if statements to control program

    if args.P:
        with open(args.P) as destport:
            for port in destport:
                port_array.append(port)

    if args.p:
        port_array.append(args.p)

    if args.sp:
        for i in range(args.sp, abs(args.ep)+1, 1):
            port_array.append(str(i))

    if args.I:
        with open(args.I) as targets:
            for ip in targets:
                ip_array.append(ip)

    if args.i:
        ip_array.append(args.i)

    if args.s:
        sendSYN()

    if args.a:
        sendACK()

    if args.f:
        sendFIN()

    if args.n:
        sendNULL()

    if args.x:
        sendXMAS()

    if args.m:
        sendICMP()

    if args.t:
        sendICMPTime()

    if args.d:
        sendICMPAddress()


if __name__=="__main__":
    main()

#Things for this to do:
#bind tcpdump to ip addresses in ipfile, if more than one, rather than just to eth0 [can be done using src, dst in tcpdumcmd]
#silence hping output in console if required (can use '2>&1 > /dev/null'; needs combining with subprocess.call correctly
