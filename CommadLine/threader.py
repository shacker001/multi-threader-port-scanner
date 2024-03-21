#!/usr/bin/python3
# ThreaderScan - Multi-Threader Port Scanner
# A project by Sh4cker
# v1.0.0
# https://github.com/shacker001/multi-threader

import socket
import os
import signal
import time
import threading
import sys
import subprocess
from queue import Queue
from datetime import datetime
from ipaddress import ip_network

# Main Function
def main():
    if len(sys.argv) > 1 and (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
        help_options()
        sys.exit()

    socket.setdefaulttimeout(0.30)
    print_lock = threading.Lock()
    discovered_ports = []

    # Welcome Banner
    print("    |" + "~" * 63 + "|")
    print("    |~                                                             ~|")
    print("    |~        Threader Scan - Multi-Threaded Port Scanner          ~|")
    print("    |~                       Version 1.0.0                         ~|")
    print("    |~                   A project by Sh4cker                      ~|")
    print("    |~       https://github.com/shacker001/multi-threader          ~|")
    print("    |~                                                             ~|")
    print("    |" + "~" * 63 + "|")
    print("\n\n")
    time.sleep(1)
    
    # Input IP and Port range
    target_range = input("  [+] Enter your target IP range (CIDR format, e.g., 192.168.0.0/24): ")
    start_port   = int(input("  [+] Enter the Start Port: "))
    end_port     = int(input("  [+] Enter the End Port: "))
    error = "Invalid Input"
    try:
        ips = [str(ip) for ip in ip_network(target_range).hosts()]
    except ValueError:
        print("\n[-] Invalid format. Please use a correct IP range in CIDR format (e.g., 192.168.0.0/24) [-]\n")
        sys.exit()

    # Banner
    print("    " + "~" * 63)
    print("    " + "~   Scanning target IP range: " + target_range)
    print("    ~   Time started: " + str(datetime.now()))
    print("    " + "~" * 63)
    print("\n")
    t1 = datetime.now()

    print("        ==========[ OPEN PORTS ]===========\n")

    def portscan(ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            portx = s.connect((ip, port))
            service_name = socket.getservbyport(port)
            with print_lock:
                print(f"    [+] Port {port} is open on {ip}, Service: {service_name}")
                discovered_ports.append(str(port))
        except (ConnectionRefusedError, AttributeError, OSError):
            pass
        finally:
            s.close()

    def threader():
        while True:
            worker = q.get()
            for ip in ips:
                portscan(ip, worker)
            q.task_done()

    q = Queue()

    for x in range(200):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for worker in range(start_port, end_port):
        q.put(worker)

    q.join()

    t2 = datetime.now()
    total = t2 - t1
    print("    -- Port scan completed in " + str(total))
    print("\n")
    print("    " + "~" * 63)
    print("    ThreaderScan recommends the following Nmap scan:")
    print("    " + "~" * 63)
    print("    [+] nmap -p {ports} -sV -sC -T4 -Pn -oA {ip} {ip}".format(ports=",".join(discovered_ports), ip=target_range))
    print("    " + "~" * 63)
    print("\n")
    nmap = "      nmap -p {ports} -sV -sC -T4 -Pn -oA {ip} {ip}".format(ports=",".join(discovered_ports), ip=target_range)
    t3 = datetime.now()
    total1 = t3 - t1

    def automate():
        choice = '0'
        while choice == '0':
            print("    Would you like to run Nmap or quit to terminal?")
            print("    " + "~" * 63)
            print("    1 = Run suggested Nmap scan")
            print("    2 = Run another Threader scan")
            print("    3 = Exit to terminal")
            print("    " + "~" * 63)
            choice = input("    Option Selection: ")
            if choice == "1":
                try:
                    print(nmap)
                    os.mkdir(target_range)
                    os.chdir(target_range)
                    os.system(nmap)
                    t3 = datetime.now()
                    total1 = t3 - t1
                    print("    " + "-" * 63)
                    print("    Combined scan completed in " + str(total1))
                    print("    Press enter to quit...")
                    input()
                    # quit()
                except FileExistsError as e:
                    print(e)
                    exit()
            elif choice == "2":
                main()
            elif choice == "3":
                print("\n      Goodbye!")
                print("\n      Copyright 2024 by Sh4cker\n")
                sys.exit()
            else:
                print("    Please make a valid selection")
                automate()

    automate()

# Help Options
def help_options():
    helps = """
        ++++++++++++] HELP OPTIONS [++++++++++++

        [+] python threader.py -h       to display help menu
        [+] python threader.py --help   to display help menu


        [++] IPv4 CIDR (Classless Inter-Domain Routing) Notation [++]

        [+] Single IPv4 address: 127.0.0.1/32
        [+] Small network (e.g., 256 addresses): 192.168.1.0/24
        [+] Medium network (e.g., 65,536 addresses): 10.0.0.0/12
        [+] Large network (e.g., 16,777,216 addresses): 172.16.0.0/12


        [++] IPv6 CIDR Notation [++]

        [+] Single IPv6 address: ::1/128
        [+] Small network (e.g., 2^64 addresses): 2001:0db8::/64
        [+] Medium network (e.g., 2^80 addresses): 2001:0db8:1234::/64
        [+] Large network (e.g., 2^96 addresses): 2001:0db8:1234:5678::/64


        ++++++++++++++] USAGE [++++++++++++++

        [+] Python threader.py          to start the port scan
        [+] python3 threader.py         to start the port scan
        
    
    """
    print(helps)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n    Goodbye!")
        print("\n    Copyright 2024 by Sh4cker\n")
        quit()
