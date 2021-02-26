#!/usr/bin/python3

import re
import signal
from argparse import ArgumentParser
from pathlib import Path
from time import sleep


class txtcolor:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


def sig_handler(frame, signal):
    print("\033[0m", end="")
    exit()


def print_header():
    print(f"{txtcolor.GREEN}{txtcolor.BOLD}", end="")
    print(f"\nCount\tSource IP\tSource Port\tDestination IP", end="")
    print(f"\t  Destination Port\tProtocol/Type\tLEN\tTTL\tDate")
    print("-" * 130)
    print(f"{txtcolor.END}", end="")


def get_user_input():
    parser = ArgumentParser()

    parser.add_argument("-file", default="/var/log/syslog",
                        help="file to inspect. Default is /var/log/syslog")
    parser.add_argument("-key", default="UFW BLOCK",
                        help="block/reject keyword to look for. Default is 'UFW BLOCK'")
    parser.add_argument("-interval", default=60,
                        help="interval to check the file in seconds. Default is 60" +
                        ". specify 'onetime' to run once")

    args = parser.parse_args()

    return args.file, args.key, args.interval


def check_file(logfile):

    if not Path(logfile).is_file():
        print(f"{txtcolor.FAIL}", end="")
        print(f"[-] Cannot access {logfile}")
        print(f"{txtcolor.END}", end="")
        exit(1)


def main():

    signal.signal(signal.SIGINT, sig_handler)

    logfile, key, interval = get_user_input()
    check_file(logfile)

    ipv4_pattern = re.compile(r"SRC=([0-9]{1,3}[\.]){3}[0-9]{1,3}")

    print(f"{txtcolor.BOLD}", end="")
    print(f"\n{txtcolor.BLUE}[*] Scanning {logfile} using {key} keyword")
    print(f"{txtcolor.END}", end="")

    while True:
        counter = 0
        scanned_lines = 0
        found = False
        protocol = ""

        print_header()

        with open(logfile, "r") as file:

            for line in file:
                scanned_lines += 1

                if key in line and re.search(ipv4_pattern, line):
                    found = True
                    counter += 1
                    if (counter % 15) == 0:
                        print_header()

                    protocol = re.search(r"PROTO=...", line)[0]
                    protocol = protocol.replace("PROTO=", "")

                    if protocol == "ICM":
                        protocol = "ICMP"

                    srcIP = re.search(ipv4_pattern, line)[0]
                    srcIP = srcIP.replace("SRC=", "")

                    dstIP = re.search(
                        r"DST=([0-9]{1,3}[\.]){3}[0-9]{1,3}", line)[0]
                    dstIP = dstIP.replace("DST=", "")

                    if protocol != "ICMP":
                        srcPort = re.search(r"SPT=\d*", line)[0]
                        srcPort = srcPort.replace("SPT=", "")
                        dstPort = re.search(r"DPT=\d*", line)[0]
                        dstPort = dstPort.replace("DPT=", "")
                    else:
                        srcPort = "NULL"
                        dstPort = "NULL"

                    pktLen = re.search(r"LEN=\d*", line)[0]
                    pktLen = pktLen.replace("LEN=", "")
                    TTL = re.search(r"TTL=\d*", line)[0]
                    TTL = TTL.replace("TTL=", "")
                    logDate = re.search(r"^...\s* \d* \d\d:\d\d:\d\d", line)[0]

                    print(f"{txtcolor.BOLD}", end="")
                    print(f'{counter})\t', end='')
                    print(f'{srcIP}\t', end='')
                    print(f'{srcPort}\t\t', end='')
                    print(f'{dstIP}\t  ', end='')
                    print(f'{dstPort}\t\t\t', end='')

                    if protocol == "UDP":
                        print(f'{protocol}\t\t', end='')
                    elif protocol == "TCP":
                        print(f'{protocol}', end='')

                        pkt_type = re.search(r"RES=.* ... ", line)[0]
                        pkt_type = pkt_type.replace("RES=0x00 ", "/")

                        if len(pkt_type) > 12:
                            print(f'{pkt_type} ', end='')
                        else:
                            print(f'{pkt_type}\t', end='')
                    else:
                        print(f'{protocol}\t\t', end='')

                    print(f'{pktLen}\t', end='')
                    print(f'{TTL}\t', end='')
                    print(f'{logDate}', end='')
                    print(f'{txtcolor.GREEN}\t |')
                    print("-" * 130)
                    print(f"{txtcolor.END}", end="")
                    # sleep(0.2)

                else:
                    pass

            if not found:
                print(f"{txtcolor.FAIL}{txtcolor.BOLD}", end="")
                print(f"[-] Could not find a log with '{key}' keyword")
                print(f"{txtcolor.WARNING}{txtcolor.BOLD}", end="")
                print(f"[*] Sleeping for 10 seconds... ", end="")
                print("Press control+c to exit")
                print(f"{txtcolor.END}\n", end="")

                if interval == "onetime":
                    exit()

                sleep(10)

            print("\n\n")

        print("\033[36m", end="")
        print(f"[*] Scanned {scanned_lines} lines!\n")
        print("\033[0m", end="")

        if interval == "onetime":
            exit()
        sleep(interval)


if __name__ == "__main__":
    main()
