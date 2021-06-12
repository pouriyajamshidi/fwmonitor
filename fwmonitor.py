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
    print("\033[0m")
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


def read_file(file):
    with open(file, "r") as f:
        lines = f.readlines()
    return lines


def analyze_ipv4_log(log, key, interval):

    src_ipv4_ptrn = re.compile(r"SRC=([0-9]{1,3}[\.]){3}[0-9]{1,3}")
    dst_ipv4_ptrn = re.compile(r"DST=([0-9]{1,3}[\.]){3}[0-9]{1,3}")
    src_port_ptrn = re.compile(r"SPT=\d*")
    dst_port_ptrn = re.compile(r"DPT=\d*")
    pkt_len_ptrn = re.compile(r"LEN=\d*")
    TTL_ptrn = re.compile(r"TTL=\d*")
    log_date_ptrn = re.compile(r"^...\s* \d* \d\d:\d\d:\d\d")
    pkt_type_ptrn = re.compile(r"RES=.* ... ")

    while True:
        counter = 0
        scanned_lines = 0
        found = False
        protocol = ""

        for line in log:
            scanned_lines += 1

            if key in line and re.search(src_ipv4_ptrn, line):
                found = True
                counter += 1
                if counter == 1 or (counter % 15) == 0:
                    print(f"{txtcolor.GREEN}{txtcolor.BOLD}", end="")
                    print(f"\nCount\tSource IP\tSource Port", end="")
                    print(f"\tDestination IP\t  Destination Port", end="")
                    print(f"\tProtocol/Type\tLEN\tTTL\tDate")
                    print("-" * 130)
                    print(f"{txtcolor.END}", end="")

                srcIP_raw = re.search(src_ipv4_ptrn, line)[0]
                srcIP = srcIP_raw.replace("SRC=", "")

                dstIP_raw = re.search(dst_ipv4_ptrn, line)[0]
                dstIP = dstIP_raw.replace("DST=", "")

                protocol_raw = re.search(r"PROTO=...", line)[0]
                protocol = protocol_raw.replace("PROTO=", "")

                if protocol == "ICM":
                    protocol = "ICMP"
                    srcPort = "NULL"
                    dstPort = "NULL"
                else:
                    srcPort_raw = re.search(src_port_ptrn, line)[0]
                    srcPort = srcPort_raw.replace("SPT=", "")
                    dstPort_raw = re.search(dst_port_ptrn, line)[0]
                    dstPort = dstPort_raw.replace("DPT=", "")

                pktLen = re.search(pkt_len_ptrn, line)[0]
                pktLen = pktLen.replace("LEN=", "")

                TTL_raw = re.search(TTL_ptrn, line)[0]
                TTL = TTL_raw.replace("TTL=", "")

                logDate = re.search(log_date_ptrn, line)[0]

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

                    pkt_type = re.search(pkt_type_ptrn, line)[0]
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

            else:
                pass

        print("\033[36m", end="")
        print(f"\n[*] Scanned {scanned_lines} lines!")
        print("\033[0m", end="")

        if not found:
            print(f"{txtcolor.FAIL}{txtcolor.BOLD}", end="")
            print(f"[-] Could not find a log with '{key}' keyword")
            print(f"{txtcolor.WARNING}{txtcolor.BOLD}", end="")

            if interval == "onetime":
                exit()

            print(f"[*] re-scanning in 10 seconds... ", end="")
            print("[*] Press control+c to exit")
            print(f"{txtcolor.END}\n", end="")

            sleep(10)
            break

        if interval == "onetime":
            exit()

        print("\n\n")

        slp_ctr = int(interval)

        while slp_ctr != 0:
            print("\033[36m", end="")
            print(f"\r[+] re-scanning in {slp_ctr}", flush=True, end=" ")
            print("\033[0m", end="")
            slp_ctr -= 1
            sleep(1)


def main():

    signal.signal(signal.SIGINT, sig_handler)

    logfile, key, interval = get_user_input()
    check_file(logfile)
    log = read_file(logfile)

    print(f"{txtcolor.BOLD}", end="")
    print(f"\n{txtcolor.BLUE}[*] Scanning {logfile} using {key} keyword")
    print(f"{txtcolor.END}", end="")

    analyze_ipv4_log(log, key, interval)


if __name__ == "__main__":
    main()