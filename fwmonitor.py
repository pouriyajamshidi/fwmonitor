#!/usr/bin/python3

import re
import signal
import sys
from argparse import ArgumentParser
from pathlib import Path
from time import sleep


class TXTColor:
    BLUE = "\033[94m"
    CYAN = "\033[36m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


class IPv4:
    SRC_IPV4_PTRN = re.compile(r"SRC=([0-9]{1,3}[\.]){3}[0-9]{1,3}")
    DST_IPV4_PTRN = re.compile(r"DST=([0-9]{1,3}[\.]){3}[0-9]{1,3}")
    PROTO_PTRN = re.compile(r"PROTO=\S*")
    SRC_PORT_PTRN = re.compile(r"SPT=\d*")
    DST_PORT_PTRN = re.compile(r"DPT=\d*")
    PKT_LEN_PTRN = re.compile(r"LEN=\d*")
    TTL_PTRN = re.compile(r"TTL=\d*")
    LOG_DATE_PTRN = re.compile(r"^...\s* \d* \d\d:\d\d:\d\d")
    PKT_TYPE_PTRN = re.compile(r"RES=.* ... ")


def sig_handler(frame, signal):
    sys.exit(TXTColor.END)


def get_user_input():
    parser = ArgumentParser()

    parser.add_argument(
        "--file",
        default="/var/log/syslog",
        help="file to inspect. Default is /var/log/syslog",
    )
    parser.add_argument(
        "--key",
        default="UFW BLOCK",
        help="block/reject keyword to look for. Default is 'UFW BLOCK'",
    )
    parser.add_argument(
        "--interval",
        default=60,
        help="interval to check the file in seconds. Default is 60"
        + ". specify 'onetime' to run once",
    )

    args = parser.parse_args()

    return args.file, args.key, args.interval


def validate_interval(interval):
    if interval == "onetime":
        return interval
    try:
        return int(interval)
    except ValueError:
        print(f"{TXTColor.FAIL}[-] Invalid interval value")
        print("\033[0m")
        sys.exit()


def check_file(logfile):
    if not Path(logfile).is_file():
        print(f"{TXTColor.FAIL}", end="")
        print(f"[-] Cannot find {logfile}")
        print(f"{TXTColor.END}", end="")
        sys.exit(1)


def read_file(file):
    with open(file, "r", errors="ignore") as f:
        lines = f.readlines()
    return lines


def sleep_for(interval):
    print(TXTColor.CYAN, end="")

    while interval != 0:
        print(f"\r[+] re-scanning in {interval}", flush=True, end=" ")
        interval -= 1
        sleep(1)

    print(TXTColor.END, end="")


def report_not_found(key):
    print(f"{TXTColor.FAIL}{TXTColor.BOLD}", end="")
    print(f"[-] Could not find a log with '{key}' keyword")
    print(f"{TXTColor.WARNING}{TXTColor.BOLD}", end="")


def display_scanned_lines(scanned_lines):
    print("\033[36m", end="")
    print(f"\n[*] Scanned {scanned_lines} lines!")
    print("\033[0m")


def print_banner():
    print(f"{TXTColor.GREEN}{TXTColor.BOLD}", end="")
    print("\nCount\tSource IP\tSource Port", end="")
    print("\tDestination IP\t  Destination Port", end="")
    print("\tProtocol/Type\tLEN\tTTL\tDate")
    print("-" * 130)
    print(f"{TXTColor.END}", end="")


def analyze_ipv4_log(log, key):
    counter = 0
    scanned_lines = 0
    found = False

    for line in log:
        scanned_lines += 1

        if key not in line or not re.search(IPv4.SRC_IPV4_PTRN, line):
            continue

        found = True
        counter += 1

        if counter == 1 or (counter % 20) == 0:
            print_banner()

        src_ip_raw = re.search(IPv4.SRC_IPV4_PTRN, line)[0]
        src_ip = src_ip_raw.replace("SRC=", "")

        dst_ip_raw = re.search(IPv4.DST_IPV4_PTRN, line)[0]
        dst_ip = dst_ip_raw.replace("DST=", "")

        protocol_raw = re.search(IPv4.PROTO_PTRN, line)[0]
        protocol = protocol_raw.replace("PROTO=", "")

        src_port = dst_port = None

        # let's see if we need to look for src/dst ports
        if protocol in ["TCP", "UDP"]:
            src_port_raw = re.search(IPv4.SRC_PORT_PTRN, line)[0]
            src_port = src_port_raw.replace("SPT=", "")
            dst_port_raw = re.search(IPv4.DST_PORT_PTRN, line)[0]
            dst_port = dst_port_raw.replace("DPT=", "")
            # TCP has packet type unlike UDP
            if protocol == "TCP":
                pkt_type_raw = re.search(IPv4.PKT_TYPE_PTRN, line)[0]
                pkt_type = pkt_type_raw.replace("RES=0x00 ", "/")
        elif protocol in ["ICM", "ICMP"]:
            protocol = "ICMP"
        elif protocol == "2":
            protocol = "IGMP"

        pkt_len = re.search(IPv4.PKT_LEN_PTRN, line)[0]
        pkt_len = pkt_len.replace("LEN=", "")

        ttl_raw = re.search(IPv4.TTL_PTRN, line)[0]
        ttl = ttl_raw.replace("TTL=", "")

        log_date = re.search(IPv4.LOG_DATE_PTRN, line)[0]

        print(f"{TXTColor.BOLD}", end="")
        print(f"{counter})\t", end="")
        print(f"{src_ip}\t", end="")
        print(f"{src_port}\t\t", end="")
        print(f"{dst_ip}\t  ", end="")
        print(f"{dst_port}\t\t\t", end="")

        if protocol != "TCP":
            print(f"{protocol}", end="")
            print(" " * (16 - len(protocol)), end="")
        else:
            print(f"{protocol}", end="")
            print(f"{pkt_type}", end="")
            print(" " * (13 - len(pkt_type)), end="")

        print(f"{pkt_len}\t", end="")
        print(f"{ttl}\t", end="")
        print(f"{log_date}", end="")
        print(" " * (130 - (len(log_date) + 113)) + f"{TXTColor.GREEN}|")
        print("-" * 130)
        print(f"{TXTColor.END}", end="")

    return found, scanned_lines


def main():
    logfile, key, interval = get_user_input()
    interval = validate_interval(interval)
    check_file(logfile)

    print(f"{TXTColor.BOLD}")
    print(f"{TXTColor.BLUE}[*] Scanning {logfile} using {key} keyword")
    print(f"{TXTColor.END}", end="")

    while True:
        log = read_file(logfile)   # Tackles log rotation
        result, scanned_lines = analyze_ipv4_log(log, key)
        display_scanned_lines(scanned_lines)
        if not result:
            report_not_found(key)
            if interval != "onetime":
                sleep_for(10)
        if interval == "onetime":
            sys.exit()
        print("\n\n")
        sleep_for(interval)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, sig_handler)
    main()
