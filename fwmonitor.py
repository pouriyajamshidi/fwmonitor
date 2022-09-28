#!/usr/bin/env python3

import re
import signal
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from time import sleep
from typing import List, NoReturn, Tuple

__version__ = "1.2.3"


class TXTColor:
    BLUE = "\033[94m"
    CYAN = "\033[36m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


class TransportLayer:
    PROTO_PTRN = re.compile(r"PROTO=\S*")
    SRC_PORT_PTRN = re.compile(r"SPT=\d*")
    DST_PORT_PTRN = re.compile(r"DPT=\d*")
    PKT_LEN_PTRN = re.compile(r"LEN=\d*")
    TTL_PTRN = re.compile(r"TTL=\d*")
    LOG_DATE_PTRN = re.compile(r"^...\s* \d* \d\d:\d\d:\d\d")
    PKT_TYPE_PTRN = re.compile(r"RES=.*\s...\s")


class IPv4(TransportLayer):
    SRC_IPV4_PTRN = re.compile(r"SRC=([0-9]{1,3}[\.]){3}[0-9]{1,3}")
    DST_IPV4_PTRN = re.compile(r"DST=([0-9]{1,3}[\.]){3}[0-9]{1,3}")


class IPv6(TransportLayer):
    SRC_IPV6_PTRN = re.compile(r"SRC=([0-9a-f]{1,4}:+){3,7}[0-9a-f]{1,4}")
    DST_IPV6_PTRN = re.compile(r"DST=([0-9a-f]{1,4}:+){3,7}[0-9a-f]{1,4}")
    TTL_PTRN = re.compile(r"HOPLIMIT=\d*")


def sig_handler(frame, signal) -> NoReturn:
    sys.exit(TXTColor.END)


def get_user_input() -> Namespace:
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
        + ". specify '0' to run once",
    )
    parser.add_argument(
        "--ipv6", default=False, action="store_true", help="scan IPv6 logs"
    )
    parser.add_argument(
        "--version", default=False, action="store_true", help="show version"
    )

    return parser.parse_args()


def validate_interval(interval: str) -> int:
    try:
        value = int(interval)
        if value < 0:
            sys.exit(f"{TXTColor.FAIL}[-] Invalid interval value{TXTColor.END}")
        return value
    except ValueError:
        sys.exit(f"{TXTColor.FAIL}[-] Invalid interval value{TXTColor.END}")


def check_logfile_exists(logfile: str) -> None:
    if not Path(logfile).is_file():
        print(f"{TXTColor.FAIL}", end="")
        print(f"[-] Cannot find {logfile}")
        print(f"{TXTColor.END}")
        sys.exit(1)


def read_logfile(file_name: str) -> List[str]:
    with open(file_name, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def sleep_for(interval: int) -> None:
    print(TXTColor.CYAN, end="")

    while interval != 0:
        print(f"\r[+] re-scanning in {interval}", flush=True, end=" ")
        interval -= 1
        sleep(1)

    print(TXTColor.END, end="")


def report_not_found(key: str) -> None:
    print(f"{TXTColor.FAIL}{TXTColor.BOLD}", end="")
    print(f"[-] Could not find a log with '{key}' keyword")
    print(f"{TXTColor.WARNING}{TXTColor.BOLD}", end="")


def display_scanned_lines_number(scanned_lines: int) -> None:
    print(f"{TXTColor.CYAN}", end="")
    print(f"\n[*] Scanned {scanned_lines} lines!")
    print(f"{TXTColor.END}", end="")


def print_banner() -> None:
    print(f"{TXTColor.GREEN}{TXTColor.BOLD}", end="")
    print("\nCount\tSource IP\tSource Port", end="")
    print("\tDestination IP\t  Destination Port", end="")
    print("\tProtocol/Type\tLEN\tTTL\tDate")
    print("-" * 130)
    print(f"{TXTColor.END}", end="")


def print_initial_info(logfile: str, key: str) -> None:
    print(f"{TXTColor.BOLD}")
    print(f"{TXTColor.BLUE}[*] Scanning {logfile} using the '{key}' keyword")
    print(f"{TXTColor.END}", end="")


def analyze_ipv4_log(logs: List[str], key: str) -> Tuple[bool, int]:
    counter = 0
    scanned_lines = 0
    found = False

    for line in logs:
        scanned_lines += 1

        if key not in line or not re.search(IPv4.SRC_IPV4_PTRN, line):
            continue

        found = True
        counter += 1

        if counter == 1 or (counter % 20) == 0:
            print_banner()

        src_ip = re.search(IPv4.SRC_IPV4_PTRN, line)[0].replace("SRC=", "")
        dst_ip = re.search(IPv4.DST_IPV4_PTRN, line)[0].replace("DST=", "")
        protocol = re.search(IPv4.PROTO_PTRN, line)[0].replace("PROTO=", "")
        pkt_len = re.search(IPv4.PKT_LEN_PTRN, line)[0].replace("LEN=", "")
        ttl = re.search(IPv4.TTL_PTRN, line)[0].replace("TTL=", "")
        log_date = re.search(IPv4.LOG_DATE_PTRN, line)[0]
        src_port = dst_port = None

        # let's see if we need to look for src/dst ports
        if protocol in ["TCP", "UDP"]:
            src_port = re.search(IPv4.SRC_PORT_PTRN, line)[0].replace("SPT=", "")
            dst_port = re.search(IPv4.DST_PORT_PTRN, line)[0].replace("DPT=", "")
            # TCP has packet type unlike UDP
            if protocol == "TCP":
                pkt_type = re.search(IPv4.PKT_TYPE_PTRN, line)[0].replace(
                    "RES=0x00 ", "/"
                )
        elif protocol in ["ICM", "ICMP"]:
            protocol = "ICMP"
        elif protocol == "2":
            protocol = "IGMP"

        log = f"{counter})\t{src_ip}\t{src_port}\t\t{dst_ip}\t  {dst_port}\t\t\t"

        if protocol != "TCP":
            log += protocol
            log += " " * (16 - len(protocol))
        else:
            log += protocol + pkt_type
            log += " " * (13 - len(pkt_type))

        log += f"{pkt_len}\t{ttl}\t{log_date}"
        log += " " * (130 - (len(log_date) + 113)) + f"{TXTColor.GREEN}|"

        print(f"{TXTColor.BOLD}{log}")
        print(f"{'-' * 130}{TXTColor.END}")

    return found, scanned_lines


def analyze_ipv6_log(logs: List[str], key: str) -> Tuple[bool, int]:
    counter = 0
    scanned_lines = 0
    found = False

    for line in logs:
        scanned_lines += 1

        if key not in line or not re.search(IPv6.SRC_IPV6_PTRN, line):
            continue

        found = True
        counter += 1

        src_ip = re.search(IPv6.SRC_IPV6_PTRN, line)[0].replace("SRC=", "")
        dst_ip = re.search(IPv6.DST_IPV6_PTRN, line)[0].replace("DST=", "")
        protocol = re.search(IPv6.PROTO_PTRN, line)[0].replace("PROTO=", "")
        pkt_len = re.search(IPv6.PKT_LEN_PTRN, line)[0].replace("LEN=", "")
        ttl = re.search(IPv6.TTL_PTRN, line)[0].replace("HOPLIMIT=", "")
        log_date = re.search(IPv6.LOG_DATE_PTRN, line)[0]
        src_port = dst_port = None

        # let's see if we need to look for src/dst ports
        if protocol in ["TCP", "UDP"]:
            src_port = re.search(IPv6.SRC_PORT_PTRN, line)[0].replace("SPT=", "")
            dst_port = re.search(IPv6.DST_PORT_PTRN, line)[0].replace("DPT=", "")
            # TCP has packet type unlike UDP
            if protocol == "TCP":
                pkt_type = re.search(IPv6.PKT_TYPE_PTRN, line)[0].replace(
                    "RES=0x00 ", ""
                )
        elif protocol in ["ICM", "ICMP"]:
            protocol = "ICMP"
        elif protocol == "2":
            protocol = "IGMP"

        log = f"{counter})\nSource IP: {src_ip}\nSource Port: {src_port}\n"
        log += f"Destination IP: {dst_ip}\nDestination Port: {dst_port}\n"

        if protocol != "TCP":
            log += f"Protocol: {protocol}\n"
        else:
            log += f"Protocol: {protocol}\nPacket Type: {pkt_type}\n"

        log += f"Packet Length: {pkt_len}\nTTL: {ttl}\nDate: {log_date}\n"

        print(f"{TXTColor.BOLD}", end="")
        print(f"{TXTColor.GREEN}-" * 80)
        print(f"{TXTColor.END}{TXTColor.BOLD}{log}")
        print(f"{TXTColor.GREEN}-" * 80)
        print(f"{TXTColor.END}", end="")

    return found, scanned_lines


def main() -> None:
    args = get_user_input()
    logfile = args.file
    key = args.key
    interval = validate_interval(args.interval)
    version = args.version

    if version:
        print(__version__)
        sys.exit(0)

    check_logfile_exists(logfile)

    print_initial_info(logfile, key)

    while True:
        log = read_logfile(logfile)  # Tackles log rotation

        if args.ipv6:
            has_result, scanned_lines_number = analyze_ipv6_log(log, key)
        else:
            has_result, scanned_lines_number = analyze_ipv4_log(log, key)

        display_scanned_lines_number(scanned_lines_number)

        if not has_result:
            report_not_found(key)
        if interval == 0:
            sys.exit()

        print("\n")
        sleep_for(interval)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, sig_handler)
    main()
