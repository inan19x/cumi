#!/usr/bin/env python3

import configparser
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlparse


PROGRAM_NAME = "cumi"


class CumiError(Exception):
    """Cumi application error."""


def load_config(config_path):
    config = configparser.ConfigParser()

    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            config.read_file(config_file)
    except OSError as exc:
        raise CumiError(f"unable to read config file: {exc}")

    if not config.has_section("general"):
        raise CumiError("missing [general] section in config")

    required = ("access_log", "signature_file", "alert_log")

    for option in required:
        if not config.has_option("general", option):
            raise CumiError(f"missing configuration option: {option}")

    access_log = config.get("general", "access_log").strip()
    signature_file = config.get("general", "signature_file").strip()
    alert_log = config.get("general", "alert_log").strip()

    if not access_log:
        raise CumiError("access_log cannot be empty")

    if not signature_file:
        raise CumiError("signature_file cannot be empty")

    if not alert_log:
        raise CumiError("alert_log cannot be empty")

    return access_log, signature_file, alert_log


def normalize_domain(domain):
    domain = domain.strip().lower()

    if not domain:
        return ""

    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.hostname or ""

    domain = domain.rstrip(".")

    if "/" in domain:
        domain = domain.split("/", 1)[0]

    if domain.count(":") == 1:
        host, port = domain.rsplit(":", 1)

        if port.isdigit():
            domain = host

    return domain


def load_signatures(signature_path):
    signatures = {}
    current_category = None

    try:
        with open(signature_path, "r", encoding="utf-8") as signature_file:
            for line_number, raw_line in enumerate(signature_file, 1):
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                if line.startswith("[") and line.endswith("]"):
                    category = line[1:-1].strip().lower()

                    if not category:
                        raise CumiError(
                            f"empty signature category at line {line_number}"
                        )

                    current_category = category
                    signatures.setdefault(category, set())
                    continue

                if current_category is None:
                    raise CumiError(
                        f"domain found before a category at line {line_number}"
                    )

                domain = normalize_domain(line)

                if domain:
                    signatures[current_category].add(domain)

    except OSError as exc:
        raise CumiError(f"unable to read signature file: {exc}")

    if not signatures:
        raise CumiError("signature file contains no categories")

    return signatures


def extract_hostname(request_url):
    request_url = request_url.strip()

    if not request_url or request_url == "-":
        return None

    # CONNECT requests are normally logged as:
    # example.com:443
    if "://" not in request_url:
        host = request_url

        if host.startswith("["):
            closing_bracket = host.find("]")

            if closing_bracket != -1:
                host = host[1:closing_bracket]

        elif host.count(":") == 1:
            hostname, port = host.rsplit(":", 1)

            if port.isdigit():
                host = hostname

        return normalize_domain(host)

    parsed = urlparse(request_url)

    return normalize_domain(parsed.hostname or "")


def domain_matches(hostname, signature):
    hostname = normalize_domain(hostname)
    signature = normalize_domain(signature)

    if not hostname or not signature:
        return False

    if hostname == signature:
        return True

    return hostname.endswith("." + signature)


def find_matching_categories(hostname, signatures):
    matches = []

    for category, domains in signatures.items():
        for signature in domains:
            if domain_matches(hostname, signature):
                matches.append(category)
                break

    return matches


def parse_squid_line(line):
    """
    Parse the standard Squid native log format:

    %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt

    Example:

    1759321234.123  125 192.168.1.50 TCP_TUNNEL/200 1234
    CONNECT www.example.com:443 john HIER_DIRECT/1.2.3.4 -
    """

    line = line.rstrip("\r\n")

    if not line:
        return None

    parts = line.split()

    if len(parts) < 9:
        return None

    request = {
        "timestamp": parts[0],
        "elapsed": parts[1],
        "client": parts[2],
        "result_status": parts[3],
        "response_size": parts[4],
        "method": parts[5],
        "url": parts[6],
        "user": parts[7],
        "hierarchy": parts[8],
        "content_type": parts[9] if len(parts) > 9 else "-",
    }

    return request


def build_alert(category, request):
    return (
        f"{datetime.now().strftime('%H:%M:%S')} "
        f"ALERT {PROGRAM_NAME}: "
        f"category={category} "
        f"URL={request['url']} "
        f"client={request['client']} "
        f"user={request['user']} "
        f"method={request['method']}"
    )


def write_alert(alert_path, alert):
    try:
        parent = os.path.dirname(alert_path)

        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(alert_path, "a", encoding="utf-8") as alert_file:
            alert_file.write(alert + "\n")

    except OSError as exc:
        raise CumiError(f"unable to write alert log: {exc}")


def open_log(path):
    try:
        return open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise CumiError(f"unable to open access log: {exc}")


def follow_log(path):
    """
    Follow the Squid access log.

    Initial startup:
        Start at EOF so existing entries aren't processed.

    Replacement/rotation:
        Open the new file from the beginning so entries already
        written to the replacement file are not skipped.

    Truncation:
        Reopen from the beginning of the truncated file.
    """

    while not os.path.exists(path):
        time.sleep(0.5)

    log_file = open_log(path)

    try:
        # Initial startup: ignore existing log contents.
        log_file.seek(0, os.SEEK_END)

        current_inode = os.fstat(log_file.fileno()).st_ino

        while True:
            line = log_file.readline()

            if line:
                yield line
                continue

            time.sleep(0.5)

            try:
                stat = os.stat(path)
                current_position = log_file.tell()

                # File was truncated.
                if stat.st_size < current_position:
                    log_file.close()
                    log_file = open_log(path)

                    current_inode = os.fstat(log_file.fileno()).st_ino

                    # IMPORTANT:
                    # Start at the beginning of the new contents.
                    continue

                # File was replaced/rotated.
                if stat.st_ino != current_inode:
                    log_file.close()
                    log_file = open_log(path)

                    current_inode = os.fstat(log_file.fileno()).st_ino

                    # IMPORTANT:
                    # Do NOT seek to EOF here.
                    # Read entries already present in the replacement.
                    continue

            except FileNotFoundError:
                try:
                    log_file.close()
                except OSError:
                    pass

                while not os.path.exists(path):
                    time.sleep(0.5)

                log_file = open_log(path)
                current_inode = os.fstat(log_file.fileno()).st_ino

                # Read the new file from the beginning.

            except OSError:
                # Ignore transient filesystem errors and retry.
                continue

    finally:
        try:
            log_file.close()
        except OSError:
            pass


def process_line(line, signatures, alert_log):
    request = parse_squid_line(line)

    if request is None:
        return

    hostname = extract_hostname(request["url"])

    if not hostname:
        return

    categories = find_matching_categories(hostname, signatures)

    for category in categories:
        alert = build_alert(category, request)

        # Print immediately.
        print(alert, flush=True)

        # Write the exact same line to the alert log.
        write_alert(alert_log, alert)


def main():
    config_path = "config/cumi.conf"

    try:
        access_log, signature_file, alert_log = load_config(config_path)

        signatures = load_signatures(signature_file)

        print(f"Cumi monitoring: {access_log}", flush=True)

        for line in follow_log(access_log):
            process_line(line, signatures, alert_log)

    except KeyboardInterrupt:
        print("Cumi stopped.", flush=True)
        return 0

    except CumiError as exc:
        print(f"Cumi error: {exc}", file=sys.stderr)
        return 1

    except Exception as exc:
        print(f"Cumi error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

