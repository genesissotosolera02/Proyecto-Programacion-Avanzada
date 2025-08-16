#!/usr/bin/env python3

import sys, subprocess, threading, queue, re, time, os, signal, pathlib

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

# Import AlertLogger from user's script
from alert_logger import AlertLogger  # expects alert_logger.py at project root

# Patterns based on sniffer_defense.py prints
RE_PING = re.compile(r"\[!\]\s*Ping detectado desde\s+([0-9\.]+)")
RE_SCAN = re.compile(r"\[!\]\s*Escaneo hacia puerto\s+(\d+)\s+desde\s+([0-9\.]+)")

def run():
    logger = AlertLogger()
    logger.start()

    sniffer_path = str(ROOT_DIR / "sniffer_defense.py")
    if not os.path.exists(sniffer_path):
        print("[ADAPTER] sniffer_defense.py no encontrado", flush=True)
        return

    print("[ADAPTER] Lanzando sniffer_defense.py ...", flush=True)
    proc = subprocess.Popen(
        ["python3", sniffer_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            print(f"[SNIFFER] {line}", flush=True)

            # Parse events and forward to AlertLogger
            m_ping = RE_PING.search(line)
            if m_ping:
                ip = m_ping.group(1)
                logger.log_event_simple(
                    event_type="ICMP_PING",
                    source_ip=ip,
                    target_port=0,
                    severity="LOW",
                    description="Ping detectado por sniffer_defense",
                    source_module="sniffer_defense"
                )
                continue

            m_scan = RE_SCAN.search(line)
            if m_scan:
                port = int(m_scan.group(1))
                ip = m_scan.group(2)
                severity = "MEDIUM" if port not in (22,80,443) else "LOW"
                if port in (22, 3306, 3389):
                    severity = "HIGH"
                logger.log_event_simple(
                    event_type="PORT_SCAN",
                    source_ip=ip,
                    target_port=port,
                    severity=severity,
                    description=f"Escaneo hacia puerto {port}",
                    source_module="sniffer_defense"
                )
                continue

        proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        logger.stop()
        try:
            proc.terminate()
        except Exception:
            pass

if __name__ == "__main__":
    run()
