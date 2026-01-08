import subprocess
import xml.etree.ElementTree as ET

from .utils import log, NMAP_ARGUMENTS


def scan_target(target: str) -> dict:
    log(f"Starting Nmap scan for {target}", "INFO")

    # Build command from NMAP_ARGUMENTS so you can change it in one place
    command = ["nmap"] + NMAP_ARGUMENTS.split() + ["-oX", "-", target]
    log(f"Running command: {' '.join(command)}", "INFO")

    try:
        xml_output = subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=50,  # prevent backend from hanging forever
        )
        log("Nmap finished successfully", "INFO")
    except subprocess.TimeoutExpired:
        log("Nmap timed out after 50 seconds", "ERROR")
        raise RuntimeError("Nmap timed out")
    except Exception as e:
        log(f"Nmap execution failed: {e}", "ERROR")
        raise RuntimeError("Nmap scan failed")

    return _parse_nmap_xml(xml_output)


def _parse_nmap_xml(xml_data: str) -> dict:
    root = ET.fromstring(xml_data)
    hosts: dict = {}

    for host in root.findall("host"):
        address_el = host.find("address")
        if address_el is None:
            continue
        address = address_el.attrib.get("addr")

        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.attrib.get("name") if hostname_el is not None else ""

        services = []
        for port in host.findall(".//port"):
            state_el = port.find("state")
            state = state_el.attrib.get("state") if state_el is not None else ""

            service_el = port.find("service")

            service_data = {
                "port": int(port.attrib.get("portid", 0)),
                "protocol": port.attrib.get("protocol", ""),
                "state": state,
                "service": service_el.attrib.get("name", "") if service_el is not None else "",
                "product": service_el.attrib.get("product", "") if service_el is not None else "",
                "version": service_el.attrib.get("version", "") if service_el is not None else "",
                "vulnerabilities": [],  # Layer 2 / later analysis will fill this
            }

            services.append(service_data)

        hosts[address] = {
            "hostname": hostname,
            "state": "up",
            "services": services,
        }

    return hosts
