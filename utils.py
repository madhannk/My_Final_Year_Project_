def protocol_name(proto):
    return {
        6: "TCP",
        17: "UDP",
        1: "ICMP"
    }.get(proto, "OTHER")

def service_name(port):
    return {
        80: "HTTP",
        443: "HTTPS",
        22: "SSH",
        21: "FTP",
        53: "DNS"
    }.get(port, "OTHER")
