def protocol_name(proto):
    return {
        6: "TCP",
        17: "UDP",
        1: "ICMP"
    }.get(proto, "OTHER")
