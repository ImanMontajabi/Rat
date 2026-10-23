import Foundation

/// The service usually found on a well-known port (`TCP 443` → HTTPS, `TCP 5223` → APN). A port is a hint, not
/// proof: any program can use any port, so the UI presents the name as the usual service, never as a fact.
public enum PortNames {
    public enum Proto: Sendable { case tcp, udp }

    /// The usual service on `port`, or nil when the port has no well-known name.
    public static func name(port: Int, proto: Proto) -> String? {
        if proto == .udp, let n = udp[port] { return n }
        if proto == .tcp, let n = tcp[port] { return n }
        return common[port]
    }

    /// Where TCP and UDP differ on the same port.
    static let udp: [Int: String] = [
        443: "QUIC",          // HTTP/3
        853: "DoQ",           // DNS over QUIC
        4500: "IPSec-NAT",
    ]
    static let tcp: [Int: String] = [:]

    /// Reviewed from the list in issue #1. Changed against it: 2483 is Oracle's plain listener (2484 is TLS),
    /// 5500 is VNC's listen mode, 7000 is AirPlay (macOS' AirPlay receiver listens there, as on 5000), 7443 is an
    /// HTTPS alternative, 8080 an HTTP alternative, 9100 is printing (JetDirect), 16379 is Redis' cluster bus and
    /// 62078 the iPhone sync service (lockdownd). Dropped as unverified or wrong: 323, 475, 3480, 4243, 5006, 5100,
    /// 6380, 10443, 55555.
    static let common: [Int: String] = [
        1: "TCPMUX", 5: "RJE", 7: "Echo", 9: "Discard", 11: "SysStat", 13: "Daytime", 15: "NetStat", 17: "QOTD", 19: "Chargen",
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 37: "Time", 39: "RLP", 42: "NameServer", 43: "WHOIS",
        49: "TACACS", 53: "DNS", 57: "MTP", 67: "DHCP", 68: "DHCP", 69: "TFTP", 70: "Gopher", 79: "Finger", 80: "HTTP",
        88: "Kerberos", 95: "SUPDUP", 101: "HOSTNAME", 102: "ISO-TSAP", 104: "DICOM", 109: "POP2", 110: "POP3", 111: "RPCBind",
        113: "Ident", 115: "SFTP", 117: "UUCP-Path", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
        139: "NetBIOS-SSN", 143: "IMAP", 144: "NEWS", 161: "SNMP", 162: "SNMP-Trap", 170: "Print-Srv", 179: "BGP", 194: "IRC",
        199: "SMUX", 201: "AppleTalk", 209: "QMTP", 210: "ANSI-Z39.50", 213: "IPX", 220: "IMAP3", 264: "BGMP", 318: "TSP",
        383: "HP-PerfData", 389: "LDAP", 401: "UPS", 411: "DirectConnect", 427: "SLP", 443: "HTTPS", 445: "SMB",
        464: "Kerberos-PW", 465: "SMTPS", 497: "Retrospect", 500: "ISAKMP", 501: "STMF", 502: "Modbus", 512: "Exec",
        513: "rLogin", 514: "Syslog", 515: "LPD", 520: "RIP", 521: "RIPng", 524: "NCP", 530: "RPC", 543: "KLogin", 544: "KShell",
        546: "DHCPv6-Client", 547: "DHCPv6-Server", 548: "AFP", 554: "RTSP", 556: "Remotefs", 563: "NNTPS", 587: "SMTP-Submit",
        591: "FileMaker", 593: "HTTP-RPC", 623: "IPMI", 625: "AppleXSrvr", 631: "IPP", 636: "LDAPS", 646: "LDP",
        660: "AppleMacOS", 691: "MS-Exchange", 749: "Kerberos-Adm", 751: "Kerberos-IV", 853: "DoT", 873: "Rsync",
        902: "VMware", 903: "VMware-Console", 953: "RNDC", 993: "IMAPS", 995: "POP3S",
        1080: "SOCKS", 1099: "RMI", 1194: "OpenVPN", 1214: "Kazaa", 1241: "Nessus", 1293: "IPSec", 1311: "Dell-OMSA",
        1337: "WASTE", 1433: "MS-SQL", 1434: "MS-SQL-Mon", 1512: "WINS", 1521: "Oracle-DB", 1589: "Cisco-VQPC", 1701: "L2TP",
        1723: "PPTP", 1725: "Steam", 1812: "RADIUS", 1813: "RADIUS-Acct", 1883: "MQTT", 1900: "SSDP", 1935: "RTMP",
        2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL", 2095: "Webmail", 2096: "Webmail-SSL",
        2100: "Oracle-XDB", 2181: "ZooKeeper", 2195: "APNs", 2196: "APNs-Feedback", 2197: "APNs-HTTP2", 2375: "Docker",
        2376: "Docker-TLS", 2377: "Docker-Swarm", 2379: "etcd-Client", 2380: "etcd-Peer", 2483: "Oracle-DB", 2484: "Oracle-TLS",
        2525: "SMTP-Alt", 3000: "Dev-Server", 3001: "Dev-Server-Alt", 3128: "Squid", 3268: "LDAP-GC", 3269: "LDAP-GC-SSL",
        3283: "Apple-Remote", 3306: "MySQL", 3389: "RDP", 3478: "STUN", 3479: "STUN", 3544: "Teredo", 3689: "iTunes-DAAP",
        3690: "SVN", 3724: "Blizzard", 3784: "BFD", 3868: "Diameter",
        4000: "ICQ", 4070: "Spotify", 4222: "NATS", 4369: "EPMD", 4443: "Pharos", 4500: "IPSec-NAT", 4505: "SaltStack",
        4506: "SaltStack", 4662: "eMule", 4672: "eMule-UDP", 4730: "Gearman", 4789: "VXLAN", 4848: "GlassFish",
        5000: "AirPlay", 5001: "Synology", 5004: "RTP", 5005: "RTP-Alt", 5009: "Apple-Util", 5050: "Yahoo-Msg", 5060: "SIP",
        5061: "SIP-TLS", 5190: "AIM", 5222: "XMPP", 5223: "APN", 5228: "GCM", 5229: "GCM", 5230: "GCM", 5269: "XMPP-S2S",
        5353: "mDNS", 5355: "LLMNR", 5432: "PostgreSQL", 5500: "VNC-Listen", 5601: "Kibana", 5672: "AMQP", 5683: "CoAP",
        5900: "VNC", 5938: "TeamViewer", 5984: "CouchDB", 5985: "WinRM", 5986: "WinRM-TLS",
        6000: "X11", 6379: "Redis", 6443: "K8s-API", 6514: "Syslog-TLS", 6660: "IRC", 6667: "IRC", 6697: "IRC-TLS",
        6881: "BitTorrent", 7000: "AirPlay", 7001: "Cassandra-SSL", 7070: "RealServer", 7199: "Cassandra-JMX",
        7443: "HTTPS-Alt", 7474: "Neo4j", 7687: "Neo4j-Bolt",
        8000: "HTTP-Dev", 8006: "Proxmox", 8008: "HTTP-Alt", 8080: "HTTP-Alt", 8081: "HTTP-Alt", 8088: "Splunk",
        8089: "Splunk-Mgmt", 8096: "Jellyfin", 8123: "HomeAssistant", 8200: "Vault", 8291: "MikroTik", 8333: "Bitcoin",
        8384: "Syncthing", 8443: "HTTPS-Alt", 8444: "HTTPS-Alt", 8500: "Consul", 8530: "WSUS", 8531: "WSUS-SSL",
        8761: "Eureka", 8834: "Nessus-UI", 8883: "MQTT/S", 8888: "Jupyter",
        9000: "PHP-FPM", 9001: "Tor", 9042: "Cassandra-CQL", 9043: "WebSphere", 9090: "Prometheus", 9092: "Kafka",
        9100: "JetDirect", 9200: "Elasticsearch", 9300: "ES-Transport", 9418: "Git", 9443: "HTTPS-Alt",
        10000: "Webmin", 10250: "Kubelet", 10255: "Kubelet-RO", 11211: "Memcached", 11214: "Memcached-SSL",
        15672: "RabbitMQ-Mgmt", 16379: "Redis-Cluster", 16992: "Intel-AMT", 17500: "Dropbox", 19132: "Minecraft-BE",
        25565: "Minecraft", 25575: "Minecraft-RCON", 27017: "MongoDB", 27018: "MongoDB-Shard", 27019: "MongoDB-Config",
        28015: "RethinkDB", 28017: "MongoDB-HTTP", 32400: "Plex", 33848: "Jenkins", 43594: "RuneScape", 47984: "Moonlight",
        51820: "WireGuard", 62078: "iPhone-Sync", 64738: "Mumble",
    ]
}
