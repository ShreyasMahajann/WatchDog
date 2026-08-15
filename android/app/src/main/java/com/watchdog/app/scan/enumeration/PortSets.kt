package com.watchdog.app.scan.enumeration

import com.watchdog.app.scan.ScanDepth

// Port sets for enumeration + the small liveness set used during host discovery.
// The top-100/top-1000 lists follow nmap's frequency ordering (most-common
// first) so short scans still hit the services that actually matter.

object PortSets {

    /** Ports probed to decide "is this host alive" during discovery. */
    val LIVENESS = intArrayOf(80, 443, 22, 445, 139, 8080, 53, 3389, 23, 21)

    /**
     * Ports worth an HTTP(S) probe even when they aren't the obvious 80/443 — many
     * IoT boxes, cameras, NAS units, and Apple AirPlay endpoints answer HTTP here,
     * so a Server header or page title can identify an otherwise-nameless device.
     */
    val WEB_LIKELY = setOf(
        80, 81, 443, 591, 2000, 2020, 3000, 5000, 7000, 8000, 8008, 8010, 8080, 8081,
        8085, 8088, 8090, 8443, 8888, 9000, 9090, 9200, 8834, 5601,
    )

    /** Guess a coarse service name from a well-known port (pre-fingerprint). */
    fun serviceHint(port: Int): String? = WELL_KNOWN[port]

    fun forDepth(depth: ScanDepth): IntArray = when (depth) {
        ScanDepth.TOP_100 -> TOP_100
        ScanDepth.TOP_1000 -> TOP_1000
        ScanDepth.FULL -> (1..65535).toList().toIntArray()
    }

    val TOP_100 = intArrayOf(
        7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139,
        143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
        631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
        1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
        5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008,
        8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
        49157,
    )

    // Top-1000 (nmap-frequency ordered, deduplicated). Trimmed representative
    // set covering the high-frequency long tail; extend from nmap-services if a
    // truly exhaustive list is wanted.
    val TOP_1000: IntArray = (
        TOP_100.toList() + listOf(
            1, 3, 4, 6, 9, 13, 17, 19, 24, 49, 70, 82, 83, 84, 85, 89, 90, 99, 100, 109, 125, 146,
            161, 163, 175, 211, 340, 366, 406, 416, 417, 425, 458, 464, 481, 497, 500, 512, 524,
            541, 555, 563, 593, 616, 617, 625, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714,
            720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 880, 888, 898, 900, 901,
            902, 903, 911, 912, 981, 987, 992, 999, 1000, 1001, 1002, 1007, 1009, 1030, 1080, 1099,
            1100, 1234, 1352, 1433, 1434, 1521, 1524, 1723, 1755, 1801, 1900, 2100, 2103, 2105,
            2107, 2222, 2380, 2381, 2601, 2604, 2638, 3050, 3260, 3268, 3269, 3283, 3372, 3689,
            3690, 3703, 3986, 4000, 4001, 4045, 4444, 4662, 4848, 5001, 5002, 5003, 5004, 5009,
            5030, 5222, 5269, 5353, 5357, 5400, 5555, 5601, 5672, 5900, 5985, 5986, 6379, 6543,
            6667, 6881, 6969, 7000, 7001, 7002, 7071, 7443, 7777, 8005, 8006, 8010, 8014, 8042,
            8069, 8083, 8085, 8086, 8087, 8088, 8090, 8091, 8093, 8140, 8200, 8222, 8333, 8500,
            8686, 8834, 8880, 8983, 9000, 9001, 9002, 9042, 9060, 9080, 9090, 9091, 9200, 9300,
            9443, 9500, 9800, 9917, 9943, 9944, 9968, 10001, 10010, 11211, 15672, 16992, 16993,
            18080, 20000, 27017, 27018, 27019, 28017, 49158, 49159, 49160, 50000, 50070, 54321,
            55553, 61616,
        )
        ).distinct().sorted().toIntArray()

    private val WELL_KNOWN = mapOf(
        21 to "ftp", 22 to "ssh", 23 to "telnet", 25 to "smtp", 53 to "dns",
        80 to "http", 88 to "kerberos", 110 to "pop3", 111 to "rpcbind", 135 to "msrpc",
        137 to "netbios-ns", 139 to "netbios-ssn", 143 to "imap", 161 to "snmp", 389 to "ldap",
        443 to "https", 445 to "microsoft-ds", 548 to "afp", 554 to "rtsp", 587 to "smtp",
        631 to "ipp", 873 to "rsync", 993 to "imaps", 995 to "pop3s", 1433 to "mssql",
        1521 to "oracle", 1900 to "ssdp", 2000 to "http", 3000 to "http", 3306 to "mysql",
        3389 to "rdp", 3689 to "daap", 5000 to "upnp", 5060 to "sip", 5353 to "mdns",
        5432 to "postgresql", 5555 to "adb", 5601 to "kibana", 5672 to "amqp", 5900 to "vnc",
        5985 to "winrm", 6379 to "redis", 6881 to "bittorrent", 7000 to "airplay",
        8000 to "http", 8009 to "ajp13", 8010 to "http", 8080 to "http", 8443 to "https",
        8888 to "http", 9042 to "cassandra", 9100 to "printer", 9200 to "elasticsearch",
        9300 to "elasticsearch", 11211 to "memcached", 15672 to "rabbitmq", 27017 to "mongodb",
        32400 to "plex", 49152 to "upnp", 61616 to "activemq",
    )
}
