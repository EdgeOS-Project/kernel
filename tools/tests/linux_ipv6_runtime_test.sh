#!/bin/sh

set -u

failures=0

record_status() {
    name=$1
    status=$2
    echo "${name}=${status}"
    if [ "$status" -ne 0 ]; then
        failures=$((failures + 1))
    fi
}

echo "EDGE_IPV6_RUNTIME_BEGIN"

printf '0' >/proc/sys/net/ipv6/conf/all/disable_ipv6
record_status IPV6_ENABLE_STATUS $?
sleep 6

ipv6_dns_servers=${EDGE_IPV6_DNS_SERVERS:-"fec0::3 2606:4700:4700::1111"}
if [ -n "${EDGE_IPV6_RESOLVER:-}" ]; then
    echo "nameserver ${EDGE_IPV6_RESOLVER}" >/etc/resolv.conf
fi

ip -6 addr show
record_status IPV6_ADDR_STATUS $?
ip -6 route show
record_status IPV6_ROUTE_STATUS $?
ip -6 neigh show
record_status IPV6_NEIGH_STATUS $?

python3 - <<'PY'
import socket
import struct
import subprocess

interface = "eth0"
interface_index = socket.if_nametoindex(interface)
address_output = subprocess.check_output(
    ["ip", "-4", "-o", "addr", "show", "dev", interface], text=True
)
interface_address = socket.inet_aton(address_output.split()[3].split("/", 1)[0])

ipv4_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ipv4_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                       interface_address)
assert ipv4_socket.getsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, 4) == \
    interface_address
ipv4_socket.setsockopt(
    socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
    b"\0" * 4 + interface_address + struct.pack("i", interface_index)
)
assert ipv4_socket.getsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, 4) == \
    interface_address
ipv4_socket.close()

ipv6_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
ipv6_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                       struct.pack("i", interface_index))
assert ipv6_socket.getsockopt(socket.IPPROTO_IPV6,
                              socket.IPV6_MULTICAST_IF) == interface_index
ipv6_socket.close()
PY
record_status MULTICAST_INTERFACE_STATUS $?

python3 - <<'PY'
import socket
import struct

IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49)
IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50)
IPV6_RECVHOPLIMIT = getattr(socket, "IPV6_RECVHOPLIMIT", 51)
IPV6_HOPLIMIT = getattr(socket, "IPV6_HOPLIMIT", 52)
IPV6_RECVTCLASS = getattr(socket, "IPV6_RECVTCLASS", 66)
IPV6_TCLASS = getattr(socket, "IPV6_TCLASS", 67)

receiver4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver4.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
receiver4.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
receiver4.bind(("127.0.0.1", 0))
sender4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender4.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 37)
sender4.sendto(b"ipv4-ancillary", receiver4.getsockname())
payload4, control4, flags4, source4 = receiver4.recvmsg(128, 256)
assert payload4 == b"ipv4-ancillary"
assert flags4 == 0
packet_info4 = next(data for level, kind, data in control4
                    if level == socket.IPPROTO_IP and kind == IP_PKTINFO)
interface4, local4, destination4 = struct.unpack("i4s4s", packet_info4)
assert interface4 > 0
assert local4 == socket.inet_aton("127.0.0.1")
assert destination4 == socket.inet_aton("127.0.0.1")
ttl4 = next(struct.unpack("i", data)[0] for level, kind, data in control4
            if level == socket.IPPROTO_IP and kind == socket.IP_TTL)
assert ttl4 == 37
sender4.close()
receiver4.close()

receiver6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
receiver6.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
receiver6.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)
receiver6.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVTCLASS, 1)
receiver6.bind(("::1", 0))
sender6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sender6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 43)
sender6.setsockopt(socket.IPPROTO_IPV6, IPV6_TCLASS, 0xb8)
sender6.sendto(b"ipv6-ancillary", receiver6.getsockname())
payload6, control6, flags6, source6 = receiver6.recvmsg(128, 256)
assert payload6 == b"ipv6-ancillary"
assert flags6 == 0
packet_info6 = next(data for level, kind, data in control6
                    if level == socket.IPPROTO_IPV6 and kind == IPV6_PKTINFO)
destination6, interface6 = struct.unpack("16sI", packet_info6)
assert destination6 == socket.inet_pton(socket.AF_INET6, "::1")
assert interface6 > 0
hop_limit6 = next(struct.unpack("i", data)[0]
                  for level, kind, data in control6
                  if level == socket.IPPROTO_IPV6 and kind == IPV6_HOPLIMIT)
traffic_class6 = next(struct.unpack("i", data)[0]
                      for level, kind, data in control6
                      if level == socket.IPPROTO_IPV6 and kind == IPV6_TCLASS)
assert hop_limit6 == 43
assert traffic_class6 == 0xb8
sender6.close()
receiver6.close()
PY
record_status IP_ANCILLARY_STATUS $?

python3 - <<'PY'
import socket
import struct

IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49)
IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50)
IPV6_RECVHOPLIMIT = getattr(socket, "IPV6_RECVHOPLIMIT", 51)
IPV6_HOPLIMIT = getattr(socket, "IPV6_HOPLIMIT", 52)
IPV6_RECVTCLASS = getattr(socket, "IPV6_RECVTCLASS", 66)
IPV6_TCLASS = getattr(socket, "IPV6_TCLASS", 67)
loopback_index = socket.if_nametoindex("lo")
print("IP_SEND_LOOPBACK_INDEX", loopback_index)

receiver4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver4.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
receiver4.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
receiver4.bind(("127.0.0.1", 0))
sender4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
source4 = socket.inet_aton("127.0.0.1")
payload4_expected = b"ipv4-send-ancillary"
sent4 = sender4.sendmsg(
    [b"ipv4-", b"send-", b"ancillary"],
    [(socket.IPPROTO_IP, IP_PKTINFO,
      struct.pack("i4s4s", loopback_index, source4, b"\0" * 4)),
     (socket.IPPROTO_IP, socket.IP_TTL, struct.pack("i", 29)),
     (socket.IPPROTO_IP, socket.IP_TOS, struct.pack("i", 0x88))],
    0, receiver4.getsockname())
assert sent4 == len(payload4_expected)
payload4, control4, flags4, peer4 = receiver4.recvmsg(128, 256)
assert payload4 == payload4_expected
assert peer4[0] == "127.0.0.1"
ttl4 = next(struct.unpack("i", data)[0] for level, kind, data in control4
            if level == socket.IPPROTO_IP and kind == socket.IP_TTL)
assert ttl4 == 29
sender4.close()
receiver4.close()

receiver6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
receiver6.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
receiver6.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)
receiver6.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVTCLASS, 1)
receiver6.bind(("::1", 0))
sender6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
source6 = socket.inet_pton(socket.AF_INET6, "::1")
payload6_expected = b"ipv6-send-ancillary"
sent6 = sender6.sendmsg(
    [b"ipv6-", b"send-", b"ancillary"],
    [(socket.IPPROTO_IPV6, IPV6_PKTINFO,
      struct.pack("16sI", source6, loopback_index)),
     (socket.IPPROTO_IPV6, IPV6_HOPLIMIT, struct.pack("i", 35)),
     (socket.IPPROTO_IPV6, IPV6_TCLASS, struct.pack("i", 0xa0))],
    0, receiver6.getsockname())
assert sent6 == len(payload6_expected)
payload6, control6, flags6, peer6 = receiver6.recvmsg(128, 256)
assert payload6 == payload6_expected
assert peer6[0] == "::1"
hop6 = next(struct.unpack("i", data)[0] for level, kind, data in control6
            if level == socket.IPPROTO_IPV6 and kind == IPV6_HOPLIMIT)
tclass6 = next(struct.unpack("i", data)[0]
               for level, kind, data in control6
               if level == socket.IPPROTO_IPV6 and kind == IPV6_TCLASS)
assert hop6 == 35
assert tclass6 == 0xa0
sender6.close()
receiver6.close()
PY
record_status IP_SEND_ANCILLARY_STATUS $?

for path in \
    /proc/net/if_inet6 \
    /proc/net/ipv6_route \
    /proc/net/snmp6 \
    /proc/sys/net/ipv6/conf/all/disable_ipv6 \
    /proc/sys/net/ipv6/conf/all/forwarding \
    /proc/sys/net/ipv6/conf/all/accept_ra \
    /proc/sys/net/ipv6/conf/all/autoconf; do
    test -r "$path"
    record_status "READ_${path##*/}" $?
done

iteration=1
while [ "$iteration" -le 3 ]; do
    timeout 5 ping -6 -c 1 -W 2 fec0::2
    echo "PING6_${iteration}_STATUS=$?"
    iteration=$((iteration + 1))
done

udp6_status=1
for ipv6_dns_server in $ipv6_dns_servers; do
    iteration=1
    while [ "$iteration" -le 2 ]; do
        echo "UDP6_SERVER=${ipv6_dns_server} ATTEMPT=${iteration}"
        if timeout 8 python3 -c \
            "import socket; q=bytes.fromhex('123401000001000000000000076578616d706c6503636f6d0000010001'); s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.settimeout(5); s.sendto(q,('${ipv6_dns_server}',53)); d,_=s.recvfrom(2048); assert d[:2] == q[:2] and len(d) >= 12; print('UDP6_PASS', len(d))"; then
            udp6_status=0
            break 2
        fi
        iteration=$((iteration + 1))
        sleep 1
    done
done
record_status UDP6_STATUS "$udp6_status"

timeout 8 getent ahosts example.com
record_status DNS_STATUS $?

ipv6_https_code=$(timeout 20 curl -6 -sS -o /dev/null \
    -w '%{http_code}' https://example.com)
ipv6_https_result=$?
echo "IPV6_HTTPS_CODE=${ipv6_https_code}"
if [ "$ipv6_https_result" -eq 0 ] &&
   [ -n "$ipv6_https_code" ] && [ "$ipv6_https_code" != 000 ]; then
    ipv6_https_result=0
else
    ipv6_https_result=1
fi
record_status IPV6_HTTPS_STATUS "$ipv6_https_result"

ip -6 addr add 2001:db8:1::15/64 dev eth0
record_status STATIC6_ADD_STATUS $?
sleep 2
ip -6 addr show dev eth0 | grep -q '2001:db8:1::15'
record_status STATIC6_VISIBLE_STATUS $?
ip -6 addr del 2001:db8:1::15/64 dev eth0
record_status STATIC6_DEL_STATUS $?

printf '1' >/proc/sys/net/ipv6/conf/all/forwarding
record_status FORWARDING_WRITE_STATUS $?
forwarding=$(cat /proc/sys/net/ipv6/conf/all/forwarding)
test "$forwarding" = 1
record_status FORWARDING_READ_STATUS $?
printf '0' >/proc/sys/net/ipv6/conf/all/forwarding
printf '2' >/proc/sys/net/ipv6/conf/eth0/accept_ra
record_status ACCEPT_RA_ROUTER_MODE_WRITE_STATUS $?
accept_ra=$(cat /proc/sys/net/ipv6/conf/eth0/accept_ra)
test "$accept_ra" = 2
record_status ACCEPT_RA_ROUTER_MODE_READ_STATUS $?
printf '1' >/proc/sys/net/ipv6/conf/eth0/accept_ra

if [ -d /proc/sys/net/ipv6/conf/docker0 ]; then
    printf '1' >/proc/sys/net/ipv6/conf/docker0/disable_ipv6
    record_status DOCKER0_DISABLE_WRITE_STATUS $?
    docker0_disabled=$(cat /proc/sys/net/ipv6/conf/docker0/disable_ipv6)
    test "$docker0_disabled" = 1
    record_status DOCKER0_DISABLE_READ_STATUS $?
    eth0_disabled=$(cat /proc/sys/net/ipv6/conf/eth0/disable_ipv6)
    test "$eth0_disabled" = 0
    record_status ETH0_REMAINS_ENABLED_STATUS $?
    ip -6 addr show dev eth0 | grep -q 'scope global'
    record_status ETH0_GLOBAL_REMAINS_STATUS $?
    printf '0' >/proc/sys/net/ipv6/conf/docker0/disable_ipv6
fi

printf '1' >/proc/sys/net/ipv6/conf/eth0/disable_ipv6
record_status ETH0_DISABLE_STATUS $?
ip -6 route show >/dev/null
record_status EMPTY_ROUTE_DUMP_STATUS $?
printf '0' >/proc/sys/net/ipv6/conf/eth0/disable_ipv6
record_status ETH0_REENABLE_STATUS $?
sleep 6
ip -6 addr show dev eth0 | grep -q 'scope global'
record_status SLAAC_RESTORE_STATUS $?

echo "EDGE_IPV6_RUNTIME_FAILURES=${failures}"
if [ "$failures" -eq 0 ]; then
    echo "EDGE_IPV6_RUNTIME_PASS"
    exit 0
fi

echo "EDGE_IPV6_RUNTIME_FAIL"
exit 1
