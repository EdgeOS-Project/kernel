#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Runtime acceptance for shared Linux policy routing on EdgeOS.

set -eux

fail() {
    echo "EDGE_POLICY_ROUTING_FAIL: $*" >&2
    exit 1
}

cleanup() {
    ip -4 rule del priority 1000 2>/dev/null || true
    ip -6 rule del priority 1001 2>/dev/null || true
    ip -4 rule del priority 1002 2>/dev/null || true
    ip -4 rule del priority 1003 2>/dev/null || true
    ip -4 route flush table 100 2>/dev/null || true
    ip -6 route flush table 101 2>/dev/null || true
    ip -4 route flush table 102 2>/dev/null || true
    ip -4 route flush table 103 2>/dev/null || true
    ip nexthop del id 20 2>/dev/null || true
    ip nexthop del id 11 2>/dev/null || true
    ip nexthop del id 12 2>/dev/null || true
}

trap cleanup EXIT INT TERM
cleanup

ip -4 route add 198.51.100.0/24 via 10.0.2.2 dev eth0 \
    table 100 metric 25
ip -4 rule add from 192.0.2.0/24 fwmark 0x42/0xff \
    priority 1000 table 100

route4="$(ip -4 route show table 100)"
rule4="$(ip -4 rule show)"
printf '%s\n' "$route4" | grep -q '198.51.100.0/24' || \
    fail "IPv4 custom route is absent"
printf '%s\n' "$route4" | grep -q 'metric 25' || \
    fail "IPv4 route metric is absent"
printf '%s\n' "$rule4" | grep -q '^1000:.*from 192.0.2.0/24.*fwmark 0x42/0xff.*lookup 100' || \
    fail "IPv4 policy rule is absent"
ip -4 route get 198.51.100.25 from 192.0.2.44 mark 0x42 | \
    grep -q 'via 10.0.2.2.*dev eth0.*table 100' || \
    fail "IPv4 policy lookup did not select table 100"

ip -6 route add 2001:db8:100::/64 via fe80::2 dev eth0 \
    table 101 metric 30
ip -6 rule add from 2001:db8:200::/64 priority 1001 table 101

route6="$(ip -6 route show table 101)"
rule6="$(ip -6 rule show)"
printf '%s\n' "$route6" | grep -q '2001:db8:100::/64' || \
    fail "IPv6 custom route is absent"
printf '%s\n' "$route6" | grep -q 'metric 30' || \
    fail "IPv6 route metric is absent"
printf '%s\n' "$rule6" | grep -q '^1001:.*from 2001:db8:200::/64.*lookup 101' || \
    fail "IPv6 policy rule is absent"
ip -6 route get 2001:db8:100::25 from 2001:db8:200::44 | \
    grep -q 'via fe80::2.*dev eth0.*table 101' || \
    fail "IPv6 policy lookup did not select table 101"

ip -4 route add blackhole 203.0.113.0/24 table 102
ip -4 route show table 102 | grep -q '^blackhole 203.0.113.0/24' || \
    fail "blackhole route type is absent"
ip -4 route del blackhole 203.0.113.0/24 table 102

ip -4 route add 203.0.113.0/24 table 102 \
    nexthop via 10.0.2.2 dev eth0 weight 1 \
    nexthop via 10.0.2.3 dev eth0 weight 3
ip -4 rule add fwmark 0x43 priority 1002 table 102
multipath="$(ip -4 route show table 102)"
printf '%s\n' "$multipath" | grep -q 'nexthop via 10.0.2.2 dev eth0 weight 1' || \
    fail "first ECMP nexthop is absent"
printf '%s\n' "$multipath" | grep -q 'nexthop via 10.0.2.3 dev eth0 weight 3' || \
    fail "weighted ECMP nexthop is absent"
ip -4 route get 203.0.113.25 mark 0x43 | \
    grep -Eq 'via 10.0.2.(2|3).*dev eth0.*table 102' || \
    fail "ECMP lookup did not select a nexthop"

ip nexthop add id 11 via 10.0.2.2 dev eth0
ip nexthop add id 12 via 10.0.2.3 dev eth0
ip nexthop add id 20 group 11,1/12,3
ip -4 route add 198.19.0.0/24 nhid 20 table 103
ip -4 rule add fwmark 0x44 priority 1003 table 103
nexthops="$(ip -4 nexthop show)"
printf '%s\n' "$nexthops" | grep -q '^id 11 via 10.0.2.2 dev eth0' || \
    fail "first nexthop object is absent"
printf '%s\n' "$nexthops" | grep -q '^id 12 via 10.0.2.3 dev eth0' || \
    fail "second nexthop object is absent"
printf '%s\n' "$nexthops" | grep -Eq '^id 20 group 11(,1)?/12,3' || \
    fail "weighted nexthop group is absent"
ip -4 route show table 103 | grep -q '^198.19.0.0/24 nhid 20' || \
    fail "route does not retain its nexthop object"
ip -4 route get 198.19.0.25 mark 0x44 | \
    grep -Eq 'via 10.0.2.(2|3).*dev eth0.*table 103' || \
    fail "nexthop object route did not resolve"

echo "EDGE_POLICY_ROUTING_PASS"
