"""Property/differential test for the normalization core (stdlib only).

Compares our implementation against an address-space oracle on a small
IPv4 universe (/24), and asserts:
  * result covers exactly allow - deny (equivalence)
  * result networks are pairwise non-overlapping
  * result is minimal: no two networks are complete adjacent siblings
  * result is sorted by (network address, prefix length)
  * counts are reported correctly
Also checks IPv6, sorting and a few hand-computed cases.
"""

import random
from ipaddress import IPv4Network, ip_network

from app.cidr import (
    are_siblings,
    merge_siblings,
    normalize_policy,
)

BASE = IPv4Network("10.0.0.0/24")
SIZE = 256


def coverage(nets):
    bits = [0] * SIZE
    for net in nets:
        if net.version != 4:
            continue
        n = net
        if not n.subnet_of(BASE):
            continue
        start = int(n.network_address) - int(BASE.network_address)
        for i in range(start, start + n.num_addresses):
            bits[i] = 1
    return bits


def oracle(allow_strs, deny_strs):
    a = coverage(ip_network(s, strict=False) for s in allow_strs)
    d = coverage(ip_network(s, strict=False) for s in deny_strs)
    return [x and not y for x, y in zip(a, d)]


def random_prefix(rng):
    plen = rng.randint(24, 31)
    bitlen = 32 - plen
    start = rng.randint(0, (1 << (32 - 24)) - 1)
    start = (start >> bitlen) << bitlen  # align
    addr = f"10.0.0.{start}"
    return f"{addr}/{plen}"


def check_equivalence(allow, deny, label):
    result = normalize_policy(allow, deny)
    nets = result.ipv4
    got = coverage(nets)
    want = oracle(allow, deny)
    assert got == want, f"{label}: coverage mismatch\n{nets}"

    # pairwise disjoint
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            assert not nets[i].overlaps(nets[j]), f"{label}: overlap {nets[i]} {nets[j]}"

    # sorted
    keys = [(int(n.network_address), n.prefixlen) for n in nets]
    assert keys == sorted(keys), f"{label}: not sorted"

    # minimality: no complete adjacent sibling pair remains
    for i in range(len(nets) - 1):
        assert not are_siblings(nets[i], nets[i + 1]), (
            f"{label}: unmerged siblings {nets[i]} {nets[i+1]}"
        )
    return result


def main():
    rng = random.Random(20260919)
    for trial in range(4000):
        n_allow = rng.randint(0, 8)
        n_deny = rng.randint(0, 8)
        allow = [random_prefix(rng) for _ in range(n_allow)]
        deny = [random_prefix(rng) for _ in range(n_deny)]
        check_equivalence(allow, deny, f"trial {trial}")
    print("random differential trials: OK (4000)")

    # Hand case 1: clean cut
    r = normalize_policy(["10.0.0.0/24"], ["10.0.0.0/25"])
    assert [str(n) for n in r.ipv4] == ["10.0.0.128/25"], r.ipv4

    # Hand case 2: recursive cut of a /22 by a /24
    # /22 = 10.0.0.0/23 + 10.0.2.0/23
    # deny 10.0.0.0/24 removes one half of the first /23 -> 10.0.1.0/24
    r = normalize_policy(["10.0.0.0/22"], ["10.0.0.0/24"])
    assert [str(n) for n in r.ipv4] == ["10.0.1.0/24", "10.0.2.0/23"], r.ipv4

    # Sibling merge: deny middle /24 splits /23 but halves are NOT siblings
    r = normalize_policy(["10.0.0.0/24", "10.0.1.0/24"], [])
    assert [str(n) for n in r.ipv4] == ["10.0.0.0/23"], r.ipv4

    # Non-sibling neighbors stay apart
    r = normalize_policy(["10.0.0.0/25", "10.0.0.192/26"], [])
    assert [str(n) for n in r.ipv4] == ["10.0.0.0/25", "10.0.0.192/26"], r.ipv4

    # Full deny -> empty
    r = normalize_policy(["10.0.0.0/24"], ["10.0.0.0/24"])
    assert r.ipv4 == []
    assert r.counts["ipv4"].output == 0

    # Deny outside allow -> unchanged and collapsed
    r = normalize_policy(["10.0.0.0/24"], ["192.168.1.0/24"])
    assert [str(n) for n in r.ipv4] == ["10.0.0.0/24"]

    # Deduplication / counts (incl. host-bit normalization)
    r = normalize_policy(
        ["10.0.0.0/24", "10.0.0.5/24", "10.0.1.0/24"], []
    )
    assert r.counts["ipv4"].input == 3
    assert r.counts["ipv4"].unique == 2
    assert r.counts["ipv4"].output == 1
    assert [str(n) for n in r.ipv4] == ["10.0.0.0/23"]

    # IPv6 cut + merge
    r = normalize_policy(["2001:db8::/32"], ["2001:db8::/33"])
    assert [str(n) for n in r.ipv6] == ["2001:db8:8000::/33"], r.ipv6

    r = normalize_policy(["2001:db8::/33", "2001:db8:8000::/33"], [])
    assert [str(n) for n in r.ipv6] == ["2001:db8::/32"], r.ipv6

    # Cross-family sorting: ipv4 block precedes ipv6 in the payload
    r = normalize_policy(["2001:db8::/33", "10.0.0.0/25"], [])
    assert [str(n) for n in r.ipv4] == ["10.0.0.0/25"]
    assert [str(n) for n in r.ipv6] == ["2001:db8::/33"]

    # Stable sorting inside a family: network address first (non-siblings,
    # so they must not merge even though they are adjacent).
    r = normalize_policy(
        ["10.0.1.0/24", "10.0.0.0/25"], []
    )
    assert [str(n) for n in r.ipv4] == ["10.0.0.0/25", "10.0.1.0/24"], r.ipv4

    # Same network address can never occur in the canonical output (blocks
    # are aligned and disjoint), so ordering is unambiguous.

    # /32 deny recursion depth
    r = normalize_policy(["10.0.0.0/30"], ["10.0.0.1/32"])
    assert [str(n) for n in r.ipv4] == [
        "10.0.0.0/32",
        "10.0.0.2/31",
    ], r.ipv4

    # merge_siblings idempotency
    nets = [ip_network("10.0.0.0/25"), ip_network("10.0.0.128/25")]
    once = merge_siblings(nets)
    assert merge_siblings(once) == once == [ip_network("10.0.0.0/24")]

    # invalid CIDR
    from app.cidr import InvalidCIDRError

    for bad in ["not-a-cidr", "10.0.0.0/33", "999.0.0.0/8", "10.0.0.0/"]:
        try:
            normalize_policy([bad], [])
        except InvalidCIDRError as e:
            assert e.index == 0 and e.value == bad
        else:
            raise AssertionError(f"expected error for {bad!r}")

    # invalid entry in deny carries its own index
    try:
        normalize_policy(["10.0.0.0/24"], ["nope"])
    except InvalidCIDRError as e:
        assert e.index == 0 and e.value == "nope"
    else:
        raise AssertionError("expected deny index error")

    print("hand cases: OK")


if __name__ == "__main__":
    main()
