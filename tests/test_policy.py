"""Unit + property tests for the CIDR normalization core (stdlib only)."""

from __future__ import annotations

import ipaddress
import random

import pytest

from app.policy import _normalize_family, normalize, parse_network


def ref_subtract(allow, deny):
    """Reference implementation using ipaddress.address_exclude."""
    nets = list(ipaddress.collapse_addresses(allow))
    for d in ipaddress.collapse_addresses(deny):
        nxt = []
        for n in nets:
            if d == n or n.subnet_of(d):
                continue
            if d.subnet_of(n):
                nxt.extend(n.address_exclude(d))
            else:
                nxt.append(n)
        nets = nxt
    return set(ipaddress.collapse_addresses(nets))


def _strings(networks):
    return {str(n) for n in networks}


def test_simple_cut_through_ipv4():
    # 10.0.0.128/26 cuts 10.0.0.0/24 into two prefixes.
    result = normalize(["10.0.0.0/24"], ["10.0.0.128/26"])
    assert result["ipv4"] == ["10.0.0.0/25", "10.0.0.192/26"]


def test_sibling_halves_merge_back():
    # Deny a hole whose leftovers are the two halves; they must merge.
    result = normalize(["10.0.0.0/24"], ["10.0.0.128/25"])
    assert result["ipv4"] == ["10.0.0.0/25"]


def test_nested_split_minimal():
    # Two adjacent /26 denies in the lower half leave one /25 survivor...
    result = normalize(
        ["10.0.0.0/24"],
        ["10.0.0.0/26", "10.0.0.64/26"],
    )
    assert result["ipv4"] == ["10.0.0.128/25"]


def test_non_sibling_adjacent_prefixes_do_not_merge():
    # 10.0.0.0/25 and 10.0.0.128/26 are adjacent but unequal siblings of no
    # common pair; minimal canonical remainder of /24 minus 10.0.0.192/26 is
    # exactly these two pieces (10.0.0.0/24 \\ 10.0.0.192/26).
    result = normalize(["10.0.0.0/24"], ["10.0.0.192/26"])
    assert result["ipv4"] == ["10.0.0.0/25", "10.0.0.128/26"]


def test_deny_swallows_allow_entirely():
    result = normalize(["10.0.0.0/24"], ["10.0.0.0/16"])
    assert result["ipv4"] == []


def test_deny_equals_allow():
    result = normalize(["10.0.0.0/24"], ["10.0.0.0/24"])
    assert result["ipv4"] == []


def test_overlapping_allow_inputs_are_collapsed():
    result = normalize(["10.0.0.0/25", "10.0.0.128/25"], [])
    assert result["ipv4"] == ["10.0.0.0/24"]


def test_duplicates_are_deduplicated():
    result = normalize(
        ["10.0.0.0/24", "10.0.0.0/24", "10.0.0.1/32"],
        ["10.0.0.0/8", "10.0.0.0/8"],
    )
    stats = result["stats"]
    assert stats["allow"] == {"input": 3, "unique": 2, "duplicates_removed": 1,
                              "ipv4": 2, "ipv6": 0}
    assert stats["deny"] == {"input": 2, "unique": 1, "duplicates_removed": 1,
                             "ipv4": 1, "ipv6": 0}
    assert stats["output"] == {"ipv4": 0, "ipv6": 0, "total": 0}


def test_mixed_families_are_independent():
    result = normalize(
        ["10.0.0.0/24", "2001:db8::/32"],
        ["10.0.0.128/25", "2001:db8:1::/48"],
    )
    assert result["ipv4"] == ["10.0.0.0/25"]
    assert result["ipv6"] == ["2001:db8::/48", "2001:db8:2::/47",
                              "2001:db8:4::/46", "2001:db8:8::/45",
                              "2001:db8:10::/44", "2001:db8:20::/43",
                              "2001:db8:40::/42", "2001:db8:80::/41",
                              "2001:db8:100::/40", "2001:db8:200::/39",
                              "2001:db8:400::/38", "2001:db8:800::/37",
                              "2001:db8:1000::/36", "2001:db8:2000::/35",
                              "2001:db8:4000::/34", "2001:db8:8000::/33"]


def test_sorting_is_stable_by_network_then_prefixlen():
    result = normalize(
        ["192.0.2.0/24", "10.0.0.0/8", "172.16.0.0/12"],
        [],
    )
    assert result["ipv4"] == ["10.0.0.0/8", "172.16.0.0/12", "192.0.2.0/24"]


def test_bare_address_means_host_prefix():
    result = normalize(["10.0.0.1", "::1"], [])
    assert result["ipv4"] == ["10.0.0.1/32"]
    assert result["ipv6"] == ["::1/128"]


def test_host_bits_rejected():
    with pytest.raises(ValueError):
        parse_network("10.0.0.1/24")
    with pytest.raises(ValueError):
        parse_network("2001:db8::1/32")


def test_garbage_rejected():
    for bad in ["not-a-cidr", "10.0.0.0/33", "999.0.0.0/8", "", "10.0.0.0/"]:
        with pytest.raises(ValueError):
            parse_network(bad)


def test_host_prefix_subtraction():
    result = normalize(["10.0.0.0/30"], ["10.0.0.1/32", "10.0.0.2/32"])
    assert result["ipv4"] == ["10.0.0.0/32", "10.0.0.3/32"]


def test_output_is_non_overlapping_and_minimal():
    result = normalize(
        ["10.0.0.0/23", "10.0.2.0/24", "192.168.0.0/16"],
        ["10.0.1.0/24", "192.168.255.0/24", "10.0.0.128/25"],
    )
    nets = [ipaddress.ip_network(s) for s in result["ipv4"]]
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b)
    # No pair of complete sibling prefixes may remain (they would be merged).
    for i, a in enumerate(nets):
        if a.prefixlen == 0:
            continue
        supernet = a.supernet()
        siblings = [n for n in nets if n != a and n.subnet_of(supernet)
                    and n.prefixlen == a.prefixlen]
        # If both halves of the supernet are present, collapse would have
        # merged them, so at most a alone sits directly under that supernet.
        assert not (siblings and set(supernet.subnets()) <= set(nets))


@pytest.mark.parametrize("seed", range(64))
def test_matches_ipaddress_reference_ipv4(seed):
    rng = random.Random(seed)
    base = ipaddress.IPv4Address(0x0A000000)  # 10.0.0.0
    allow, deny = [], []
    for _ in range(rng.randint(1, 12)):
        shift = rng.randint(0, 20)
        addr = int(base) + (rng.getrandbits(shift) << (24 - shift) if shift else 0)
        allow.append(ipaddress.IPv4Network((addr, rng.randint(8, 32)), strict=False))
    for _ in range(rng.randint(0, 12)):
        shift = rng.randint(0, 20)
        addr = int(base) + (rng.getrandbits(shift) << (24 - shift) if shift else 0)
        deny.append(ipaddress.IPv4Network((addr, rng.randint(8, 32)), strict=False))

    expected = ref_subtract(allow, deny)
    actual = set(_normalize_family(allow, deny, ipaddress.IPv4Network))
    assert actual == expected


@pytest.mark.parametrize("seed", range(32))
def test_matches_ipaddress_reference_ipv6(seed):
    rng = random.Random(1000 + seed)
    base = int(ipaddress.IPv6Address("2001:db8::"))

    def random_net():
        # Pick a host part within the 2001:db8::/32 block so the address can
        # never overflow 2**128, then mask it to the chosen prefix length.
        host = rng.randrange(2 ** 96)
        prefixlen = rng.randint(32, 120)
        addr = (base | host) & (~((1 << (128 - prefixlen)) - 1))
        return ipaddress.IPv6Network((addr, prefixlen), strict=False)

    allow = [random_net() for _ in range(rng.randint(1, 8))]
    deny = [random_net() for _ in range(rng.randint(0, 8))]

    expected = ref_subtract(allow, deny)
    actual = set(_normalize_family(allow, deny, ipaddress.IPv6Network))
    assert actual == expected
