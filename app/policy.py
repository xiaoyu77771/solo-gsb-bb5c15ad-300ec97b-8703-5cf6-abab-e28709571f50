"""CIDR allow/deny normalization built on the standard-library ``ipaddress``.

The core operation is a set difference ``allow - deny`` computed independently
for IPv4 and IPv6.  When a deny prefix cuts through an allow prefix the allow
network is recursively split into its two halves until every deny boundary is
aligned with a prefix.  Pieces are merged back only when they form two
complete, adjacent sibling prefixes (via :func:`ipaddress.collapse_addresses`),
which yields the equivalent, non-overlapping and minimum-cardinality CIDR set.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from typing import TypeAlias, Union

Network: TypeAlias = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_MAX_PREFIXLEN: dict[type, int] = {
    ipaddress.IPv4Network: 32,
    ipaddress.IPv6Network: 128,
}


def parse_network(value: object) -> Network:
    """Parse a strict CIDR string into an IPv4/IPv6 network object.

    ``strict=True`` rejects addresses with host bits set (e.g. ``10.0.0.1/24``).
    A bare address (``10.0.0.1``) is accepted as a host prefix (``/32`` or
    ``/128``).  Any invalid input raises :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise ValueError(f"CIDR must be a string, got {type(value).__name__}")
    return ipaddress.ip_network(value.strip(), strict=True)


def _sort_key(network: Network) -> tuple[bytes, int]:
    # ``packed`` orders network addresses as unsigned byte strings (works for
    # both families); prefix length is the secondary, stable key.
    return network.network_address.packed, network.prefixlen


def _diff(network: Network, deny: Sequence[Network]) -> list[Network]:
    """Subtract every deny network from one allow network by recursive splits.

    Caller guarantees that ``deny`` contains only strict subnets of
    ``network`` (equal/net-supernet cases are handled before calling this).
    Each recursion splits ``network`` into its two immediate sibling halves;
    a half that contains no deny prefix survives whole, while a half that does
    is split again — this is exactly the "cut through, split recursively"
    rule, and it produces maximal (minimum-count) aligned prefixes.
    """
    if not deny:
        return [network]

    # Defensive guard: a /32 or /128 has no strict subnets, so with a
    # correctly filtered ``deny`` this branch is unreachable.
    if network.prefixlen == _MAX_PREFIXLEN[type(network)]:
        return [network]

    left, right = network.subnets()

    result: list[Network] = []
    for half in (left, right):
        half_deny = [d for d in deny if d.subnet_of(half)]
        if any(d == half for d in half_deny):
            # The whole half is denied: it contributes nothing.
            continue
        if not half_deny:
            # No deny boundary touches the half: keep it whole.
            result.append(half)
        else:
            # Deny prefixes cut through the half: split again.
            result.extend(_diff(half, half_deny))
    return result


def _normalize_family(
    allow: Iterable[Network],
    deny: Iterable[Network],
    family: type,
) -> list[Network]:
    """Compute allow - deny for one address family, minimum and non-overlapping."""
    # Collapsing first removes duplicates/overlap and contained prefixes in
    # each input list, which also bounds the recursion work below.
    allow_nets = list(ipaddress.collapse_addresses(
        n for n in allow if isinstance(n, family)
    ))
    deny_nets = list(ipaddress.collapse_addresses(
        n for n in deny if isinstance(n, family)
    ))

    survivors: list[Network] = []
    for network in allow_nets:
        strict_deny: list[Network] = []
        swallowed = False
        for blocked in deny_nets:
            if network == blocked or network.subnet_of(blocked):
                # A deny prefix equal to or larger than the allow network
                # removes it completely.
                swallowed = True
                break
            if blocked.subnet_of(network):
                # A deny prefix cutting through the network: recurse.
                strict_deny.append(blocked)
        if swallowed:
            continue
        if not strict_deny:
            survivors.append(network)
        else:
            survivors.extend(_diff(network, strict_deny))

    # Sibling-only merge.  collapse_addresses merges a pair only when both are
    # complete adjacent halves of one common parent; merely adjacent prefixes
    # of unequal length are left untouched.
    merged = list(ipaddress.collapse_addresses(survivors))
    merged.sort(key=_sort_key)
    return merged


def _list_stats(raw: Sequence[str], networks: Sequence[Network]) -> dict:
    unique = set(networks)
    return {
        "input": len(raw),
        "unique": len(unique),
        "duplicates_removed": len(raw) - len(unique),
        "ipv4": sum(isinstance(n, ipaddress.IPv4Network) for n in unique),
        "ipv6": sum(isinstance(n, ipaddress.IPv6Network) for n in unique),
    }


def normalize(allow_raw: Sequence[str], deny_raw: Sequence[str]) -> dict:
    """Parse, validate and normalize allow/deny CIDR lists.

    Input strings are assumed to have been validated already (e.g. by the
    Pydantic schema); a malformed value raises :class:`ValueError`.
    """
    allow_nets = [parse_network(item) for item in allow_raw]
    deny_nets = [parse_network(item) for item in deny_raw]

    ipv4_result = _normalize_family(
        allow_nets, deny_nets, ipaddress.IPv4Network
    )
    ipv6_result = _normalize_family(
        allow_nets, deny_nets, ipaddress.IPv6Network
    )

    return {
        "ipv4": [str(network) for network in ipv4_result],
        "ipv6": [str(network) for network in ipv6_result],
        "stats": {
            "allow": _list_stats(allow_raw, allow_nets),
            "deny": _list_stats(deny_raw, deny_nets),
            "output": {
                "ipv4": len(ipv4_result),
                "ipv6": len(ipv6_result),
                "total": len(ipv4_result) + len(ipv6_result),
            },
        },
    }
