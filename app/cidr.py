"""CIDR policy normalization core.

Builds the set difference ``allow - deny`` separately for IPv4 and IPv6,
recursively splitting blocks where a deny prefix cuts through an allow
prefix. The result is the equivalent, non-overlapping, minimum-cardinality
set of CIDR prefixes: complete adjacent sibling prefixes are merged into
their parent.

This module only depends on the standard-library :mod:`ipaddress`.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import (
    IPv4Network,
    IPv6Network,
    collapse_addresses,
    ip_network,
)
from typing import Iterable, Union

IPNetwork = Union[IPv4Network, IPv6Network]


class InvalidCIDRError(ValueError):
    """Raised when an input entry is not a parseable CIDR/prefix."""

    def __init__(self, index: int, value: object, reason: str) -> None:
        self.index = index
        self.value = value
        self.reason = reason
        super().__init__(f"invalid CIDR at index {index!r}: {value!r} ({reason})")


def family_sort_key(network: IPNetwork) -> tuple[int, int, int]:
    """Stable ordering: address family, then network address, then prefix length."""
    return (network.version, int(network.network_address), network.prefixlen)


def parse_networks(values: Iterable[str]) -> list[IPNetwork]:
    """Parse CIDR strings into canonical networks, preserving input order.

    Duplicates are kept in the returned list (and counted later as raw
    input); callers use ``set()`` for deduplication. Host bits that happen
    to be set are normalized to the network address (e.g.
    ``10.0.0.5/24`` -> ``10.0.0.0/24``); anything unparseable raises
    :class:`InvalidCIDRError`.
    """
    networks: list[IPNetwork] = []
    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise InvalidCIDRError(index, value, "expected a string")
        try:
            network = ip_network(value.strip(), strict=False)
        except ValueError as exc:
            raise InvalidCIDRError(index, value, str(exc)) from None
        networks.append(network)
    return networks


def disjoint_union(networks: Iterable[IPNetwork]) -> list[IPNetwork]:
    """Return the canonical, minimum, non-overlapping union as a sorted list."""
    collapsed = collapse_addresses(networks)
    return sorted(collapsed, key=family_sort_key)


def exclude_networks(
    allowed: list[IPNetwork], denied: list[IPNetwork]
) -> list[IPNetwork]:
    """Compute ``allowed - denied`` by recursive prefix splitting.

    Both arguments must be disjoint, canonical unions (as produced by
    :func:`disjoint_union`) for a single address family. When a deny prefix
    cuts through an allow prefix, the allow prefix is recursively split into
    its children until each piece is fully inside or outside the deny set.
    """
    result: list[IPNetwork] = []

    for allow_net in allowed:
        surviving = exclude_from_network(allow_net, denied)
        result.extend(surviving)

    return sorted(result, key=family_sort_key)


def exclude_from_network(
    allow_net: IPNetwork, denied: list[IPNetwork]
) -> list[IPNetwork]:
    """Subtract ``denied`` from a single network via recursive splitting."""
    for deny_net in denied:
        # Different families can never intersect.
        if allow_net.version != deny_net.version:
            continue

        # Already disjoint: this deny prefix does not affect the network.
        if not allow_net.overlaps(deny_net):
            continue

        # The deny prefix fully contains this network: nothing survives.
        if deny_net.supernet_of(allow_net):
            return []

        # Overlapping CIDR blocks are always nested, so reaching here means
        # the deny prefix lies strictly inside the allow network and cuts
        # through it: recursively split into the two children.
        left, right = allow_net.subnets()
        return exclude_from_network(left, denied) + exclude_from_network(
            right, denied
        )

    return [allow_net]


def are_siblings(left: IPNetwork, right: IPNetwork) -> bool:
    """True iff ``left``/``right`` are the two complete adjacent children.

    They must share a non-zero prefix length and differ in exactly the bit
    that distinguishes the two halves of their parent. Inputs are assumed to
    be address-sorted, so ``left`` is the lower half.
    """
    if left.version != right.version:
        return False
    if left.prefixlen != right.prefixlen or left.prefixlen == 0:
        return False
    return (
        int(left.network_address) ^ int(right.network_address)
        == 1 << (left.max_prefixlen - left.prefixlen)
    )


def merge_siblings(networks: list[IPNetwork]) -> list[IPNetwork]:
    """Merge every pair of complete adjacent sibling prefixes into its parent.

    Merging repeats so that newly formed parents can merge in turn. The
    output is the minimum-cardinality representation of the union.
    """
    current = sorted(networks, key=family_sort_key)

    while True:
        merged_once = False
        next_round: list[IPNetwork] = []
        i = 0
        while i < len(current):
            if i + 1 < len(current) and are_siblings(current[i], current[i + 1]):
                parent = current[i].supernet(prefixlen_diff=1)
                next_round.append(parent)
                merged_once = True
                i += 2
            else:
                next_round.append(current[i])
                i += 1
        current = next_round
        if not merged_once:
            return sorted(current, key=family_sort_key)


@dataclass
class FamilyResult:
    """Normalization outcome for one address family."""

    networks: list[IPNetwork]
    input_count: int
    unique_count: int
    output_count: int


@dataclass
class FamilyCounts:
    """Input/dedup/output counters for one family."""

    input: int
    unique: int
    output: int


@dataclass
class PolicyResult:
    """Full normalization result across both families."""

    ipv4: list[IPNetwork]
    ipv6: list[IPNetwork]
    counts: dict[str, FamilyCounts]


def normalize_family(
    allow: Iterable[IPNetwork], deny: Iterable[IPNetwork]
) -> FamilyResult:
    """Normalize one address family: ``allow - deny``, minimized and sorted."""
    allow_list = list(allow)
    deny_list = list(deny)

    allow_union = disjoint_union(allow_list)
    deny_union = disjoint_union(deny_list)

    difference = exclude_networks(allow_union, deny_union)
    merged = merge_siblings(difference)

    return FamilyResult(
        networks=merged,
        input_count=len(allow_list),
        unique_count=len(set(allow_list)),
        output_count=len(merged),
    )


def normalize_policy(
    raw_allow: Iterable[str], raw_deny: Iterable[str]
) -> PolicyResult:
    """Parse raw allow/deny entries and normalize both address families.

    Raises :class:`InvalidCIDRError` for any unparseable entry.
    """
    allow = parse_networks(raw_allow)
    deny = parse_networks(raw_deny)

    allow_v4 = [n for n in allow if n.version == 4]
    allow_v6 = [n for n in allow if n.version == 6]
    deny_v4 = {n for n in deny if n.version == 4}
    deny_v6 = {n for n in deny if n.version == 6}

    result_v4 = normalize_family(allow_v4, deny_v4)
    result_v6 = normalize_family(allow_v6, deny_v6)

    counts = {
        "ipv4": FamilyCounts(
            input=result_v4.input_count,
            unique=result_v4.unique_count,
            output=result_v4.output_count,
        ),
        "ipv6": FamilyCounts(
            input=result_v6.input_count,
            unique=result_v6.unique_count,
            output=result_v6.output_count,
        ),
    }
    return PolicyResult(
        ipv4=result_v4.networks, ipv6=result_v6.networks, counts=counts
    )
