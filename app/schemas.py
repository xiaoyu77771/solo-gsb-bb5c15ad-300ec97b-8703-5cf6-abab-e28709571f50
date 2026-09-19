"""Request/response schemas for the normalization API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class NormalizeRequest(BaseModel):
    allow: list[str] = Field(
        default_factory=list,
        description="CIDR prefixes that are permitted.",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="CIDR prefixes that are denied and cut out of allow.",
    )


class FamilyNetworks(BaseModel):
    networks: list[str] = Field(
        description="Equivalent, non-overlapping, minimal CIDR prefixes.",
    )


class FamilyCount(BaseModel):
    input: int = Field(description="Raw number of allow entries in this family.")
    unique: int = Field(
        description="Allow entries left after deduplication in this family."
    )
    output: int = Field(description="Number of CIDR prefixes in the result.")


class Counts(BaseModel):
    ipv4: FamilyCount
    ipv6: FamilyCount


class NormalizeResponse(BaseModel):
    ipv4: FamilyNetworks
    ipv6: FamilyNetworks
    counts: Counts
