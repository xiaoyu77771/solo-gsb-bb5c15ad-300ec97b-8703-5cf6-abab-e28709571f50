"""FastAPI application exposing the CIDR policy normalization API."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .cidr import InvalidCIDRError, normalize_policy
from .schemas import (
    Counts,
    FamilyCount,
    FamilyNetworks,
    NormalizeRequest,
    NormalizeResponse,
)

app = FastAPI(
    title="CIDR Policy Normalization API",
    version="1.0.0",
    description=(
        "Computes allow - deny for IPv4 and IPv6, recursively splitting "
        "prefixes and merging complete adjacent sibling blocks into an "
        "equivalent, non-overlapping, minimal CIDR set."
    ),
)


@app.exception_handler(InvalidCIDRError)
async def invalid_cidr_handler(_: Request, exc: InvalidCIDRError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {
                    "type": "invalid_cidr",
                    "msg": exc.reason,
                    "index": exc.index,
                    "value": exc.value,
                }
            ]
        },
    )


@app.exception_handler(RequestValidationError)
async def request_validation_handler(
    _: Request, exc: RequestValidationError
) -> JSONResponse:
    # Preserve FastAPI's 422 contract for malformed request bodies.
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/normalize", response_model=NormalizeResponse, tags=["policy"])
async def normalize(payload: NormalizeRequest) -> NormalizeResponse:
    result = normalize_policy(payload.allow, payload.deny)
    return NormalizeResponse(
        ipv4=FamilyNetworks(networks=[str(n) for n in result.ipv4]),
        ipv6=FamilyNetworks(networks=[str(n) for n in result.ipv6]),
        counts=Counts(
            ipv4=FamilyCount(
                input=result.counts["ipv4"].input,
                unique=result.counts["ipv4"].unique,
                output=result.counts["ipv4"].output,
            ),
            ipv6=FamilyCount(
                input=result.counts["ipv6"].input,
                unique=result.counts["ipv6"].unique,
                output=result.counts["ipv6"].output,
            ),
        ),
    )
