"""Shared helpers for the ingest adapters.

Every adapter turns one wire format into canonical `Alert` records. They share
three things: asset resolution against the inventory, indicator extraction,
and the rule that an alert's *own* host and user are not indicators of
themselves (asset adjacency covers that; counting it twice would let one
signal masquerade as two).
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from functools import lru_cache

from src.config import settings
from src.enrichment.ioc import extract_indicators, merge_indicators
from src.models import AssetRef, Indicator, IndicatorType


@lru_cache(maxsize=1)
def asset_inventory() -> list[dict]:
    data = json.loads(settings.asset_inventory_path.read_text(encoding="utf-8"))
    return data["assets"]


@lru_cache(maxsize=1)
def _asset_index() -> tuple[dict[str, dict], dict[str, dict]]:
    by_name: dict[str, dict] = {}
    by_ip: dict[str, dict] = {}
    for asset in asset_inventory():
        by_name[asset["asset_id"].lower()] = asset
        if asset.get("hostname"):
            by_name[asset["hostname"].lower()] = asset
        if asset.get("ip"):
            by_ip[asset["ip"]] = asset
    return by_name, by_ip


def resolve_known_asset(name: str) -> dict | None:
    """Inventory record for a hostname / asset id, or None if unknown."""
    by_name, _ = _asset_index()
    return by_name.get(name.lower())


def _subnet_of(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


def resolve_asset(*, hostname: str | None = None, ip: str | None = None, user: str | None = None) -> AssetRef | None:
    """Build an AssetRef, joining the inventory where the host is known.

    Criticality is intentionally *not* populated here - the scorer joins it
    later. Ingestion should not know what an asset is worth.
    """
    by_name, by_ip = _asset_index()
    record = None
    if hostname and hostname.lower() in by_name:
        record = by_name[hostname.lower()]
    elif ip and ip in by_ip:
        record = by_ip[ip]
    if record:
        return AssetRef(
            asset_id=record["asset_id"],
            hostname=record.get("hostname"),
            ip=record.get("ip") or ip,
            subnet=record.get("subnet") or _subnet_of(ip),
            user_principal=user.lower() if user else None,
        )
    if not hostname and not ip and not user:
        return None
    asset_id = (hostname or ip or user or "UNKNOWN").upper()
    return AssetRef(
        asset_id=asset_id,
        hostname=hostname.lower() if hostname else None,
        ip=ip,
        subnet=_subnet_of(ip),
        user_principal=user.lower() if user else None,
    )


def parse_timestamp(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    ts = datetime.fromisoformat(value)
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def field_indicator(kind: IndicatorType, value: str | None, field: str) -> list[Indicator]:
    if not value:
        return []
    return [Indicator(type=kind, value=value, context=f"field {field}")]


def finalise_indicators(asset: AssetRef | None, *groups) -> list[Indicator]:
    """Merge indicator groups and drop the alert's own asset identity."""
    own: set[tuple[IndicatorType, str]] = set()
    if asset:
        if asset.ip:
            own.add((IndicatorType.IPV4, asset.ip.lower()))
        if asset.hostname:
            own.add((IndicatorType.HOSTNAME, asset.hostname.lower()))
        own.add((IndicatorType.HOSTNAME, asset.asset_id.lower()))
        if asset.user_principal:
            own.add((IndicatorType.USER, asset.user_principal.lower()))
    merged = merge_indicators(*groups)
    return [i for i in merged if (i.type, i.value) not in own]


def text_indicators(text: str) -> list[Indicator]:
    return extract_indicators(text)
