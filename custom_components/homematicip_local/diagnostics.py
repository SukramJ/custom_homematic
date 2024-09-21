"""Diagnostics support for Homematic(IP) Local."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from typing import Any

from hahomematic.central import CentralUnit
from hahomematic.const import CONF_PASSWORD, CONF_USERNAME, HmPlatform

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import HomematicConfigEntry
from .control_unit import ControlUnit

REDACT_CONFIG = {CONF_USERNAME, CONF_PASSWORD}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: HomematicConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    control_unit: ControlUnit = entry.runtime_data
    diag: dict[str, Any] = {"config": async_redact_data(entry.as_dict(), REDACT_CONFIG)}

    diag["platform_stats"] = get_entities_by_platform_stats(
        central=control_unit.central, registered=True
    )
    diag["devices"] = get_devices_per_type_stats(central=control_unit.central)
    diag["system_information"] = async_redact_data(
        asdict(control_unit.central.system_information), "serial"
    )

    return diag


def get_devices_per_type_stats(central: CentralUnit) -> tuple[str, ...]:
    """Return the central statistics for devices by type."""
    return tuple(sorted({d.model for d in central.devices}))


def get_entities_by_platform_stats(
    central: CentralUnit, registered: bool | None = None
) -> Mapping[HmPlatform, int]:
    """Return the central statistics for entities by platform."""
    _entities_by_platform: dict[HmPlatform, int] = {}
    for entity in (
        central.get_entities(registered=registered)
        + central.program_buttons
        + central.sysvar_entities
    ):
        if (platform := entity.platform) not in _entities_by_platform:
            _entities_by_platform[platform] = 0
        _entities_by_platform[platform] += 1
    return dict(sorted(_entities_by_platform.items()))
