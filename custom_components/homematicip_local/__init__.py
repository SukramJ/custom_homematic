"""Homematic(IP) local is a Python 3 module for Home Assistant and Homematic(IP) devices."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import logging
from typing import TypeAlias

from awesomeversion import AwesomeVersion
from hahomematic import __version__ as HAHM_VERSION
from hahomematic.const import (
    DEFAULT_SYS_SCAN_INTERVAL,
    DEFAULT_SYSVAR_SCAN_ENABLED,
    DEFAULT_UN_IGNORES,
)
from hahomematic.support import cleanup_cache_dirs, find_free_port

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, __version__ as HA_VERSION_STR
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity_registry import async_migrate_entries
from homeassistant.util.hass_dict import HassKey

from .const import (
    CONF_ADVANCED_CONFIG,
    CONF_ENABLE_SYSTEM_NOTIFICATIONS,
    CONF_PROGRAM_SCAN_ENABLED,
    CONF_SYS_SCAN_INTERVAL,
    CONF_SYSVAR_SCAN_ENABLED,
    CONF_UN_IGNORES,
    DEFAULT_ENABLE_SYSTEM_NOTIFICATIONS,
    DOMAIN,
    HMIP_LOCAL_HAHOMEMATIC_VERSION,
    HMIP_LOCAL_MIN_HA_VERSION,
    HMIP_LOCAL_PLATFORMS,
)
from .control_unit import ControlConfig, ControlUnit, get_storage_folder
from .services import async_get_loaded_config_entries, async_setup_services, async_unload_services
from .support import get_device_address_at_interface_from_identifiers

HA_VERSION = AwesomeVersion(HA_VERSION_STR)
HomematicConfigEntry: TypeAlias = ConfigEntry[ControlUnit]


@dataclass
class HomematicData:
    """Common data for shared homematic ip local data."""

    default_callback_port: int | None = None


HM_KEY: HassKey[HomematicData] = HassKey(DOMAIN)
_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: HomematicConfigEntry) -> bool:
    """Set up Homematic(IP) Local from a config entry."""
    if AwesomeVersion(HMIP_LOCAL_HAHOMEMATIC_VERSION) != AwesomeVersion(HAHM_VERSION):
        _LOGGER.error(
            "This release of Homematic(IP) Local requires hahomematic version %s, but found version %s. "
            "Looks like HA has a problem with dependency management. "
            "This is NOT an issue of the integration.",
            HMIP_LOCAL_HAHOMEMATIC_VERSION,
            HAHM_VERSION,
        )
        _LOGGER.warning("Homematic(IP) Local setup blocked")
        return False

    if AwesomeVersion(HMIP_LOCAL_MIN_HA_VERSION) >= HA_VERSION:
        _LOGGER.warning(
            "This release of Homematic(IP) Local requires HA version %s and above",
            HMIP_LOCAL_MIN_HA_VERSION,
        )
        _LOGGER.warning("Homematic(IP) Local setup blocked")
        return False

    hass.data.setdefault(HM_KEY, HomematicData())
    if (default_callback_port := hass.data[HM_KEY].default_callback_port) is None:
        default_callback_port = find_free_port()
        hass.data[HM_KEY].default_callback_port = default_callback_port

    control = ControlConfig(
        hass=hass,
        entry_id=entry.entry_id,
        data=entry.data,
        default_port=default_callback_port,
    ).create_control_unit()
    entry.runtime_data = control
    await hass.config_entries.async_forward_entry_setups(entry, HMIP_LOCAL_PLATFORMS)
    await control.start_central()
    await async_setup_services(hass)

    # Register on HA stop event to gracefully shutdown Homematic(IP) Local connection
    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, control.stop_central)
    entry.async_on_unload(entry.add_update_listener(update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: HomematicConfigEntry) -> bool:
    """Unload a config entry."""
    await async_unload_services(hass)
    if hasattr(entry, "runtime_data") and (control := entry.runtime_data):
        await control.stop_central()
    unload_ok = await hass.config_entries.async_unload_platforms(entry, HMIP_LOCAL_PLATFORMS)
    if len(async_get_loaded_config_entries(hass=hass)) == 0:
        del hass.data[HM_KEY]
    return unload_ok


async def async_remove_entry(hass: HomeAssistant, entry: HomematicConfigEntry) -> None:
    """Handle removal of an entry."""
    cleanup_cache_dirs(
        instance_name=entry.data["instance_name"], storage_folder=get_storage_folder(hass=hass)
    )


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: HomematicConfigEntry, device_entry: dr.DeviceEntry
) -> bool:
    """Remove a config entry from a device."""

    if (
        address_data := get_device_address_at_interface_from_identifiers(
            identifiers=device_entry.identifiers
        )
    ) is None:
        return False

    interface_id: str = address_data[0]
    device_address: str = address_data[1]

    if interface_id and device_address and (control_unit := entry.runtime_data):
        await control_unit.central.delete_device(
            interface_id=interface_id, device_address=device_address
        )
        _LOGGER.debug(
            "Called delete_device: %s, %s",
            interface_id,
            device_address,
        )
    return True


async def update_listener(hass: HomeAssistant, entry: HomematicConfigEntry) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_migrate_entry(hass: HomeAssistant, entry: HomematicConfigEntry) -> bool:
    """Migrate old entry."""
    _LOGGER.debug("Migrating from version %s", entry.version)

    if entry.version == 1:
        data = dict(entry.data)
        data.update({CONF_ENABLE_SYSTEM_NOTIFICATIONS: True})
        hass.config_entries.async_update_entry(entry, version=2, data=data)
    if entry.version == 2:

        @callback
        def update_entity_unique_id(entity_entry: er.RegistryEntry) -> dict[str, str] | None:
            """Update unique ID of entity entry."""
            if entity_entry.unique_id.startswith(f"{DOMAIN}_bidcos_wir"):
                return {
                    "new_unique_id": entity_entry.unique_id.replace(
                        f"{DOMAIN}_bidcos_wir",
                        f"{DOMAIN}_{entry.unique_id}_bidcos_wir",
                    )
                }
            return None

        await async_migrate_entries(hass, entry.entry_id, update_entity_unique_id)

        hass.config_entries.async_update_entry(entry, version=3)
    if entry.version == 3:
        data = dict(entry.data)
        data.update({CONF_UN_IGNORES: []})
        hass.config_entries.async_update_entry(entry, version=4, data=data)
    if entry.version == 4:
        data = dict(entry.data)

        advanced_config = {
            CONF_SYSVAR_SCAN_ENABLED: data.get(
                CONF_SYSVAR_SCAN_ENABLED, DEFAULT_SYSVAR_SCAN_ENABLED
            ),
            CONF_SYS_SCAN_INTERVAL: data.get(CONF_SYS_SCAN_INTERVAL, DEFAULT_SYS_SCAN_INTERVAL),
            CONF_ENABLE_SYSTEM_NOTIFICATIONS: data.get(
                CONF_ENABLE_SYSTEM_NOTIFICATIONS, DEFAULT_ENABLE_SYSTEM_NOTIFICATIONS
            ),
            CONF_UN_IGNORES: data.get(CONF_UN_IGNORES, DEFAULT_UN_IGNORES),
        }
        default_advanced_config = {
            CONF_SYSVAR_SCAN_ENABLED: DEFAULT_SYSVAR_SCAN_ENABLED,
            CONF_SYS_SCAN_INTERVAL: DEFAULT_SYS_SCAN_INTERVAL,
            CONF_ENABLE_SYSTEM_NOTIFICATIONS: DEFAULT_ENABLE_SYSTEM_NOTIFICATIONS,
            CONF_UN_IGNORES: DEFAULT_UN_IGNORES,
        }
        data[CONF_ADVANCED_CONFIG] = (
            {} if advanced_config == default_advanced_config else advanced_config
        )

        def del_param(name: str) -> None:
            with contextlib.suppress(Exception):
                del data[name]

        del_param(name=CONF_SYSVAR_SCAN_ENABLED)
        del_param(name=CONF_SYS_SCAN_INTERVAL)
        del_param(name=CONF_ENABLE_SYSTEM_NOTIFICATIONS)
        del_param(name=CONF_UN_IGNORES)

        cleanup_cache_dirs(
            instance_name=entry.data["instance_name"], storage_folder=get_storage_folder(hass=hass)
        )
        hass.config_entries.async_update_entry(entry, version=5, data=data)
    if entry.version == 5:
        data = dict(entry.data)
        cleanup_cache_dirs(
            instance_name=entry.data["instance_name"], storage_folder=get_storage_folder(hass=hass)
        )
        hass.config_entries.async_update_entry(entry, version=6, data=data)
    if entry.version == 6:
        data = dict(entry.data)
        if data.get(CONF_ADVANCED_CONFIG):
            data[CONF_ADVANCED_CONFIG][CONF_PROGRAM_SCAN_ENABLED] = data[CONF_ADVANCED_CONFIG][
                CONF_SYSVAR_SCAN_ENABLED
            ]
        hass.config_entries.async_update_entry(entry, version=7, data=data)
    _LOGGER.info("Migration to version %s successful", entry.version)
    return True
