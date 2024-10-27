"""Provides device actions for Homematic(IP) Local."""

from __future__ import annotations

from typing import Any

from hahomematic.const import Parameter
from hahomematic.model.generic import DpAction, DpButton
import voluptuous as vol

from homeassistant.const import CONF_DEVICE_ID, CONF_DOMAIN, CONF_TYPE
from homeassistant.core import Context, HomeAssistant
from homeassistant.helpers import device_registry as dr
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.typing import ConfigType, TemplateVarsType

from . import DOMAIN
from .const import CONF_SUBTYPE
from .control_unit import ControlUnit
from .support import get_device_address_at_interface_from_identifiers

ACTION_PARAMS = {Parameter.PRESS_LONG, Parameter.PRESS_SHORT}
ACTION_TYPES = {param.lower() for param in ACTION_PARAMS}

ACTION_SCHEMA = cv.DEVICE_ACTION_BASE_SCHEMA.extend(
    {
        vol.Required(CONF_TYPE): vol.In(ACTION_TYPES),
        vol.Required(CONF_SUBTYPE): int,
    }
)


async def async_get_actions(hass: HomeAssistant, device_id: str) -> list[dict[str, Any]]:
    """List device actions for Homematic(IP) Local devices."""

    device_registry = dr.async_get(hass)
    if (device := device_registry.async_get(device_id)) is None:
        return []
    if (
        data := get_device_address_at_interface_from_identifiers(identifiers=device.identifiers)
    ) is None:
        return []

    device_address, interface_id = data
    actions = []
    for entry_id in device.config_entries:
        if (
            entry := hass.config_entries.async_get_entry(entry_id=entry_id)
        ) and entry.domain == DOMAIN:
            control_unit: ControlUnit = entry.runtime_data
            if control_unit.central.has_client(interface_id=interface_id) is False:
                continue
            if hm_device := control_unit.central.get_device(address=device_address):
                for dp in hm_device.generic_data_points:
                    if not isinstance(dp, DpAction | DpButton):
                        continue
                    if dp.parameter not in ACTION_PARAMS:
                        continue

                    action = {
                        CONF_DOMAIN: DOMAIN,
                        CONF_DEVICE_ID: device_id,
                        CONF_TYPE: dp.parameter.lower(),
                        CONF_SUBTYPE: dp.channel.no,
                    }
                    actions.append(action)

    return actions


async def async_call_action_from_config(
    hass: HomeAssistant,
    config: ConfigType,
    variables: TemplateVarsType,
    context: Context | None,
) -> None:
    """Execute a device action."""
    device_id: str = config[CONF_DEVICE_ID]
    action_type: str = config[CONF_TYPE]
    action_subtype: int = config[CONF_SUBTYPE]

    device_registry = dr.async_get(hass)
    if (device := device_registry.async_get(device_id)) is None:
        return
    if (
        data := get_device_address_at_interface_from_identifiers(identifiers=device.identifiers)
    ) is None:
        return

    device_address, interface_id = data
    for entry_id in device.config_entries:
        if (
            entry := hass.config_entries.async_get_entry(entry_id=entry_id)
        ) and entry.domain == DOMAIN:
            control_unit: ControlUnit = entry.runtime_data
            if control_unit.central.has_client(interface_id=interface_id) is False:
                continue
            if hm_device := control_unit.central.get_device(address=device_address):
                for dp in hm_device.generic_data_points:
                    if not isinstance(dp, DpAction | DpButton):
                        continue
                    if dp.parameter == action_type.upper() and dp.channel.no == action_subtype:
                        await dp.send_value(True)
