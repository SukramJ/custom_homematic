"""Provides device triggers for Home Assistant Homematic(IP) Local."""

from __future__ import annotations

from hahomematic.const import CLICK_EVENTS, DataPointUsage
from hahomematic.model.event import ClickEvent
import voluptuous as vol

from homeassistant.components.device_automation import DEVICE_TRIGGER_BASE_SCHEMA
from homeassistant.components.homeassistant.triggers import event as event_trigger
from homeassistant.const import CONF_ADDRESS, CONF_DEVICE_ID, CONF_DOMAIN, CONF_PLATFORM, CONF_TYPE
from homeassistant.core import CALLBACK_TYPE, HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.trigger import TriggerActionType, TriggerInfo
from homeassistant.helpers.typing import ConfigType

from . import DOMAIN
from .const import CONF_EVENT_TYPE, CONF_INTERFACE_ID, CONF_SUBTYPE
from .control_unit import ControlUnit
from .support import cleanup_click_event_data, get_device_address_at_interface_from_identifiers

TRIGGER_TYPES = {param.lower() for param in CLICK_EVENTS}

TRIGGER_SCHEMA = DEVICE_TRIGGER_BASE_SCHEMA.extend(
    {
        vol.Required(CONF_INTERFACE_ID): str,
        vol.Required(CONF_ADDRESS): str,
        vol.Required(CONF_TYPE): vol.In(TRIGGER_TYPES),
        vol.Required(CONF_SUBTYPE): int,
        vol.Required(CONF_EVENT_TYPE): str,
    },
    extra=vol.REMOVE_EXTRA,
)


async def async_get_triggers(hass: HomeAssistant, device_id: str) -> list[dict[str, str]]:
    """List device triggers for Home Assistant Homematic(IP) Local devices."""
    device_registry = dr.async_get(hass)
    if (device := device_registry.async_get(device_id)) is None:
        return []
    if (
        data := get_device_address_at_interface_from_identifiers(identifiers=device.identifiers)
    ) is None:
        return []

    device_address, interface_id = data
    triggers = []
    for entry_id in device.config_entries:
        if (
            entry := hass.config_entries.async_get_entry(entry_id=entry_id)
        ) and entry.domain == DOMAIN:
            control_unit: ControlUnit = entry.runtime_data
            if control_unit.central.has_client(interface_id=interface_id) is False:
                continue
            if hm_device := control_unit.central.get_device(address=device_address):
                for action_event in hm_device.generic_events:
                    if not isinstance(action_event, ClickEvent):
                        continue

                    if action_event.usage == DataPointUsage.NO_CREATE:
                        continue

                    trigger = {
                        CONF_PLATFORM: "device",
                        CONF_DOMAIN: DOMAIN,
                        CONF_DEVICE_ID: device_id,
                        CONF_EVENT_TYPE: action_event.event_type.value,
                    }
                    trigger.update(
                        cleanup_click_event_data(event_data=action_event.get_event_data())
                    )
                    triggers.append(trigger)

    return triggers


async def async_attach_trigger(
    hass: HomeAssistant,
    config: ConfigType,
    action: TriggerActionType,
    trigger_info: TriggerInfo,
) -> CALLBACK_TYPE:
    """Listen for state changes based on configuration."""
    _event_data = {
        CONF_INTERFACE_ID: config[CONF_INTERFACE_ID],
        CONF_ADDRESS: config[CONF_ADDRESS],
        CONF_TYPE: config[CONF_TYPE],
        CONF_SUBTYPE: config[CONF_SUBTYPE],
    }

    event_config = {
        event_trigger.CONF_PLATFORM: "event",
        event_trigger.CONF_EVENT_TYPE: config[CONF_EVENT_TYPE],
        event_trigger.CONF_EVENT_DATA: _event_data,
    }

    event_config = event_trigger.TRIGGER_SCHEMA(event_config)
    return await event_trigger.async_attach_trigger(
        hass=hass,
        config=event_config,
        action=action,
        trigger_info=trigger_info,
        platform_type="device",
    )
