"""Describe Homematic(IP) Local logbook events."""

from __future__ import annotations

from collections.abc import Callable

from hahomematic.const import EVENT_PARAMETER, EventType

from homeassistant.components.logbook import LOGBOOK_ENTRY_MESSAGE, LOGBOOK_ENTRY_NAME
from homeassistant.core import Event, HomeAssistant, callback

from .const import DOMAIN as HMIP_DOMAIN, EVENT_ERROR, EVENT_ERROR_VALUE, EVENT_NAME
from .support import DEVICE_ERROR_EVENT_SCHEMA, is_valid_event


@callback
def async_describe_events(
    _hass: HomeAssistant,
    async_describe_event: Callable[[str, str, Callable[[Event], dict[str, str]]], None],
) -> None:
    """Describe logbook events."""

    @callback
    def async_describe_homematic_device_error_event(event: Event) -> dict[str, str]:
        """Describe Homematic(IP) Local logbook device error event."""
        if not is_valid_event(event_data=event.data, schema=DEVICE_ERROR_EVENT_SCHEMA):
            return {}
        error_name = event.data[EVENT_PARAMETER].replace("_", " ").title()
        error_value = event.data[EVENT_ERROR_VALUE]
        is_error = event.data[EVENT_ERROR]
        error_message = (
            f"{error_name} {error_value} occurred" if is_error else f"{error_name} resolved"
        )

        return {
            LOGBOOK_ENTRY_NAME: event.data[EVENT_NAME],
            LOGBOOK_ENTRY_MESSAGE: error_message,
        }

    async_describe_event(
        HMIP_DOMAIN,
        EventType.DEVICE_ERROR.value,
        async_describe_homematic_device_error_event,
    )
