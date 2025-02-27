"""Helper."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any, TypeAlias, TypeVar, cast

from hahomematic.const import IDENTIFIER_SEPARATOR, EventKey
from hahomematic.model.calculated import CalculatedDataPoint
from hahomematic.model.custom import CustomDataPoint
from hahomematic.model.data_point import EVENT_DATA_SCHEMA, CallbackDataPoint
from hahomematic.model.generic import GenericDataPoint
from hahomematic.model.hub import GenericProgramDataPoint, GenericSysvarDataPoint
import voluptuous as vol

from homeassistant.const import CONF_TYPE
from homeassistant.exceptions import HomeAssistantError

from .const import (
    CONF_SUBTYPE,
    EVENT_DEVICE_ID,
    EVENT_ERROR,
    EVENT_ERROR_VALUE,
    EVENT_IDENTIFIER,
    EVENT_MESSAGE,
    EVENT_NAME,
    EVENT_TITLE,
    EVENT_UNAVAILABLE,
)

# Union for entity types used as base class for data points
HmBaseDataPoint: TypeAlias = CalculatedDataPoint | CustomDataPoint | GenericDataPoint
# Generic base type used for data points in Homematic(IP) Local
HmGenericDataPoint = TypeVar("HmGenericDataPoint", bound=HmBaseDataPoint)
# Generic base type used for sysvar data points in Homematic(IP) Local
HmGenericProgramDataPoint = TypeVar("HmGenericProgramDataPoint", bound=GenericProgramDataPoint)
# Generic base type used for sysvar data points in Homematic(IP) Local
HmGenericSysvarDataPoint = TypeVar("HmGenericSysvarDataPoint", bound=GenericSysvarDataPoint)
T = TypeVar("T", bound=CallbackDataPoint)

BASE_EVENT_DATA_SCHEMA = EVENT_DATA_SCHEMA.extend(
    {
        vol.Required(EVENT_DEVICE_ID): str,
        vol.Required(EVENT_NAME): str,
    }
)
CLICK_EVENT_SCHEMA = BASE_EVENT_DATA_SCHEMA.extend(
    {
        vol.Required(CONF_TYPE): str,
        vol.Required(CONF_SUBTYPE): int,
        vol.Remove(str(EventKey.CHANNEL_NO)): int,
        vol.Remove(str(EventKey.PARAMETER)): str,
        vol.Remove(str(EventKey.VALUE)): vol.Any(bool, int),
    },
    extra=vol.ALLOW_EXTRA,
)
DEVICE_AVAILABILITY_EVENT_SCHEMA = BASE_EVENT_DATA_SCHEMA.extend(
    {
        vol.Required(EVENT_IDENTIFIER): str,
        vol.Required(EVENT_TITLE): str,
        vol.Required(EVENT_MESSAGE): str,
        vol.Required(EVENT_UNAVAILABLE): bool,
    },
    extra=vol.ALLOW_EXTRA,
)
DEVICE_ERROR_EVENT_SCHEMA = BASE_EVENT_DATA_SCHEMA.extend(
    {
        vol.Required(EVENT_IDENTIFIER): str,
        vol.Required(EVENT_TITLE): str,
        vol.Required(EVENT_MESSAGE): str,
        vol.Required(EVENT_ERROR_VALUE): vol.Any(bool, int),
        vol.Required(EVENT_ERROR): bool,
    },
    extra=vol.ALLOW_EXTRA,
)

_LOGGER = logging.getLogger(__name__)


def cleanup_click_event_data(event_data: dict[Any, Any]) -> dict[str, Any]:
    """Cleanup the click_event."""
    cleand_event_data = {str(key): value for key, value in event_data.items()}
    cleand_event_data.update(
        {
            CONF_TYPE: cleand_event_data[EventKey.PARAMETER].lower(),
            CONF_SUBTYPE: cleand_event_data[EventKey.CHANNEL_NO],
        }
    )
    del cleand_event_data[EventKey.PARAMETER]
    del cleand_event_data[EventKey.CHANNEL_NO]
    return cleand_event_data


def is_valid_event(event_data: Mapping[str, Any], schema: vol.Schema) -> bool:
    """Validate evenc_data against a given schema."""
    try:
        schema(event_data)
    except vol.Invalid as err:
        _LOGGER.debug("The EVENT could not be validated. %s, %s", err.path, err.msg)
        return False
    return True


def get_device_address_at_interface_from_identifiers(
    identifiers: set[tuple[str, str]],
) -> tuple[str, str] | None:
    """Get the device_address from device_info.identifiers."""
    for identifier in identifiers:
        if IDENTIFIER_SEPARATOR in identifier[1]:
            return cast(tuple[str, str], identifier[1].split(IDENTIFIER_SEPARATOR))
    return None


def get_data_point(data_point: T) -> T:
    """Return the homematic data point. Makes it mockable."""
    return data_point


class InvalidConfig(HomeAssistantError):
    """Error to indicate there is invalid config."""
