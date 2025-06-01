"""valve for Homematic(IP) Local."""

from __future__ import annotations

import logging
from typing import Any, Final

from hahomematic.const import DataPointCategory
from hahomematic.model.custom import CustomDpIpIrrigationValve
import voluptuous as vol

from homeassistant.components.valve import ValveEntity, ValveEntityFeature
from homeassistant.const import STATE_CLOSED, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import HomematicConfigEntry
from .const import HmipLocalServices
from .control_unit import ControlUnit, signal_new_data_point
from .generic_entity import HaHomematicGenericRestoreEntity

_LOGGER = logging.getLogger(__name__)
ATTR_ON_TIME: Final = "on_time"
ATTR_CHANNEL_STATE: Final = "channel_state"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local valve platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_valve(data_points: tuple[CustomDpIpIrrigationValve, ...]) -> None:
        """Add valve from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_VALVE: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicValve(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(entry_id=entry.entry_id, platform=DataPointCategory.VALVE),
            target=async_add_valve,
        )
    )

    async_add_valve(
        data_points=control_unit.get_new_data_points(
            data_point_type=CustomDpIpIrrigationValve,
        )
    )

    platform = entity_platform.async_get_current_platform()
    platform.async_register_entity_service(
        HmipLocalServices.VALVE_SET_ON_TIME,
        {
            vol.Required(ATTR_ON_TIME): vol.All(vol.Coerce(int), vol.Range(min=-1, max=8580000)),
        },
        "async_set_on_time",
    )


class HaHomematicValve(HaHomematicGenericRestoreEntity[CustomDpIpIrrigationValve], ValveEntity):
    """Representation of the HomematicIP valve entity."""

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes of the generic entity."""
        attributes = super().extra_state_attributes
        if isinstance(self._data_point, CustomDpIpIrrigationValve) and (
            self._data_point.channel_value and self._data_point.value != self._data_point.channel_value
        ):
            attributes[ATTR_CHANNEL_STATE] = self._data_point.channel_value
        return attributes

    @property
    def is_closed(self) -> bool | None:
        """Return if the valve is closed or not."""
        if self._data_point.is_valid:
            return self._data_point.value is False
        if (
            self.is_restored
            and self._restored_state
            and (restored_state := self._restored_state.state)
            not in (
                STATE_UNKNOWN,
                STATE_UNAVAILABLE,
            )
        ):
            return restored_state == STATE_CLOSED
        return None

    @property
    def reports_position(self) -> bool:
        """Return True if entity reports position, False otherwise."""
        return False

    @property
    def supported_features(self) -> ValveEntityFeature:
        """Return the list of supported features."""
        return ValveEntityFeature.OPEN | ValveEntityFeature.CLOSE

    async def async_open_valve(self) -> None:
        """Open the valve."""
        await self._data_point.open()

    async def async_close_valve(self) -> None:
        """Close the valve."""
        await self._data_point.close()

    async def async_set_on_time(self, on_time: float) -> None:
        """Set the on time of the light."""
        self._data_point.set_timer_on_time(on_time=on_time)
