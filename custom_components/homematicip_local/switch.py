"""switch for Homematic(IP) Local."""

from __future__ import annotations

import logging
from typing import Any, Final

from hahomematic.const import DataPointCategory
from hahomematic.model.custom import CustomDpSwitch
from hahomematic.model.generic import DpSwitch
from hahomematic.model.hub import SysvarDpSwitch
import voluptuous as vol

from homeassistant.components.switch import SwitchEntity
from homeassistant.const import STATE_ON, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import HomematicConfigEntry
from .const import SERVICE_SWITCH_SET_ON_TIME
from .control_unit import ControlUnit, signal_new_data_point
from .generic_entity import HaHomematicGenericRestoreEntity, HaHomematicGenericSysvarEntity

_LOGGER = logging.getLogger(__name__)
ATTR_ON_TIME: Final = "on_time"
ATTR_CHANNEL_STATE: Final = "channel_state"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local switch platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_switch(data_points: tuple[CustomDpSwitch | DpSwitch, ...]) -> None:
        """Add switch from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_SWITCH: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicSwitch(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    @callback
    def async_add_hub_switch(data_points: tuple[SysvarDpSwitch, ...]) -> None:
        """Add sysvar switch from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_HUB_SWITCH: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicSysvarSwitch(control_unit=control_unit, data_point=data_point)
            for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.SWITCH
            ),
            target=async_add_switch,
        )
    )
    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.HUB_SWITCH
            ),
            target=async_add_hub_switch,
        )
    )

    async_add_switch(
        data_points=control_unit.get_new_data_points(
            data_point_type=CustomDpSwitch | DpSwitch,
        )
    )

    async_add_hub_switch(
        data_points=control_unit.get_new_hub_data_points(data_point_type=SysvarDpSwitch)
    )

    platform = entity_platform.async_get_current_platform()
    platform.async_register_entity_service(
        SERVICE_SWITCH_SET_ON_TIME,
        {
            vol.Required(ATTR_ON_TIME): vol.All(vol.Coerce(int), vol.Range(min=0, max=8580000)),
        },
        "async_set_on_time",
    )


class HaHomematicSwitch(HaHomematicGenericRestoreEntity[CustomDpSwitch | DpSwitch], SwitchEntity):
    """Representation of the HomematicIP switch entity."""

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes of the generic entity."""
        attributes = super().extra_state_attributes
        if isinstance(self._data_point, CustomDpSwitch) and (
            self._data_point.channel_value
            and self._data_point.value != self._data_point.channel_value
        ):
            attributes[ATTR_CHANNEL_STATE] = self._data_point.channel_value
        return attributes

    @property
    def is_on(self) -> bool | None:
        """Return true if switch is on."""
        if self._data_point.is_valid:
            return self._data_point.value is True
        if (
            self.is_restored
            and self._restored_state
            and (restored_state := self._restored_state.state)
            not in (
                STATE_UNKNOWN,
                STATE_UNAVAILABLE,
            )
        ):
            return restored_state == STATE_ON
        return None

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the switch on."""
        await self._data_point.turn_on()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the switch off."""
        await self._data_point.turn_off()

    async def async_set_on_time(self, on_time: float) -> None:
        """Set the on time of the light."""
        if isinstance(self._data_point, CustomDpSwitch):
            self._data_point.set_on_time(on_time=on_time)
        if isinstance(self._data_point, DpSwitch):
            await self._data_point.set_on_time(on_time=on_time)


class HaHomematicSysvarSwitch(HaHomematicGenericSysvarEntity[SysvarDpSwitch], SwitchEntity):
    """Representation of the HomematicIP hub switch entity."""

    @property
    def is_on(self) -> bool | None:
        """Return true if switch is on."""
        return self._data_point.value is True

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the switch on."""
        await self._data_point.send_variable(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the switch off."""
        await self._data_point.send_variable(False)
