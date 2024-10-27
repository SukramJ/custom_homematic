"""binary_sensor for Homematic(IP) Local."""

from __future__ import annotations

import logging

from hahomematic.const import DataPointCategory
from hahomematic.model.generic import DpBinarySensor
from hahomematic.model.hub import SysvarDpBinarySensor

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.const import STATE_ON, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import HomematicConfigEntry
from .control_unit import ControlUnit, signal_new_data_point
from .generic_entity import HaHomematicGenericRestoreEntity, HaHomematicGenericSysvarEntity

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local binary_sensor platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_binary_sensor(data_points: tuple[DpBinarySensor, ...]) -> None:
        """Add binary_sensor from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_BINARY_SENSOR: Adding %i data points", len(data_points))
        if entities := [
            HaHomematicBinarySensor(control_unit=control_unit, data_point=data_point)
            for data_point in data_points
        ]:
            async_add_entities(entities)

    @callback
    def async_add_hub_binary_sensor(data_points: tuple[SysvarDpBinarySensor, ...]) -> None:
        """Add sysvar binary sensor from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_HUB_BINARY_SENSOR: Adding %i data points", len(data_points))
        if entities := [
            HaHomematicSysvarBinarySensor(control_unit=control_unit, data_point=data_point)
            for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.BINARY_SENSOR
            ),
            target=async_add_binary_sensor,
        )
    )
    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(entry.entry_id, DataPointCategory.HUB_BINARY_SENSOR),
            target=async_add_hub_binary_sensor,
        )
    )

    async_add_binary_sensor(
        data_points=control_unit.get_new_data_points(data_point_type=DpBinarySensor)
    )

    async_add_hub_binary_sensor(
        data_points=control_unit.get_new_hub_data_points(data_point_type=SysvarDpBinarySensor)
    )


class HaHomematicBinarySensor(HaHomematicGenericRestoreEntity[DpBinarySensor], BinarySensorEntity):
    """Representation of the Homematic(IP) Local binary sensor."""

    @property
    def is_on(self) -> bool | None:
        """Return true if sensor is active."""
        if self._data_point.is_valid:
            return self._data_point.value
        if (
            self.is_restored
            and self._restored_state
            and (restored_state := self._restored_state.state)
            not in (STATE_UNKNOWN, STATE_UNAVAILABLE)
        ):
            return restored_state == STATE_ON
        return self._data_point.default  # type: ignore[no-any-return]


class HaHomematicSysvarBinarySensor(
    HaHomematicGenericSysvarEntity[SysvarDpBinarySensor], BinarySensorEntity
):
    """Representation of the HomematicIP hub binary_sensor entity."""

    @property
    def is_on(self) -> bool | None:
        """Return the native value of the entity."""
        return bool(self._data_point.value)
