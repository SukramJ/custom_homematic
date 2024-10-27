"""number for Homematic(IP) Local."""

from __future__ import annotations

import logging
from typing import Any

from hahomematic.const import DataPointCategory, SysvarType
from hahomematic.model.generic import BaseDpNumber
from hahomematic.model.hub import SysvarDpNumber

from homeassistant.components.number import NumberEntity, NumberMode, RestoreNumber
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import HomematicConfigEntry
from .const import HmEntityState
from .control_unit import ControlUnit, signal_new_data_point
from .entity_helpers import HmNumberEntityDescription
from .generic_entity import (
    ATTR_VALUE_STATE,
    HaHomematicGenericEntity,
    HaHomematicGenericSysvarEntity,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local number platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_number(data_points: tuple[BaseDpNumber, ...]) -> None:
        """Add number from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_NUMBER: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicNumber(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    @callback
    def async_add_hub_number(data_points: tuple[SysvarDpNumber, ...]) -> None:
        """Add sysvar number from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_HUB_NUMBER: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicSysvarNumber(control_unit=control_unit, data_point=data_point)
            for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.NUMBER
            ),
            target=async_add_number,
        )
    )

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.HUB_NUMBER
            ),
            target=async_add_hub_number,
        )
    )

    async_add_number(data_points=control_unit.get_new_data_points(data_point_type=BaseDpNumber))

    async_add_hub_number(
        data_points=control_unit.get_new_hub_data_points(data_point_type=SysvarDpNumber)
    )


class HaHomematicNumber(HaHomematicGenericEntity[BaseDpNumber], RestoreNumber):
    """Representation of the HomematicIP number entity."""

    entity_description: HmNumberEntityDescription
    _attr_entity_category = EntityCategory.CONFIG
    _attr_mode = NumberMode.BOX
    _restored_native_value: float | None = None

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: BaseDpNumber,
    ) -> None:
        """Initialize the number entity."""
        super().__init__(
            control_unit=control_unit,
            data_point=data_point,
        )
        self._multiplier: int = (
            self.entity_description.multiplier
            if hasattr(self, "entity_description")
            and self.entity_description
            and self.entity_description.multiplier is not None
            else data_point.multiplier
        )
        self._attr_native_min_value = data_point.min * self._multiplier
        self._attr_native_max_value = data_point.max * self._multiplier
        self._attr_native_step = 1.0 if data_point.hmtype == "INTEGER" else 0.01 * self._multiplier
        if not hasattr(self, "entity_description") and data_point.unit:
            self._attr_native_unit_of_measurement = data_point.unit

    @property
    def native_value(self) -> float | None:
        """Return the current value."""
        if self._data_point.is_valid and self._data_point.value is not None:
            return float(self._data_point.value * self._multiplier)
        if self.is_restored:
            return self._restored_native_value
        return None

    async def async_set_native_value(self, value: float) -> None:
        """Update the current value."""
        await self._data_point.send_value(value / self._multiplier)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes of the generic entity."""
        attributes = super().extra_state_attributes
        if self.is_restored:
            attributes[ATTR_VALUE_STATE] = HmEntityState.RESTORED
        return attributes

    @property
    def is_restored(self) -> bool:
        """Return if the state is restored."""
        return not self._data_point.is_valid and self._restored_native_value is not None

    async def async_added_to_hass(self) -> None:
        """Check, if state needs to be restored."""
        await super().async_added_to_hass()
        if not self._data_point.is_valid and (
            restored_sensor_data := await self.async_get_last_number_data()
        ):
            self._restored_native_value = restored_sensor_data.native_value


class HaHomematicSysvarNumber(HaHomematicGenericSysvarEntity[SysvarDpNumber], NumberEntity):
    """Representation of the HomematicIP hub number entity."""

    _attr_mode = NumberMode.BOX

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: SysvarDpNumber,
    ) -> None:
        """Initialize the number entity."""
        super().__init__(control_unit=control_unit, data_point=data_point)
        if data_point.min:
            self._attr_native_min_value = float(data_point.min)
        if data_point.max:
            self._attr_native_max_value = float(data_point.max)
        if data_point.unit:
            self._attr_native_unit_of_measurement = data_point.unit
        elif data_point.data_type in (
            SysvarType.FLOAT,
            SysvarType.INTEGER,
        ):
            self._attr_native_unit_of_measurement = " "

    @property
    def native_value(self) -> float | None:
        """Return the current value."""
        if (value := self._data_point.value) is not None and isinstance(value, (int, float)):
            return float(value)
        return None

    async def async_set_native_value(self, value: float) -> None:
        """Update the current value."""
        await self._data_point.send_variable(value)
