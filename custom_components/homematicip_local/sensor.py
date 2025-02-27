"""sensor for Homematic(IP) Local."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
import logging
from typing import Any, cast

from hahomematic.const import DEFAULT_MULTIPLIER, DataPointCategory, ParameterType, SysvarType
from hahomematic.model.generic import DpSensor
from hahomematic.model.hub import SysvarDpSensor

from homeassistant.components.sensor import RestoreSensor, SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType

from . import HomematicConfigEntry
from .const import HmEntityState
from .control_unit import ControlUnit, signal_new_data_point
from .entity_helpers import HmSensorEntityDescription
from .generic_entity import ATTR_VALUE_STATE, HaHomematicGenericEntity, HaHomematicGenericSysvarEntity

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local sensor platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_sensor(data_points: tuple[DpSensor, ...]) -> None:
        """Add sensor from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_SENSOR: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicSensor(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    @callback
    def async_add_hub_sensor(data_points: tuple[SysvarDpSensor, ...]) -> None:
        """Add sysvar sensor from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_HUB_SENSOR: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicSysvarSensor(control_unit=control_unit, data_point=data_point) for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(entry_id=entry.entry_id, platform=DataPointCategory.SENSOR),
            target=async_add_sensor,
        )
    )
    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(entry_id=entry.entry_id, platform=DataPointCategory.HUB_SENSOR),
            target=async_add_hub_sensor,
        )
    )

    async_add_sensor(data_points=control_unit.get_new_data_points(data_point_type=DpSensor))

    async_add_hub_sensor(data_points=control_unit.get_new_hub_data_points(data_point_type=SysvarDpSensor))


class HaHomematicSensor(HaHomematicGenericEntity[DpSensor], RestoreSensor):
    """Representation of the HomematicIP sensor entity."""

    entity_description: HmSensorEntityDescription
    _restored_native_value: Any = None

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: DpSensor,
    ) -> None:
        """Initialize the sensor entity."""
        super().__init__(
            control_unit=control_unit,
            data_point=data_point,
        )
        self._multiplier: float = (
            self.entity_description.multiplier
            if hasattr(self, "entity_description")
            and self.entity_description
            and self.entity_description.multiplier is not None
            else data_point.multiplier
        )
        if not hasattr(self, "entity_description") and data_point.unit:
            self._attr_native_unit_of_measurement = data_point.unit
        if self.device_class == SensorDeviceClass.ENUM:
            self._attr_options = [item.lower() for item in data_point.values] if data_point.values else None

    @property
    def native_value(self) -> StateType | date | datetime | Decimal:
        """Return the native value of the entity."""
        if self._data_point.is_valid:
            if (
                self._data_point.value is not None
                and self._data_point.hmtype in (ParameterType.FLOAT, ParameterType.INTEGER)
                and self._multiplier != DEFAULT_MULTIPLIER
            ):
                new_value = self._data_point.value * self._multiplier
                return int(new_value) if self._data_point.hmtype == ParameterType.INTEGER else new_value
            # Strings and enums with custom device class must be lowercase
            # to be translatable.
            if (
                self._data_point.value is not None
                and self.translation_key is not None
                and self._data_point.hmtype in (ParameterType.ENUM, ParameterType.STRING)
            ):
                return cast(StateType | date | datetime | Decimal, self._data_point.value.lower())
            return cast(StateType | date | datetime | Decimal, self._data_point.value)
        if self.is_restored:
            return cast(StateType | date | datetime | Decimal, self._restored_native_value)
        return None

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
        if not self._data_point.is_valid and (restored_sensor_data := await self.async_get_last_sensor_data()):
            self._restored_native_value = restored_sensor_data.native_value


class HaHomematicSysvarSensor(HaHomematicGenericSysvarEntity[SysvarDpSensor], SensorEntity):
    """Representation of the HomematicIP hub sensor entity."""

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: SysvarDpSensor,
    ) -> None:
        """Initialize the sensor entity."""
        super().__init__(control_unit=control_unit, data_point=data_point)
        if not hasattr(self, "entity_description"):
            if data_point.data_type == SysvarType.LIST:
                self._attr_options = list(data_point.values) if data_point.values else None
                self._attr_device_class = SensorDeviceClass.ENUM
            elif data_point.data_type in (
                SysvarType.FLOAT,
                SysvarType.INTEGER,
            ):
                self._attr_state_class = SensorStateClass.MEASUREMENT
                if unit := data_point.unit:
                    self._attr_native_unit_of_measurement = unit

    @property
    def native_value(self) -> StateType | date | datetime | Decimal:
        """Return the native value of the entity."""
        return self._data_point.value
