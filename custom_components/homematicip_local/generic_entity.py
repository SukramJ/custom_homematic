"""Generic entity for the HomematicIP Cloud component."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any, Final, Generic

from hahomematic.const import CALLBACK_TYPE, CallSource
from hahomematic.model.custom import CustomDataPoint
from hahomematic.model.data_point import CallbackDataPoint
from hahomematic.model.generic import GenericDataPoint
from hahomematic.model.hub import GenericHubDataPoint, GenericSysvarDataPoint

from homeassistant.core import State, callback
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.typing import UndefinedType

from .const import DOMAIN, HmEntityState
from .control_unit import ControlUnit
from .entity_helpers import get_entity_description
from .support import HmGenericDataPoint, HmGenericSysvarDataPoint, get_data_point

_LOGGER = logging.getLogger(__name__)
ATTR_ADDRESS: Final = "address"
ATTR_FUNCTION: Final = "function"
ATTR_INTERFACE_ID: Final = "interface_id"
ATTR_MODEL: Final = "model"
ATTR_NAME: Final = "name"
ATTR_PARAMETER: Final = "parameter"
ATTR_VALUE_STATE: Final = "value_state"


class HaHomematicGenericEntity(Generic[HmGenericDataPoint], Entity):
    """Representation of the HomematicIP generic entity."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    NO_RECORED_ATTRIBUTES = {
        ATTR_ADDRESS,
        ATTR_FUNCTION,
        ATTR_INTERFACE_ID,
        ATTR_MODEL,
        ATTR_PARAMETER,
        ATTR_VALUE_STATE,
    }

    _unrecorded_attributes = frozenset(NO_RECORED_ATTRIBUTES)

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: HmGenericDataPoint,
    ) -> None:
        """Initialize the generic entity."""
        self._cu: ControlUnit = control_unit
        self._data_point: HmGenericDataPoint = get_data_point(data_point=data_point)
        self._attr_unique_id = f"{DOMAIN}_{data_point.unique_id}"

        if entity_description := get_entity_description(data_point=data_point):
            self.entity_description = entity_description
        else:
            self._attr_entity_registry_enabled_default = data_point.enabled_default
            if isinstance(data_point, GenericDataPoint):
                self._attr_translation_key = data_point.parameter.lower()

        hm_device = data_point.device
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, hm_device.identifier)},
            manufacturer=hm_device.manufacturer,
            model=hm_device.model,
            name=hm_device.name,
            serial_number=hm_device.address,
            sw_version=hm_device.firmware,
            suggested_area=hm_device.room,
            # Link to the homematic control unit.
            via_device=(DOMAIN, hm_device.central.name),
        )

        self._static_state_attributes = self._get_static_state_attributes()
        self._unregister_callbacks: list[CALLBACK_TYPE] = []

        _LOGGER.debug("init: Setting up %s", data_point.full_name)
        if (
            isinstance(data_point, GenericDataPoint)
            and hasattr(self, "entity_description")
            and hasattr(self.entity_description, "native_unit_of_measurement")
            and self.entity_description.native_unit_of_measurement != data_point.unit
        ):
            _LOGGER.debug(
                "Different unit for entity: %s: entity_description: %s vs device: %s",
                data_point.full_name,
                self.entity_description.native_unit_of_measurement,
                data_point.unit,
            )

    @property
    def available(self) -> bool:
        """Return if data point is available."""
        return self._data_point.available

    def _get_static_state_attributes(self) -> Mapping[str, Any]:
        """Return the static attributes of the generic entity."""
        attributes: dict[str, Any] = {
            ATTR_INTERFACE_ID: self._data_point.device.interface_id,
            ATTR_ADDRESS: self._data_point.channel.address,
            ATTR_MODEL: self._data_point.device.model,
        }
        if isinstance(self._data_point, GenericDataPoint):
            attributes[ATTR_PARAMETER] = self._data_point.parameter
            attributes[ATTR_FUNCTION] = self._data_point.function

        return attributes

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes of the generic entity."""
        attributes: dict[str, Any] = {}
        attributes.update(self._static_state_attributes)

        if (
            isinstance(self._data_point, GenericDataPoint) and self._data_point.is_readable
        ) or isinstance(self._data_point, CustomDataPoint):
            if self._data_point.is_valid:
                attributes[ATTR_VALUE_STATE] = (
                    HmEntityState.UNCERTAIN
                    if self._data_point.state_uncertain
                    else HmEntityState.VALID
                )
            else:
                attributes[ATTR_VALUE_STATE] = HmEntityState.NOT_VALID
        return attributes

    @property
    def data_point(self) -> HmGenericDataPoint:
        """Return the homematic entity."""
        return self._data_point

    @property
    def name(self) -> str | UndefinedType | None:
        """
        Return the name of the entity.

        Override by CC.
        A hm entity can consist of two parts. The first part is already defined by the user,
        and the second part is the english named parameter that must be translated.
        This translated parameter will be used in the combined name.
        """
        entity_name = self._data_point.name

        if isinstance(self._data_point, GenericDataPoint) and entity_name:
            translated_name = super().name
            if self._do_remove_name():
                translated_name = ""
            if isinstance(translated_name, str):
                entity_name = entity_name.replace(
                    self._data_point.parameter.replace("_", " ").title(), translated_name
                )

        if isinstance(self._data_point, CustomDataPoint) and entity_name:
            translated_name = super().name
            if self._do_remove_name():
                translated_name = ""
            if isinstance(translated_name, str) and self._data_point.name_data.parameter_name:
                entity_name = entity_name.replace(
                    self._data_point.name_data.parameter_name.replace("_", " ").title(),
                    translated_name,
                )
        if entity_name == "":
            return None
        return entity_name

    def _do_remove_name(self) -> bool:
        """
        Check if entity name part should be removed.

        Here we use the HA translation support to identify if the translated name is ''
        This is guarded against failure due to future HA api changes.
        """
        try:
            if (
                self._name_translation_key
                and hasattr(self, "platform")
                and hasattr(self.platform, "platform_translations")
                and (name := self.platform.platform_translations.get(self._name_translation_key))
                is not None
            ):
                return bool(name == "")
        except Exception:  # pylint: disable=broad-exception-caught
            return False
        return False

    @property
    def use_device_name(self) -> bool:
        """
        Return if this entity does not have its own name.

        Override by CC.
        """
        return not self.name

    async def async_added_to_hass(self) -> None:
        """Register callbacks and load initial data."""
        if isinstance(self._data_point, CallbackDataPoint):
            self._unregister_callbacks.append(
                self._data_point.register_data_point_updated_callback(
                    cb=self._async_data_point_updated, custom_id=self.entity_id
                )
            )
            self._unregister_callbacks.append(
                self._data_point.register_device_removed_callback(cb=self._async_device_removed)
            )
        # Init value of entity.
        if isinstance(self._data_point, GenericDataPoint | CustomDataPoint):
            await self._data_point.load_data_point_value(call_source=CallSource.HA_INIT)
        if (
            isinstance(self._data_point, GenericDataPoint)
            and not self._data_point.is_valid
            and self._data_point.is_readable
        ) or (isinstance(self._data_point, CustomDataPoint) and not self._data_point.is_valid):
            _LOGGER.debug(
                "CCU did not provide initial value for %s. See README for more information",
                self._data_point.full_name,
            )

    @callback
    def _async_data_point_updated(self, *args: Any, **kwargs: Any) -> None:
        """Handle device state changes."""
        # Don't update disabled entities
        update_type = (
            "updated"
            if self._data_point.refreshed_at == self._data_point.modified_at
            else "refreshed"
        )
        if self.enabled:
            _LOGGER.debug("Device %s event fired for %s", update_type, self._data_point.full_name)
            self.async_schedule_update_ha_state()
        else:
            _LOGGER.debug(
                "Device %s event for %s not fired. Entity is disabled",
                update_type,
                self._data_point.full_name,
            )

    async def async_update(self) -> None:
        """Update entities."""
        if isinstance(self._data_point, GenericDataPoint | CustomDataPoint):
            await self._data_point.load_data_point_value(
                call_source=CallSource.MANUAL_OR_SCHEDULED
            )

    async def async_will_remove_from_hass(self) -> None:
        """Run when hmip device will be removed from hass."""
        # Remove callback from device.
        for unregister in self._unregister_callbacks:
            if unregister is not None:
                unregister()

    @callback
    def _async_device_removed(self, *args: Any, **kwargs: Any) -> None:
        """Handle hm device removal."""
        self.hass.async_create_task(self.async_remove(force_remove=True))

        if not self.registry_entry:
            return

        if device_id := self.registry_entry.device_id:
            # Remove from device registry.
            device_registry = dr.async_get(self.hass)
            if device_id in device_registry.devices:
                # This will also remove associated entities from entity registry.
                device_registry.async_remove_device(device_id)


class HaHomematicGenericRestoreEntity(HaHomematicGenericEntity[HmGenericDataPoint], RestoreEntity):
    """Representation of the HomematicIP generic restore entity."""

    _restored_state: State | None = None

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
        return (
            not self._data_point.is_valid
            and self._restored_state is not None
            and self._restored_state.state is not None
        )

    async def async_added_to_hass(self) -> None:
        """Check, if state needs to be restored."""
        await super().async_added_to_hass()
        # if not self._data_point.is_valid:
        self._restored_state = await self.async_get_last_state()


class HaHomematicGenericHubEntity(Entity):
    """Representation of the HomematicIP generic hub entity."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_registry_enabled_default = False

    _unrecorded_attributes = frozenset({ATTR_NAME})

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: GenericHubDataPoint,
    ) -> None:
        """Initialize the generic entity."""
        self._cu: ControlUnit = control_unit
        self._data_point = get_data_point(data_point)
        self._attr_unique_id = f"{DOMAIN}_{data_point.unique_id}"
        if entity_description := get_entity_description(data_point=data_point):
            self.entity_description = entity_description
        self._attr_name = data_point.name
        self._attr_device_info = control_unit.device_info
        self._unregister_callbacks: list[CALLBACK_TYPE] = []
        _LOGGER.debug("init sysvar: Setting up %s", self.name)

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self._data_point.available

    async def async_added_to_hass(self) -> None:
        """Register callbacks and load initial data."""
        if isinstance(self._data_point, CallbackDataPoint):
            self._unregister_callbacks.append(
                self._data_point.register_data_point_updated_callback(
                    cb=self._async_hub_entity_updated,
                    custom_id=self.entity_id,
                )
            )
            self._unregister_callbacks.append(
                self._data_point.register_device_removed_callback(
                    cb=self._async_hub_device_removed
                )
            )

    async def async_will_remove_from_hass(self) -> None:
        """Run when hmip sysvar entity will be removed from hass."""
        # Remove callbacks.
        for unregister in self._unregister_callbacks:
            if unregister is not None:
                unregister()

    @callback
    def _async_hub_entity_updated(self, *args: Any, **kwargs: Any) -> None:
        """Handle sysvar entity state changes."""
        # Don't update disabled entities
        if self.enabled:
            _LOGGER.debug("Sysvar changed event fired for %s", self.name)
            self.async_schedule_update_ha_state()
        else:
            _LOGGER.debug(
                "Sysvar changed event for %s not fired. Sysvar entity is disabled",
                self.name,
            )

    @callback
    def _async_hub_device_removed(self, *args: Any, **kwargs: Any) -> None:
        """Handle hm sysvar entity removal."""
        self.hass.async_create_task(self.async_remove(force_remove=True))

        if not self.registry_entry:
            return

        if entity_id := self.registry_entry.entity_id:
            entity_registry = er.async_get(self.hass)
            if entity_id in entity_registry.entities:
                entity_registry.async_remove(entity_id)


class HaHomematicGenericSysvarEntity(
    Generic[HmGenericSysvarDataPoint], HaHomematicGenericHubEntity
):
    """Representation of the HomematicIP generic sysvar entity."""

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: GenericSysvarDataPoint,
    ) -> None:
        """Initialize the generic entity."""
        super().__init__(
            control_unit=control_unit,
            data_point=data_point,
        )
        self._data_point: GenericSysvarDataPoint = data_point
        self._attr_extra_state_attributes = {ATTR_NAME: self._data_point.ccu_var_name}

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes of the generic entity."""
        attributes: dict[str, Any] = {ATTR_NAME: self._data_point.ccu_var_name}
        if self._data_point.is_valid:
            attributes[ATTR_VALUE_STATE] = (
                HmEntityState.UNCERTAIN
                if self._data_point.state_uncertain
                else HmEntityState.VALID
            )
        else:
            attributes[ATTR_VALUE_STATE] = HmEntityState.NOT_VALID
        return attributes
