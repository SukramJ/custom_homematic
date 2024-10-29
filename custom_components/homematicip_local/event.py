"""event for Homematic(IP) Local."""

from __future__ import annotations

import logging
from typing import Any

from hahomematic.const import CALLBACK_TYPE, DATA_POINT_EVENTS, DataPointCategory, EventKey
from hahomematic.model.device import Channel, Device
from hahomematic.model.event import GenericEvent

from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import UndefinedType

from . import HomematicConfigEntry
from .const import DOMAIN, EVENT_MODEL
from .control_unit import ControlUnit, signal_new_data_point

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local event platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_event(data_points: tuple[tuple[GenericEvent, ...], ...]) -> None:
        """Add event from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_EVENT: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicEvent(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.EVENT
            ),
            target=async_add_event,
        )
    )

    for event_type in DATA_POINT_EVENTS:
        async_add_event(
            data_points=control_unit.central.get_events(event_type=event_type, registered=False)
        )


class HaHomematicEvent(EventEntity):
    """Representation of the Homematic(IP) Local event."""

    _attr_device_class = EventDeviceClass.BUTTON
    _attr_entity_registry_enabled_default = True
    _attr_has_entity_name = True
    _attr_should_poll = False

    _unrecorded_attributes = frozenset({EventKey.ADDRESS, EventKey.INTERFACE_ID, EVENT_MODEL})

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: tuple[GenericEvent, ...],
    ) -> None:
        """Initialize the event."""
        self._cu: ControlUnit = control_unit
        self._hm_channel_events = data_point
        self._attr_event_types = [event.parameter.lower() for event in data_point]
        self._hm_primary_event: GenericEvent = data_point[0]
        self._hm_channel: Channel = self._hm_primary_event.channel
        self._hm_device: Device = self._hm_channel.device
        self._attr_translation_key = self._hm_primary_event.event_type.value.replace(".", "_")

        self._attr_unique_id = f"{DOMAIN}_{self._hm_channel.unique_id}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._hm_device.identifier)},
        )
        self._attr_extra_state_attributes = {
            EventKey.INTERFACE_ID: self._hm_device.interface_id,
            EventKey.ADDRESS: self._hm_channel.address,
            EVENT_MODEL: self._hm_device.model,
        }
        self._unregister_callbacks: list[CALLBACK_TYPE] = []
        _LOGGER.debug(
            "init: Setting up %s %s",
            self._hm_device.name,
            self._hm_channel.name,
        )

    @property
    def available(self) -> bool:
        """Return if event is available."""
        return self._hm_device.available

    @property
    def name(self) -> str | UndefinedType | None:
        """Return the name of the entity."""
        return self._hm_primary_event.name_data.channel_name

    async def async_added_to_hass(self) -> None:
        """Register callbacks and load initial data."""

        for event in self._hm_channel_events:
            self._unregister_callbacks.append(
                event.register_data_point_updated_callback(
                    cb=self._async_event_changed, custom_id=self.entity_id
                )
            )
            self._unregister_callbacks.append(
                event.register_device_removed_callback(cb=self._async_device_removed)
            )

    @callback
    def _async_event_changed(self, *args: Any, **kwargs: Any) -> None:
        """Handle device state changes."""
        # Don't update disabled entities
        if self.enabled:
            self._trigger_event(event_type=kwargs["parameter"])
            _LOGGER.debug("Device event fired %s", self.name)
            self.async_schedule_update_ha_state()
        else:
            _LOGGER.debug(
                "Device event for %s not fired. Entity is disabled",
                self.name,
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
