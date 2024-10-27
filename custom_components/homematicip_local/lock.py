"""lock for Homematic(IP) Local."""

from __future__ import annotations

import logging
from typing import Any

from hahomematic.const import DataPointCategory
from hahomematic.model.custom import BaseCustomDpLock, LockState

from homeassistant.components.lock import LockEntity, LockEntityFeature
from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import HomematicConfigEntry
from .control_unit import ControlUnit, signal_new_data_point
from .generic_entity import HaHomematicGenericRestoreEntity

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local lock platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_lock(data_points: tuple[BaseCustomDpLock, ...]) -> None:
        """Add lock from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_LOCK: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicLock(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(entry_id=entry.entry_id, platform=DataPointCategory.LOCK),
            target=async_add_lock,
        )
    )

    async_add_lock(data_points=control_unit.get_new_data_points(data_point_type=BaseCustomDpLock))


class HaHomematicLock(HaHomematicGenericRestoreEntity[BaseCustomDpLock], LockEntity):
    """Representation of the HomematicIP lock entity."""

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: BaseCustomDpLock,
    ) -> None:
        """Initialize the lock entity."""
        super().__init__(control_unit=control_unit, data_point=data_point)
        if data_point.supports_open:
            self._attr_supported_features = LockEntityFeature.OPEN

    @property
    def is_locked(self) -> bool | None:
        """Return true if lock is on."""
        if self._data_point.is_valid:
            return self._data_point.is_locked
        if (
            self.is_restored
            and self._restored_state
            and (restored_state := self._restored_state.state)
            not in (
                STATE_UNKNOWN,
                STATE_UNAVAILABLE,
            )
        ):
            return restored_state == LockState.LOCKED
        return None

    @property
    def is_locking(self) -> bool | None:
        """Return true if the lock is locking."""
        return self._data_point.is_locking

    @property
    def is_unlocking(self) -> bool | None:
        """Return true if the lock is unlocking."""
        return self._data_point.is_unlocking

    @property
    def is_jammed(self) -> bool:
        """Return true if lock is jammed."""
        return self._data_point.is_jammed is True

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the lock."""
        await self._data_point.lock()

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the lock."""
        await self._data_point.unlock()

    async def async_open(self, **kwargs: Any) -> None:
        """Open the lock."""
        await self._data_point.open()
