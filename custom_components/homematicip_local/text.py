"""text for Homematic(IP) Local."""

from __future__ import annotations

import logging

from hahomematic.const import DataPointCategory
from hahomematic.model.generic import DpText
from hahomematic.model.hub import SysvarDpText

from homeassistant.components.text import TextEntity
from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN
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
    """Set up the Homematic(IP) Local text platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_text(data_points: tuple[DpText, ...]) -> None:
        """Add text from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_TEXT: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicText(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    @callback
    def async_add_hub_text(data_points: tuple[SysvarDpText, ...]) -> None:
        """Add sysvar text from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_HUB_TEXT: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicSysvarText(control_unit=control_unit, data_point=data_point)
            for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(entry_id=entry.entry_id, platform=DataPointCategory.TEXT),
            target=async_add_text,
        )
    )
    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.HUB_TEXT
            ),
            target=async_add_hub_text,
        )
    )

    async_add_text(data_points=control_unit.get_new_data_points(data_point_type=DpText))

    async_add_hub_text(
        data_points=control_unit.get_new_hub_data_points(data_point_type=SysvarDpText)
    )


class HaHomematicText(HaHomematicGenericRestoreEntity[DpText], TextEntity):
    """Representation of the HomematicIP text entity."""

    @property
    def native_value(self) -> str | None:
        """Return the value reported by the text."""
        if self._data_point.is_valid:
            return self._data_point.value  # type: ignore[no-any-return]
        if (
            self.is_restored
            and self._restored_state
            and (restored_state := self._restored_state.state)
            not in (
                STATE_UNKNOWN,
                STATE_UNAVAILABLE,
            )
        ):
            return restored_state
        return None

    async def async_set_value(self, value: str) -> None:
        """Send the text."""
        await self._data_point.send_value(value=value)


class HaHomematicSysvarText(HaHomematicGenericSysvarEntity[SysvarDpText], TextEntity):
    """Representation of the HomematicIP hub text entity."""

    @property
    def native_value(self) -> str | None:
        """Return the value reported by the text."""
        return self._data_point.value

    async def async_set_value(self, value: str) -> None:
        """Send the text."""
        await self._data_point.send_variable(value=value)
