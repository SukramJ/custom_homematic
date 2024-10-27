"""select for Homematic(IP) Local."""

from __future__ import annotations

import logging

from hahomematic.const import DataPointCategory
from hahomematic.model.generic import DpSelect
from hahomematic.model.hub import SysvarDpSelect

from homeassistant.components.select import SelectEntity
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
    """Set up the Homematic(IP) Local select platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_select(data_points: tuple[DpSelect, ...]) -> None:
        """Add select from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_SELECT: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicSelect(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    @callback
    def async_add_hub_select(data_points: tuple[SysvarDpSelect, ...]) -> None:
        """Add sysvar select from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_HUB_SELECT: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicSysvarSelect(control_unit=control_unit, data_point=data_point)
            for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.SELECT
            ),
            target=async_add_select,
        )
    )

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.HUB_SELECT
            ),
            target=async_add_hub_select,
        )
    )

    async_add_select(data_points=control_unit.get_new_data_points(data_point_type=DpSelect))

    async_add_hub_select(
        data_points=control_unit.get_new_hub_data_points(data_point_type=SysvarDpSelect)
    )


class HaHomematicSelect(HaHomematicGenericRestoreEntity[DpSelect], SelectEntity):
    """Representation of the HomematicIP select entity."""

    @property
    def options(self) -> list[str]:
        """Return the options."""
        if options := self._data_point.values:
            return [option.lower() for option in options]
        return []

    @property
    def current_option(self) -> str | None:
        """Return the currently selected option."""
        if self._data_point.is_valid:
            return self._data_point.value.lower() if self._data_point.value is not None else None
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

    async def async_select_option(self, option: str) -> None:
        """Select an option."""
        await self._data_point.send_value(option.upper())


class HaHomematicSysvarSelect(HaHomematicGenericSysvarEntity[SysvarDpSelect], SelectEntity):
    """Representation of the HomematicIP hub select entity."""

    @property
    def options(self) -> list[str]:
        """Return the options."""
        if options := self._data_point.values:
            return list(options)
        return []

    @property
    def current_option(self) -> str | None:
        """Return the currently selected option."""
        return self._data_point.value

    async def async_select_option(self, option: str) -> None:
        """Select an option."""
        await self._data_point.send_variable(option)
