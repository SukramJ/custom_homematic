"""button for Homematic(IP) Local."""

from __future__ import annotations

import logging

from hahomematic.const import DataPointCategory
from hahomematic.model.generic import DpButton
from hahomematic.model.hub import ProgramDpButton

from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import HomematicConfigEntry
from .control_unit import ControlUnit, signal_new_data_point
from .generic_entity import ATTR_NAME, HaHomematicGenericEntity, HaHomematicGenericHubEntity

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local binary_sensor platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_button(data_points: tuple[DpButton, ...]) -> None:
        """Add button from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_BUTTON: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicButton(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    @callback
    def async_add_program_button(data_points: tuple[ProgramDpButton, ...]) -> None:
        """Add program button from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_PROGRAM_BUTTON: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicProgramButton(control_unit=control_unit, data_point=data_point)
            for data_point in data_points
        ]:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.BUTTON
            ),
            target=async_add_button,
        )
    )

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.HUB_BUTTON
            ),
            target=async_add_program_button,
        )
    )

    async_add_button(data_points=control_unit.get_new_data_points(data_point_type=DpButton))

    async_add_program_button(
        data_points=control_unit.get_new_hub_data_points(data_point_type=ProgramDpButton)
    )


class HaHomematicButton(HaHomematicGenericEntity[DpButton], ButtonEntity):
    """Representation of the Homematic(IP) Local button."""

    async def async_press(self) -> None:
        """Execute a button press."""
        await self._data_point.press()


class HaHomematicProgramButton(HaHomematicGenericHubEntity, ButtonEntity):
    """Representation of the Homematic(IP) Local button."""

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: ProgramDpButton,
    ) -> None:
        """Initialize the button entity."""
        super().__init__(
            control_unit=control_unit,
            data_point=data_point,
        )
        self._data_point: ProgramDpButton = data_point
        self._attr_extra_state_attributes = {ATTR_NAME: self._data_point.ccu_program_name}

    async def async_press(self) -> None:
        """Execute a button press."""
        await self._data_point.press()
