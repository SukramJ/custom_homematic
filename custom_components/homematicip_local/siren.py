"""siren for Homematic(IP) Local."""

from __future__ import annotations

import logging
from typing import Any, Final

from hahomematic.const import DataPointCategory
from hahomematic.model.custom import BaseCustomDpSiren, SirenOnArgs
import voluptuous as vol

from homeassistant.components.siren import (
    ATTR_DURATION,
    ATTR_TONE,
    SirenEntity,
    SirenEntityFeature,
)
from homeassistant.const import STATE_ON, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import HomematicConfigEntry
from .const import SERVICE_TURN_ON_SIREN
from .control_unit import ControlUnit, signal_new_data_point
from .generic_entity import HaHomematicGenericRestoreEntity

_LOGGER = logging.getLogger(__name__)

ATTR_LIGHT: Final = "light"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local siren platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_siren(data_points: tuple[BaseCustomDpSiren, ...]) -> None:
        """Add siren from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_SIREN: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicSiren(
                control_unit=control_unit,
                data_point=data_point,
            )
            for data_point in data_points
        ]:
            async_add_entities(entities)

    platform = entity_platform.async_get_current_platform()
    platform.async_register_entity_service(
        SERVICE_TURN_ON_SIREN,
        {
            vol.Optional(ATTR_TONE): cv.string,
            vol.Optional(ATTR_LIGHT): cv.string,
            vol.Optional(ATTR_DURATION): cv.positive_int,
        },
        "async_turn_on",
    )

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.SIREN
            ),
            target=async_add_siren,
        )
    )

    async_add_siren(
        data_points=control_unit.get_new_data_points(data_point_type=BaseCustomDpSiren)
    )


class HaHomematicSiren(HaHomematicGenericRestoreEntity[BaseCustomDpSiren], SirenEntity):
    """Representation of the HomematicIP siren entity."""

    _attr_supported_features = SirenEntityFeature.TURN_OFF | SirenEntityFeature.TURN_ON

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: BaseCustomDpSiren,
    ) -> None:
        """Initialize the siren entity."""
        super().__init__(
            control_unit=control_unit,
            data_point=data_point,
        )
        if data_point.supports_tones:
            self._attr_supported_features |= SirenEntityFeature.TONES
        if data_point.supports_duration:
            self._attr_supported_features |= SirenEntityFeature.DURATION

    @property
    def is_on(self) -> bool | None:
        """Return true if siren is on."""
        if self._data_point.is_valid:
            return self._data_point.is_on is True
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

    @property
    def available_tones(self) -> list[int | str] | dict[int, str] | None:
        """Return a list of available tones."""
        return self._data_point.available_tones  # type: ignore[return-value]

    @property
    def available_lights(self) -> list[int | str] | dict[int, str] | None:
        """Return a list of available lights."""
        return self._data_point.available_lights  # type: ignore[return-value]

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the device on."""
        hm_kwargs = SirenOnArgs()
        if tone := kwargs.get(ATTR_TONE):
            hm_kwargs["acoustic_alarm"] = tone
        if light := kwargs.get(ATTR_LIGHT):
            hm_kwargs["optical_alarm"] = light
        if duration := kwargs.get(ATTR_DURATION):
            hm_kwargs["duration"] = duration
        await self._data_point.turn_on(**hm_kwargs)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the device off."""
        await self._data_point.turn_off()
