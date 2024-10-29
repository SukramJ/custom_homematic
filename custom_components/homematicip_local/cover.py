"""binary_sensor for Homematic(IP) Local."""

from __future__ import annotations

import logging
from typing import Any, TypeVar

from hahomematic.const import DataPointCategory
from hahomematic.model.custom import CustomDpBlind, CustomDpCover, CustomDpGarage, CustomDpIpBlind
from hahomematic.model.data_point import CallParameterCollector
import voluptuous as vol

from homeassistant.components.cover import (
    ATTR_CURRENT_POSITION,
    ATTR_CURRENT_TILT_POSITION,
    ATTR_POSITION,
    ATTR_TILT_POSITION,
    CoverEntity,
)
from homeassistant.const import STATE_CLOSED, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_platform
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import HomematicConfigEntry
from .const import HmipLocalServices
from .control_unit import ControlUnit, signal_new_data_point
from .generic_entity import HaHomematicGenericRestoreEntity
from .services import CONF_WAIT_FOR_CALLBACK

_LOGGER = logging.getLogger(__name__)

HmGenericCover = TypeVar("HmGenericCover", bound=CustomDpCover | CustomDpGarage)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local cover platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_cover(data_points: tuple[HmGenericCover, ...]) -> None:
        """Add cover from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_COVER: Adding %i data points", len(data_points))
        entities: list[HaHomematicBaseCover] = []

        for data_point in data_points:
            if isinstance(data_point, CustomDpIpBlind):
                if data_point.operation_mode and data_point.operation_mode == "SHUTTER":
                    entities.append(
                        HaHomematicCover(
                            control_unit=control_unit,
                            data_point=data_point,
                        )
                    )
                else:
                    entities.append(
                        HaHomematicBlind(
                            control_unit=control_unit,
                            data_point=data_point,
                        )
                    )
            elif isinstance(data_point, CustomDpBlind):
                entities.append(
                    HaHomematicBlind(
                        control_unit=control_unit,
                        data_point=data_point,
                    )
                )
            elif isinstance(data_point, CustomDpCover):
                entities.append(
                    HaHomematicCover(
                        control_unit=control_unit,
                        data_point=data_point,
                    )
                )
            elif isinstance(data_point, CustomDpGarage):
                entities.append(
                    HaHomematicGarage(
                        control_unit=control_unit,
                        data_point=data_point,
                    )
                )

        if entities:
            async_add_entities(entities)

    entry.async_on_unload(
        func=async_dispatcher_connect(
            hass=hass,
            signal=signal_new_data_point(
                entry_id=entry.entry_id, platform=DataPointCategory.COVER
            ),
            target=async_add_cover,
        )
    )

    async_add_cover(
        data_points=control_unit.get_new_data_points(
            data_point_type=CustomDpCover | CustomDpGarage
        )
    )

    platform = entity_platform.async_get_current_platform()

    platform.async_register_entity_service(
        HmipLocalServices.SET_COVER_COMBINED_POSITION,
        {
            vol.Required(ATTR_POSITION): vol.All(vol.Coerce(int), vol.Range(min=0, max=100)),
            vol.Optional(ATTR_TILT_POSITION): vol.All(vol.Coerce(int), vol.Range(min=0, max=100)),
            vol.Optional(CONF_WAIT_FOR_CALLBACK): cv.positive_int,
        },
        "async_set_cover_combined_position",
    )


class HaHomematicBaseCover(HaHomematicGenericRestoreEntity[HmGenericCover], CoverEntity):
    """Representation of the HomematicIP cover entity."""

    @property
    def current_cover_position(self) -> int | None:
        """Return current position of cover."""
        if self._data_point.is_valid:
            return self._data_point.current_position
        if self.is_restored and self._restored_state:
            return self._restored_state.attributes.get(ATTR_CURRENT_POSITION)
        return None

    @property
    def is_closed(self) -> bool | None:
        """Return if the cover is closed."""
        if self._data_point.is_valid:
            return self._data_point.is_closed
        if (
            self.is_restored
            and self._restored_state
            and (restored_state := self._restored_state.state)
            not in (
                STATE_UNKNOWN,
                STATE_UNAVAILABLE,
            )
        ):
            return restored_state == STATE_CLOSED
        return None

    @property
    def is_opening(self) -> bool | None:
        """Return if the cover is opening."""
        return self._data_point.is_opening

    @property
    def is_closing(self) -> bool | None:
        """Return if the cover is closing."""
        return self._data_point.is_closing

    async def async_set_cover_position(self, **kwargs: Any) -> None:
        """Move the cover to a specific position."""
        # Hm cover is closed:1 -> open:0
        if ATTR_POSITION in kwargs:
            position = int(kwargs[ATTR_POSITION])
            await self._data_point.set_position(position=position)

    async def async_set_cover_combined_position(
        self, position: int, tilt_position: int | None = None, wait_for_callback: int | None = None
    ) -> None:
        """Move the cover to a specific position incl. tilt."""
        collector = CallParameterCollector(client=self._data_point.device.client)
        await self._data_point.set_position(
            position=position, tilt_position=tilt_position, collector=collector
        )
        await collector.send_data(wait_for_callback=wait_for_callback)

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover."""
        await self._data_point.open()

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover."""
        await self._data_point.close()

    async def async_stop_cover(self, **kwargs: Any) -> None:
        """Stop the device if in motion."""
        await self._data_point.stop()


class HaHomematicCover(HaHomematicBaseCover[CustomDpCover]):
    """Representation of the HomematicIP cover entity."""


class HaHomematicBlind(HaHomematicBaseCover[CustomDpBlind | CustomDpIpBlind]):
    """Representation of the HomematicIP blind entity."""

    @property
    def current_cover_tilt_position(self) -> int | None:
        """Return current tilt position of cover."""
        if self._data_point.is_valid:
            return self._data_point.current_tilt_position
        if self.is_restored and self._restored_state:
            return self._restored_state.attributes.get(ATTR_CURRENT_TILT_POSITION)
        return None

    async def async_set_cover_tilt_position(self, **kwargs: Any) -> None:
        """Move the cover to a specific tilt position."""
        if ATTR_TILT_POSITION in kwargs:
            tilt_position = int(kwargs[ATTR_TILT_POSITION])
            await self._data_point.set_position(tilt_position=tilt_position)

    async def async_open_cover_tilt(self, **kwargs: Any) -> None:
        """Open the tilt."""
        await self._data_point.open_tilt()

    async def async_close_cover_tilt(self, **kwargs: Any) -> None:
        """Close the tilt."""
        await self._data_point.close_tilt()

    async def async_stop_cover_tilt(self, **kwargs: Any) -> None:
        """Stop the device if in motion."""
        await self._data_point.stop_tilt()


class HaHomematicGarage(HaHomematicBaseCover[CustomDpGarage]):
    """Representation of the HomematicIP garage entity."""
