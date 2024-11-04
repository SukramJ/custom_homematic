"""climate for Homematic(IP) Local."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
import logging
from typing import Any, Final, cast

from hahomematic.const import DataPointCategory
from hahomematic.model.custom import (
    PROFILE_DICT,
    PROFILE_PREFIX,
    SIMPLE_PROFILE_DICT,
    SIMPLE_WEEKDAY_LIST,
    WEEKDAY_DICT,
    BaseCustomDpClimate,
    ClimateActivity,
    ClimateMode,
    ClimateProfile,
)
import voluptuous as vol

from homeassistant.components.climate import (
    ATTR_CURRENT_HUMIDITY,
    ATTR_CURRENT_TEMPERATURE,
    ATTR_PRESET_MODE,
    ATTR_TEMPERATURE,
    PRESET_AWAY,
    PRESET_BOOST,
    PRESET_COMFORT,
    PRESET_ECO,
    PRESET_NONE,
    ClimateEntity,
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN, UnitOfTemperature
from homeassistant.core import HomeAssistant, ServiceResponse, SupportsResponse, callback
from homeassistant.helpers import entity_platform
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import HomematicConfigEntry
from .const import HmipLocalServices
from .control_unit import ControlUnit, signal_new_data_point
from .generic_entity import HaHomematicGenericEntity, HaHomematicGenericRestoreEntity

_LOGGER = logging.getLogger(__name__)

ATTR_AWAY_END: Final = "end"
ATTR_AWAY_HOURS: Final = "hours"
ATTR_AWAY_START: Final = "start"
ATTR_AWAY_TEMPERATURE: Final = "away_temperature"
ATTR_BASE_TEMPERATURE: Final = "base_temperature"
ATTR_OPTIMUM_START_STOP: Final = "optimum_start_stop"
ATTR_PROFILE: Final = "profile"
ATTR_PROFILE_DATA: Final = "profile_data"
ATTR_SIMPLE_PROFILE_DATA: Final = "simple_profile_data"
ATTR_SIMPLE_WEEKDAY_LIST: Final = "simple_weekday_list"
ATTR_SOURCE_ENTITY_ID: Final = "source_entity_id"
ATTR_SOURCE_PROFILE: Final = "source_profile"
ATTR_TARGET_PROFILE: Final = "target_profile"
ATTR_TEMPERATURE_OFFSET: Final = "temperature_offset"
ATTR_WEEKDAY: Final = "weekday"
ATTR_WEEKDAY_DATA: Final = "weekday_data"

SUPPORTED_HA_PRESET_MODES: Final = [
    PRESET_AWAY,
    PRESET_BOOST,
    PRESET_COMFORT,
    PRESET_ECO,
    PRESET_NONE,
]

HM_TO_HA_HVAC_MODE: Mapping[ClimateMode, HVACMode] = {
    ClimateMode.AUTO: HVACMode.AUTO,
    ClimateMode.COOL: HVACMode.COOL,
    ClimateMode.HEAT: HVACMode.HEAT,
    ClimateMode.OFF: HVACMode.OFF,
}

HA_TO_HM_HVAC_MODE: Mapping[HVACMode, ClimateMode] = {v: k for k, v in HM_TO_HA_HVAC_MODE.items()}

HM_TO_HA_ACTION: Mapping[ClimateActivity, HVACAction] = {
    ClimateActivity.COOL: HVACAction.COOLING,
    ClimateActivity.HEAT: HVACAction.HEATING,
    ClimateActivity.IDLE: HVACAction.IDLE,
    ClimateActivity.OFF: HVACAction.OFF,
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HomematicConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Homematic(IP) Local climate platform."""
    control_unit: ControlUnit = entry.runtime_data

    @callback
    def async_add_climate(data_points: tuple[BaseCustomDpClimate, ...]) -> None:
        """Add climate from Homematic(IP) Local."""
        _LOGGER.debug("ASYNC_ADD_CLIMATE: Adding %i data points", len(data_points))

        if entities := [
            HaHomematicClimate(
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
                entry_id=entry.entry_id, platform=DataPointCategory.CLIMATE
            ),
            target=async_add_climate,
        )
    )

    async_add_climate(
        data_points=control_unit.get_new_data_points(data_point_type=BaseCustomDpClimate)
    )

    platform = entity_platform.async_get_current_platform()

    platform.async_register_entity_service(
        name=HmipLocalServices.ENABLE_AWAY_MODE_BY_CALENDAR,
        schema={
            vol.Optional(ATTR_AWAY_START): cv.datetime,
            vol.Required(ATTR_AWAY_END): cv.datetime,
            vol.Required(ATTR_AWAY_TEMPERATURE, default=18.0): vol.All(
                vol.Coerce(float), vol.Range(min=5.0, max=30.5)
            ),
        },
        func="async_enable_away_mode_by_calendar",
    )
    platform.async_register_entity_service(
        name=HmipLocalServices.ENABLE_AWAY_MODE_BY_DURATION,
        schema={
            vol.Required(ATTR_AWAY_HOURS): cv.positive_int,
            vol.Required(ATTR_AWAY_TEMPERATURE, default=18.0): vol.All(
                vol.Coerce(float), vol.Range(min=5.0, max=30.5)
            ),
        },
        func="async_enable_away_mode_by_duration",
    )
    platform.async_register_entity_service(
        name=HmipLocalServices.DISABLE_AWAY_MODE,
        schema={},
        func="async_disable_away_mode",
    )

    platform.async_register_entity_service(
        name=HmipLocalServices.COPY_SCHEDULE,
        schema={
            vol.Required(ATTR_SOURCE_ENTITY_ID): cv.string,
        },
        func="async_copy_schedule",
    )

    platform.async_register_entity_service(
        name=HmipLocalServices.COPY_SCHEDULE_PROFILE,
        schema={
            vol.Optional(ATTR_SOURCE_ENTITY_ID): cv.string,
            vol.Required(ATTR_SOURCE_PROFILE): cv.string,
            vol.Required(ATTR_TARGET_PROFILE): cv.string,
        },
        supports_response=SupportsResponse.OPTIONAL,
        func="async_copy_schedule_profile",
    )

    platform.async_register_entity_service(
        name=HmipLocalServices.GET_SCHEDULE_PROFILE,
        schema={
            vol.Required(ATTR_PROFILE): cv.string,
        },
        supports_response=SupportsResponse.OPTIONAL,
        func="async_get_schedule_profile",
    )

    platform.async_register_entity_service(
        name=HmipLocalServices.GET_SCHEDULE_PROFILE_WEEKDAY,
        schema={
            vol.Required(ATTR_PROFILE): cv.string,
            vol.Required(ATTR_WEEKDAY): cv.string,
        },
        supports_response=SupportsResponse.OPTIONAL,
        func="async_get_schedule_profile_weekday",
    )

    platform.async_register_entity_service(
        name=HmipLocalServices.SET_SCHEDULE_PROFILE,
        schema={
            vol.Required(ATTR_PROFILE): cv.string,
            vol.Required(ATTR_PROFILE_DATA): dict,
        },
        func="async_set_schedule_profile",
    )

    platform.async_register_entity_service(
        name=HmipLocalServices.SET_SCHEDULE_PROFILE_WEEKDAY,
        schema={
            vol.Required(ATTR_PROFILE): cv.string,
            vol.Required(ATTR_WEEKDAY): cv.string,
            vol.Required(ATTR_WEEKDAY_DATA): dict,
        },
        func="async_set_schedule_profile_weekday",
    )

    platform.async_register_entity_service(
        name=HmipLocalServices.SET_SCHEDULE_SIMPLE_PROFILE,
        schema={
            vol.Required(ATTR_PROFILE): cv.string,
            vol.Required(ATTR_BASE_TEMPERATURE): cv.positive_float,
            vol.Required(ATTR_SIMPLE_PROFILE_DATA): dict,
        },
        func="async_set_schedule_simple_profile",
    )

    platform.async_register_entity_service(
        name=HmipLocalServices.SET_SCHEDULE_SIMPLE_PROFILE_WEEKDAY,
        schema={
            vol.Required(ATTR_PROFILE): cv.string,
            vol.Required(ATTR_WEEKDAY): cv.string,
            vol.Required(ATTR_BASE_TEMPERATURE): cv.positive_float,
            vol.Required(ATTR_SIMPLE_WEEKDAY_LIST): list,
        },
        func="async_set_schedule_simple_profile_weekday",
    )


class HaHomematicClimate(HaHomematicGenericRestoreEntity[BaseCustomDpClimate], ClimateEntity):
    """Representation of the HomematicIP climate entity."""

    _attr_translation_key = "hmip_climate"
    _enable_turn_on_off_backwards_compatibility: bool = False
    __no_recored_attributes = HaHomematicGenericEntity.NO_RECORED_ATTRIBUTES
    __no_recored_attributes.update({ATTR_OPTIMUM_START_STOP, ATTR_TEMPERATURE_OFFSET})
    _unrecorded_attributes = frozenset(__no_recored_attributes)

    def __init__(
        self,
        control_unit: ControlUnit,
        data_point: BaseCustomDpClimate,
    ) -> None:
        """Initialize the climate entity."""
        super().__init__(
            control_unit=control_unit,
            data_point=data_point,
        )
        self._attr_temperature_unit = UnitOfTemperature.CELSIUS
        self._attr_target_temperature_step = data_point.target_temperature_step

    @property
    def target_temperature(self) -> float | None:
        """Return the temperature we try to reach."""
        if self._data_point.is_valid:
            return self._data_point.target_temperature
        if self.is_restored and self._restored_state:
            return self._restored_state.attributes.get(ATTR_TEMPERATURE)
        return None

    @property
    def current_temperature(self) -> float | None:
        """Return the current temperature."""
        if self._data_point.is_valid:
            return self._data_point.current_temperature
        if self.is_restored and self._restored_state:
            return self._restored_state.attributes.get(ATTR_CURRENT_TEMPERATURE)
        return None

    @property
    def current_humidity(self) -> int | None:
        """Return the current humidity."""
        if self._data_point.is_valid:
            return self._data_point.current_humidity
        if self.is_restored and self._restored_state:
            return self._restored_state.attributes.get(ATTR_CURRENT_HUMIDITY)
        return None

    @property
    def hvac_action(self) -> HVACAction | None:
        """Return the hvac action."""
        if self._data_point.activity and self._data_point.activity in HM_TO_HA_ACTION:
            return HM_TO_HA_ACTION[self._data_point.activity]
        return None

    @property
    def hvac_mode(self) -> HVACMode | None:
        """Return hvac mode."""
        if self._data_point.is_valid:
            if self._data_point.mode in HM_TO_HA_HVAC_MODE:
                return HM_TO_HA_HVAC_MODE[self._data_point.mode]
            return HVACMode.OFF
        if (
            self.is_restored
            and self._restored_state
            and (restored_state := self._restored_state.state)
            not in (
                STATE_UNKNOWN,
                STATE_UNAVAILABLE,
            )
        ):
            return HVACMode(value=restored_state)
        return None

    @property
    def hvac_modes(self) -> list[HVACMode]:
        """Return the list of available hvac modes."""
        return [
            HM_TO_HA_HVAC_MODE[mode]
            for mode in self._data_point.modes
            if mode in HM_TO_HA_HVAC_MODE
        ]

    @property
    def min_temp(self) -> float:
        """Return the minimum temperature."""
        return self._data_point.min_temp

    @property
    def max_temp(self) -> float:
        """Return the maximum temperature."""
        return self._data_point.max_temp

    @property
    def preset_mode(self) -> str | None:
        """Return the current preset mode."""
        if (
            self._data_point.is_valid
            and self._data_point.profile in SUPPORTED_HA_PRESET_MODES
            or str(self._data_point.profile).startswith(PROFILE_PREFIX)
        ):
            return self._data_point.profile
        if self.is_restored and self._restored_state:
            return self._restored_state.attributes.get(ATTR_PRESET_MODE)
        return None

    @property
    def preset_modes(self) -> list[str]:
        """Return a list of available preset modes incl. hmip profiles."""
        preset_modes = []
        for profile in self._data_point.profiles:
            if profile in SUPPORTED_HA_PRESET_MODES:
                preset_modes.append(profile.value)
            if str(profile).startswith(PROFILE_PREFIX):
                preset_modes.append(profile.value)
        return preset_modes

    @property
    def supported_features(self) -> ClimateEntityFeature:
        """Return the list of supported features."""
        supported_features = (
            ClimateEntityFeature.TARGET_TEMPERATURE
            | ClimateEntityFeature.TURN_OFF
            | ClimateEntityFeature.TURN_ON
        )
        if self._data_point.supports_profiles:
            supported_features |= ClimateEntityFeature.PRESET_MODE
        return supported_features

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes of the climate entity."""
        attributes = super().extra_state_attributes
        if (
            hasattr(self._data_point, "temperature_offset")
            and (temperature_offset := self._data_point.temperature_offset) is not None
        ):
            attributes[ATTR_TEMPERATURE_OFFSET] = temperature_offset
        if (
            hasattr(self._data_point, "optimum_start_stop")
            and (optimum_start_stop := self._data_point.optimum_start_stop) is not None
        ):
            attributes[ATTR_OPTIMUM_START_STOP] = optimum_start_stop
        return attributes

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set new target temperature."""
        if (temperature := kwargs.get(ATTR_TEMPERATURE)) is None:
            return
        await self._data_point.set_temperature(temperature=temperature)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set new target hvac mode."""
        if hvac_mode not in HA_TO_HM_HVAC_MODE:
            _LOGGER.warning("Hvac mode %s is not supported by integration", hvac_mode)
            return
        await self._data_point.set_mode(mode=HA_TO_HM_HVAC_MODE[hvac_mode])

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        """Set new preset mode."""
        if preset_mode not in self.preset_modes:
            _LOGGER.warning(
                "Preset mode %s is not supported in hvac_mode %s",
                preset_mode,
                self.hvac_mode,
            )
            return
        await self._data_point.set_profile(profile=ClimateProfile(preset_mode))

    async def async_enable_away_mode_by_calendar(
        self,
        end: datetime,
        away_temperature: float,
        start: datetime | None = None,
    ) -> None:
        """Enable the away mode by calendar on thermostat."""
        start = start or datetime.now() - timedelta(minutes=10)
        await self._data_point.enable_away_mode_by_calendar(
            start=start, end=end, away_temperature=away_temperature
        )

    async def async_enable_away_mode_by_duration(
        self, hours: int, away_temperature: float
    ) -> None:
        """Enable the away mode by duration on thermostat."""
        await self._data_point.enable_away_mode_by_duration(
            hours=hours, away_temperature=away_temperature
        )

    async def async_disable_away_mode(self) -> None:
        """Disable the away mode on thermostat."""
        await self._data_point.disable_away_mode()

    async def async_copy_schedule(self, source_entity_id: str) -> None:
        """Copy a schedule from this entity to another."""
        if source_climate_data_point := cast(
            BaseCustomDpClimate,
            self._data_point.device.central.get_data_point_by_custom_id(
                custom_id=source_entity_id
            ),
        ):
            await source_climate_data_point.copy_schedule(
                target_climate_data_point=self._data_point
            )

    async def async_copy_schedule_profile(
        self, source_profile: str, target_profile: str, source_entity_id: str | None = None
    ) -> None:
        """Copy a schedule profile."""
        if source_entity_id and (
            source_climate_data_point := cast(
                BaseCustomDpClimate,
                self._data_point.device.central.get_data_point_by_custom_id(
                    custom_id=source_entity_id
                ),
            )
        ):
            await source_climate_data_point.copy_schedule_profile(
                source_profile=source_profile,
                target_profile=target_profile,
                target_climate_data_point=self._data_point,
            )
        else:
            await self._data_point.copy_schedule_profile(
                source_profile=source_profile, target_profile=target_profile
            )

    async def async_get_schedule_profile(self, profile: str) -> ServiceResponse:
        """Return the schedule profile."""
        return await self._data_point.get_schedule_profile(profile=profile)  # type: ignore[no-any-return]

    async def async_get_schedule_profile_weekday(
        self, profile: str, weekday: str
    ) -> ServiceResponse:
        """Return the schedule profile weekday."""
        return await self._data_point.get_schedule_profile_weekday(  # type: ignore[no-any-return]
            profile=profile, weekday=weekday
        )

    async def async_set_schedule_profile(self, profile: str, profile_data: PROFILE_DICT) -> None:
        """Set the schedule profile."""
        for p_key, p_value in profile_data.items():
            profile_data[p_key] = {int(key): value for key, value in p_value.items()}
        await self._data_point.set_schedule_profile(profile=profile, profile_data=profile_data)

    async def async_set_schedule_simple_profile(
        self, profile: str, base_temperature: float, simple_profile_data: SIMPLE_PROFILE_DICT
    ) -> None:
        """Set the schedule simple profile."""
        await self._data_point.set_simple_schedule_profile(
            profile=profile,
            base_temperature=base_temperature,
            simple_profile_data=simple_profile_data,
        )

    async def async_set_schedule_profile_weekday(
        self, profile: str, weekday: str, weekday_data: WEEKDAY_DICT
    ) -> None:
        """Set the schedule profile weekday."""
        weekday_data = {int(key): value for key, value in weekday_data.items()}
        await self._data_point.set_schedule_profile_weekday(
            profile=profile, weekday=weekday, weekday_data=weekday_data
        )

    async def async_set_schedule_simple_profile_weekday(
        self,
        profile: str,
        weekday: str,
        base_temperature: float,
        simple_weekday_list: SIMPLE_WEEKDAY_LIST,
    ) -> None:
        """Set the schedule simple profile weekday."""
        await self._data_point.set_simple_schedule_profile_weekday(
            profile=profile,
            weekday=weekday,
            base_temperature=base_temperature,
            simple_weekday_list=simple_weekday_list,
        )
