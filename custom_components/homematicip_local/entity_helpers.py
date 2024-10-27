"""Support for Homematic(IP) Local sensors."""

from __future__ import annotations

from collections.abc import Mapping
import dataclasses
from dataclasses import dataclass
from enum import StrEnum
import logging
from typing import Final

from hahomematic.const import DataPointCategory
from hahomematic.model.custom import CustomDataPoint
from hahomematic.model.generic import GenericDataPoint
from hahomematic.model.hub import GenericHubDataPoint
from hahomematic.support import element_matches_key

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntityDescription,
)
from homeassistant.components.button import ButtonEntityDescription
from homeassistant.components.cover import CoverDeviceClass, CoverEntityDescription
from homeassistant.components.lock import LockEntityDescription
from homeassistant.components.number import NumberDeviceClass, NumberEntityDescription
from homeassistant.components.select import SelectEntityDescription
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.components.siren import SirenEntityDescription
from homeassistant.components.switch import SwitchDeviceClass, SwitchEntityDescription
from homeassistant.const import (
    CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
    CONCENTRATION_PARTS_PER_MILLION,
    DEGREE,
    LIGHT_LUX,
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    EntityCategory,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfFrequency,
    UnitOfLength,
    UnitOfPower,
    UnitOfPressure,
    UnitOfSpeed,
    UnitOfTemperature,
    UnitOfTime,
    UnitOfVolume,
    UnitOfVolumeFlowRate,
)
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.typing import UNDEFINED, UndefinedType

from .support import HmGenericDataPoint

_LOGGER = logging.getLogger(__name__)

CONCENTRATION_CM3: Final = "1/cm\u00b3"  # HmIP-SFD
CONCENTRATION_GRAMS_PER_CUBIC_METER: Final = "g/m³"  # HB-UNI-Sensor-THPD-BME280
LENGTH_MICROMETER: Final = "\u00b5m"  # HmIP-SFD


class HmNameSource(StrEnum):
    """Enum to define the source of a translation."""

    DEVICE_CLASS = "device_class"
    ENTITY_NAME = "entity_name"
    PARAMETER = "parameter"


@dataclass(frozen=True, kw_only=True)
class HmEntityDescription:
    """Base class describing Homematic(IP) Local entities."""

    name_source: HmNameSource = HmNameSource.PARAMETER


@dataclass(frozen=True, kw_only=True)
class HmNumberEntityDescription(HmEntityDescription, NumberEntityDescription):
    """Class describing Homematic(IP) Local number entities."""

    multiplier: int | None = None


@dataclass(frozen=True, kw_only=True)
class HmSelectEntityDescription(HmEntityDescription, SelectEntityDescription):
    """Class describing Homematic(IP) Local select entities."""


@dataclass(frozen=True, kw_only=True)
class HmSensorEntityDescription(HmEntityDescription, SensorEntityDescription):
    """Class describing Homematic(IP) Local sensor entities."""

    multiplier: int | None = None


@dataclass(frozen=True, kw_only=True)
class HmBinarySensorEntityDescription(HmEntityDescription, BinarySensorEntityDescription):
    """Class describing Homematic(IP) Local binary sensor entities."""


@dataclass(frozen=True, kw_only=True)
class HmButtonEntityDescription(HmEntityDescription, ButtonEntityDescription):
    """Class describing Homematic(IP) Local button entities."""


_NUMBER_DESCRIPTIONS_BY_PARAM: Mapping[str | tuple[str, ...], EntityDescription] = {
    "FREQUENCY": HmNumberEntityDescription(
        key="FREQUENCY",
        device_class=NumberDeviceClass.FREQUENCY,
        native_unit_of_measurement=UnitOfFrequency.HERTZ,
    ),
    ("LEVEL", "LEVEL_2"): HmNumberEntityDescription(
        key="LEVEL",
        multiplier=100,
        native_unit_of_measurement=PERCENTAGE,
    ),
}

_NUMBER_DESCRIPTIONS_BY_DEVICE_AND_PARAM: Mapping[
    tuple[str | tuple[str, ...], str], EntityDescription
] = {
    (
        ("HmIP-eTRV", "HmIP-HEATING"),
        "LEVEL",
    ): HmNumberEntityDescription(
        key="LEVEL",
        multiplier=100,
        native_unit_of_measurement=PERCENTAGE,
        entity_registry_enabled_default=False,
        translation_key="pipe_level",
    ),
    ("HMW-IO-12-Sw14-DR", "FREQUENCY"): HmNumberEntityDescription(
        key="FREQUENCY",
        native_unit_of_measurement="mHz",
        translation_key="frequency",
    ),
}


_SELECT_DESCRIPTIONS_BY_PARAM: Mapping[str | tuple[str, ...], EntityDescription] = {
    "HEATING_COOLING": HmSelectEntityDescription(
        key="HEATING_COOLING",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
        translation_key="heating_cooling",
    )
}


_SENSOR_DESCRIPTIONS_BY_PARAM: Mapping[str | tuple[str, ...], EntityDescription] = {
    "AIR_PRESSURE": HmSensorEntityDescription(
        key="AIR_PRESSURE",
        native_unit_of_measurement=UnitOfPressure.HPA,
        device_class=SensorDeviceClass.PRESSURE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "BRIGHTNESS": HmSensorEntityDescription(
        key="BRIGHTNESS",
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="brightness",
    ),
    "CARRIER_SENSE_LEVEL": HmSensorEntityDescription(
        key="CARRIER_SENSE_LEVEL",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    "CODE_ID": HmSensorEntityDescription(
        key="CODE_ID",
    ),
    "CONCENTRATION": HmSensorEntityDescription(
        key="CONCENTRATION",
        native_unit_of_measurement=CONCENTRATION_PARTS_PER_MILLION,
        device_class=SensorDeviceClass.CO2,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "CURRENT": HmSensorEntityDescription(
        key="CURRENT",
        native_unit_of_measurement=UnitOfElectricCurrent.MILLIAMPERE,
        device_class=SensorDeviceClass.CURRENT,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "DEWPOINT": HmSensorEntityDescription(
        key="DEWPOINT",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    ("ACTIVITY_STATE", "DIRECTION"): HmSensorEntityDescription(
        key="DIRECTION",
        device_class=SensorDeviceClass.ENUM,
        translation_key="direction",
    ),
    "DOOR_STATE": HmSensorEntityDescription(
        key="DOOR_STATE",
        device_class=SensorDeviceClass.ENUM,
        translation_key="door_state",
    ),
    "DUTY_CYCLE_LEVEL": HmSensorEntityDescription(
        key="DUTY_CYCLE_LEVEL",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    "ENERGY_COUNTER": HmSensorEntityDescription(
        key="ENERGY_COUNTER",
        native_unit_of_measurement=UnitOfEnergy.WATT_HOUR,
        device_class=SensorDeviceClass.ENERGY,
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    "FILLING_LEVEL": HmSensorEntityDescription(
        key="FILLING_LEVEL",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "FREQUENCY": HmSensorEntityDescription(
        key="FREQUENCY",
        native_unit_of_measurement=UnitOfFrequency.HERTZ,
        device_class=SensorDeviceClass.FREQUENCY,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "GAS_ENERGY_COUNTER": HmSensorEntityDescription(
        key="GAS_ENERGY_COUNTER",
        native_unit_of_measurement=UnitOfVolume.CUBIC_METERS,
        device_class=SensorDeviceClass.GAS,
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    "GAS_FLOW": HmSensorEntityDescription(
        key="GAS_FLOW",
        native_unit_of_measurement=UnitOfVolumeFlowRate.CUBIC_METERS_PER_HOUR,
        device_class=SensorDeviceClass.VOLUME_FLOW_RATE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "GAS_POWER": HmSensorEntityDescription(
        key="GAS_POWER",
        native_unit_of_measurement=UnitOfVolume.CUBIC_METERS,
    ),
    "GAS_VOLUME": HmSensorEntityDescription(
        key="GAS_VOLUME",
        native_unit_of_measurement=UnitOfVolume.CUBIC_METERS,
        device_class=SensorDeviceClass.GAS,
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    ("HUMIDITY", "ACTUAL_HUMIDITY"): HmSensorEntityDescription(
        key="HUMIDITY",
        native_unit_of_measurement=PERCENTAGE,
        device_class=SensorDeviceClass.HUMIDITY,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "IEC_ENERGY_COUNTER": HmSensorEntityDescription(
        key="IEC_ENERGY_COUNTER",
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        device_class=SensorDeviceClass.ENERGY,
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    "IEC_POWER": HmSensorEntityDescription(
        key="IEC_POWER",
        native_unit_of_measurement=UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    (
        "ILLUMINATION",
        "AVERAGE_ILLUMINATION",
        "CURRENT_ILLUMINATION",
        "HIGHEST_ILLUMINATION",
        "LOWEST_ILLUMINATION",
        "LUX",
    ): HmSensorEntityDescription(
        key="ILLUMINATION",
        native_unit_of_measurement=LIGHT_LUX,
        device_class=SensorDeviceClass.ILLUMINANCE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "IP_ADDRESS": HmSensorEntityDescription(
        key="IP_ADDRESS",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    ("LEVEL", "LEVEL_2"): HmSensorEntityDescription(
        key="LEVEL",
        native_unit_of_measurement=PERCENTAGE,
        multiplier=100,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "LOCK_STATE": HmSensorEntityDescription(
        key="LOCK_STATE",
        device_class=SensorDeviceClass.ENUM,
        translation_key="lock_state",
    ),
    (
        "MASS_CONCENTRATION_PM_1",
        "MASS_CONCENTRATION_PM_1_24H_AVERAGE",
    ): HmSensorEntityDescription(
        key="MASS_CONCENTRATION_PM_1",
        native_unit_of_measurement=CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
        device_class=SensorDeviceClass.PM1,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    (
        "MASS_CONCENTRATION_PM_10",
        "MASS_CONCENTRATION_PM_10_24H_AVERAGE",
    ): HmSensorEntityDescription(
        key="MASS_CONCENTRATION_PM_10",
        native_unit_of_measurement=CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
        device_class=SensorDeviceClass.PM10,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    (
        "MASS_CONCENTRATION_PM_2_5",
        "MASS_CONCENTRATION_PM_2_5_24H_AVERAGE",
    ): HmSensorEntityDescription(
        key="MASS_CONCENTRATION_PM_2_5",
        native_unit_of_measurement=CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
        device_class=SensorDeviceClass.PM25,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "NUMBER_CONCENTRATION_PM_1": HmSensorEntityDescription(
        key="NUMBER_CONCENTRATION_PM_1",
        native_unit_of_measurement=CONCENTRATION_CM3,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "NUMBER_CONCENTRATION_PM_10": HmSensorEntityDescription(
        key="NUMBER_CONCENTRATION_PM_10",
        native_unit_of_measurement=CONCENTRATION_CM3,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "NUMBER_CONCENTRATION_PM_2_5": HmSensorEntityDescription(
        key="NUMBER_CONCENTRATION_PM_2_5",
        native_unit_of_measurement=CONCENTRATION_CM3,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "TYPICAL_PARTICLE_SIZE": HmSensorEntityDescription(
        key="TYPICAL_PARTICLE_SIZE",
        native_unit_of_measurement=LENGTH_MICROMETER,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    ("BATTERY_STATE", "OPERATING_VOLTAGE"): HmSensorEntityDescription(
        key="OPERATING_VOLTAGE",
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    "POWER": HmSensorEntityDescription(
        key="POWER",
        native_unit_of_measurement=UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "RAIN_COUNTER": HmSensorEntityDescription(
        key="RAIN_COUNTER",
        native_unit_of_measurement=UnitOfLength.MILLIMETERS,
        state_class=SensorStateClass.TOTAL_INCREASING,
        translation_key="rain_counter",
    ),
    ("RSSI_DEVICE", "RSSI_PEER"): HmSensorEntityDescription(
        key="RSSI",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    ("ACTUAL_TEMPERATURE", "TEMPERATURE"): HmSensorEntityDescription(
        key="TEMPERATURE",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "SMOKE_DETECTOR_ALARM_STATUS": HmSensorEntityDescription(
        key="SMOKE_DETECTOR_ALARM_STATUS",
        device_class=SensorDeviceClass.ENUM,
        translation_key="smoke_detector_alarm_status",
    ),
    "SUNSHINEDURATION": HmSensorEntityDescription(
        key="SUNSHINEDURATION",
        native_unit_of_measurement=UnitOfTime.MINUTES,
        state_class=SensorStateClass.TOTAL_INCREASING,
        translation_key="sunshineduration",
    ),
    "VALUE": HmSensorEntityDescription(
        key="VALUE",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "VAPOR_CONCENTRATION": HmSensorEntityDescription(
        key="VAPOR_CONCENTRATION",
        native_unit_of_measurement=CONCENTRATION_GRAMS_PER_CUBIC_METER,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "VOLTAGE": HmSensorEntityDescription(
        key="VOLTAGE",
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    (
        "WIND_DIR",
        "WIND_DIR_RANGE",
        "WIND_DIRECTION",
        "WIND_DIRECTION_RANGE",
    ): HmSensorEntityDescription(
        key="WIND_DIR",
        native_unit_of_measurement=DEGREE,
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="wind_dir",
    ),
    "WIND_SPEED": HmSensorEntityDescription(
        key="WIND_SPEED",
        native_unit_of_measurement=UnitOfSpeed.KILOMETERS_PER_HOUR,
        device_class=SensorDeviceClass.WIND_SPEED,
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="wind_speed",
    ),
}

_SENSOR_DESCRIPTIONS_BY_DEVICE_AND_PARAM: Mapping[
    tuple[str | tuple[str, ...], str], EntityDescription
] = {
    (
        "HmIP-WKP",
        "CODE_STATE",
    ): HmSensorEntityDescription(
        key="WKP_CODE_STATE",
        device_class=SensorDeviceClass.ENUM,
        translation_key="wkp_code_state",
    ),
    (
        ("HmIP-SRH", "HM-Sec-RHS", "HM-Sec-xx", "ZEL STG RM FDK"),
        "STATE",
    ): HmSensorEntityDescription(
        key="SRH_STATE",
        device_class=SensorDeviceClass.ENUM,
        translation_key="srh_state",
    ),
    ("HM-Sec-Win", "STATUS"): HmSensorEntityDescription(
        key="SEC-WIN_STATUS",
        device_class=SensorDeviceClass.ENUM,
        translation_key="sec_win_status",
    ),
    ("HM-Sec-Win", "DIRECTION"): HmSensorEntityDescription(
        key="SEC-WIN_DIRECTION",
        device_class=SensorDeviceClass.ENUM,
        translation_key="sec_direction",
    ),
    ("HM-Sec-Win", "ERROR"): HmSensorEntityDescription(
        key="SEC-WIN_ERROR",
        device_class=SensorDeviceClass.ENUM,
        translation_key="sec_win_error",
    ),
    ("HM-Sec-Key", "DIRECTION"): HmSensorEntityDescription(
        key="SEC-KEY_DIRECTION",
        device_class=SensorDeviceClass.ENUM,
        translation_key="sec_direction",
    ),
    ("HM-Sec-Key", "ERROR"): HmSensorEntityDescription(
        key="SEC-KEY_ERROR",
        device_class=SensorDeviceClass.ENUM,
        translation_key="sec_key_error",
    ),
    (
        ("HmIP-eTRV", "HmIP-HEATING", "HmIP-FALMOT-C12", "HmIPW-FALMOT-C12"),
        "LEVEL",
    ): HmSensorEntityDescription(
        key="LEVEL",
        native_unit_of_measurement=PERCENTAGE,
        multiplier=100,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        translation_key="pipe_level",
    ),
    (
        ("HmIP-BROLL", "HmIP-FROLL", "HmIP-BBL", "HmIP-DRBLI4", "HmIPW-DRBL4", "HmIP-FBL"),
        "LEVEL",
    ): HmSensorEntityDescription(
        key="LEVEL",
        native_unit_of_measurement=PERCENTAGE,
        multiplier=100,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        translation_key="cover_level",
    ),
    (
        (
            "HmIP-BSL",
            "HmIP-RGBW",
            "HmIPW-WRC6",
        ),
        "COLOR",
    ): HmSensorEntityDescription(
        key="COLOR",
        entity_registry_enabled_default=False,
    ),
    (
        (
            "HmIP-BSL",
            "HmIP-BDT",
            "HmIP-DRDI3",
            "HmIP-FDT",
            "HmIPW-PDT",
            "HmIP-RGBW",
            "HmIP-SCTH230",
            "HmIPW-DRD3",
            "HmIPW-WRC6",
        ),
        "LEVEL",
    ): HmSensorEntityDescription(
        key="LEVEL",
        native_unit_of_measurement=PERCENTAGE,
        multiplier=100,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        translation_key="light_level",
    ),
    (
        ("HmIP-BBL", "HmIP-DRBLI4", "HmIPW-DRBL4", "HmIP-FBL"),
        "LEVEL_2",
    ): HmSensorEntityDescription(
        key="LEVEL",
        native_unit_of_measurement=PERCENTAGE,
        multiplier=100,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        translation_key="cover_tilt",
    ),
    ("HMW-IO-12-Sw14-DR", "FREQUENCY"): HmSensorEntityDescription(
        key="FREQUENCY",
        native_unit_of_measurement="mHz",
        translation_key="frequency",
    ),
    (("HM-CC-RT-DN", "HM-CC-VD"), "VALVE_STATE"): HmSensorEntityDescription(
        key="VALVE_STATE",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        translation_key="pipe_level",
    ),
}

_SENSOR_DESCRIPTIONS_BY_UNIT: Mapping[str, EntityDescription] = {
    PERCENTAGE: HmSensorEntityDescription(
        key="PERCENTAGE",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    UnitOfPressure.BAR: HmSensorEntityDescription(
        key="PRESSURE_BAR",
        native_unit_of_measurement=UnitOfPressure.BAR,
        device_class=SensorDeviceClass.PRESSURE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    UnitOfTemperature.CELSIUS: HmSensorEntityDescription(
        key="TEMPERATURE",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    CONCENTRATION_GRAMS_PER_CUBIC_METER: HmSensorEntityDescription(
        key="CONCENTRATION_GRAMS_PER_CUBIC_METER",
        native_unit_of_measurement=CONCENTRATION_GRAMS_PER_CUBIC_METER,
        state_class=SensorStateClass.MEASUREMENT,
    ),
}


_BINARY_SENSOR_DESCRIPTIONS_BY_PARAM: Mapping[str | tuple[str, ...], EntityDescription] = {
    "ALARMSTATE": HmBinarySensorEntityDescription(
        key="ALARMSTATE",
        device_class=BinarySensorDeviceClass.SAFETY,
    ),
    "ACOUSTIC_ALARM_ACTIVE": HmBinarySensorEntityDescription(
        key="ACOUSTIC_ALARM_ACTIVE",
        device_class=BinarySensorDeviceClass.SAFETY,
    ),
    ("BLOCKED_PERMANENT", "BLOCKED_TEMPORARY"): HmBinarySensorEntityDescription(
        key="BLOCKED",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    "BURST_LIMIT_WARNING": HmBinarySensorEntityDescription(
        key="BURST_LIMIT_WARNING",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    ("DUTYCYCLE", "DUTY_CYCLE"): HmBinarySensorEntityDescription(
        key="DUTY_CYCLE",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    "DEW_POINT_ALARM": HmBinarySensorEntityDescription(
        key="DEW_POINT_ALARM",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_registry_enabled_default=False,
    ),
    "EMERGENCY_OPERATION": HmBinarySensorEntityDescription(
        key="EMERGENCY_OPERATION",
        device_class=BinarySensorDeviceClass.SAFETY,
        entity_registry_enabled_default=False,
    ),
    "ERROR_JAMMED": HmBinarySensorEntityDescription(
        key="ERROR_JAMMED",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_registry_enabled_default=False,
    ),
    "HEATER_STATE": HmBinarySensorEntityDescription(
        key="HEATER_STATE",
        device_class=BinarySensorDeviceClass.HEAT,
    ),
    ("LOWBAT", "LOW_BAT", "LOWBAT_SENSOR"): HmBinarySensorEntityDescription(
        key="LOW_BAT",
        device_class=BinarySensorDeviceClass.BATTERY,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    "MOISTURE_DETECTED": HmBinarySensorEntityDescription(
        key="MOISTURE_DETECTED",
        device_class=BinarySensorDeviceClass.MOISTURE,
    ),
    "MOTION": HmBinarySensorEntityDescription(
        key="MOTION",
        device_class=BinarySensorDeviceClass.MOTION,
    ),
    "OPTICAL_ALARM_ACTIVE": HmBinarySensorEntityDescription(
        key="OPTICAL_ALARM_ACTIVE",
        device_class=BinarySensorDeviceClass.SAFETY,
    ),
    "POWER_MAINS_FAILURE": HmBinarySensorEntityDescription(
        key="POWER_MAINS_FAILURE",
        device_class=BinarySensorDeviceClass.POWER,
    ),
    "PRESENCE_DETECTION_STATE": HmBinarySensorEntityDescription(
        key="PRESENCE_DETECTION_STATE",
        device_class=BinarySensorDeviceClass.PRESENCE,
    ),
    ("PROCESS", "WORKING"): HmBinarySensorEntityDescription(
        key="PROCESS",
        device_class=BinarySensorDeviceClass.RUNNING,
    ),
    "RAINING": HmBinarySensorEntityDescription(
        key="RAINING",
        device_class=BinarySensorDeviceClass.MOISTURE,
    ),
    ("SABOTAGE", "SABOTAGE_STICKY"): HmBinarySensorEntityDescription(
        key="SABOTAGE",
        device_class=BinarySensorDeviceClass.TAMPER,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    "WATERLEVEL_DETECTED": HmBinarySensorEntityDescription(
        key="WATERLEVEL_DETECTED",
        device_class=BinarySensorDeviceClass.MOISTURE,
    ),
    "WINDOW_STATE": HmBinarySensorEntityDescription(
        key="WINDOW_STATE",
        device_class=BinarySensorDeviceClass.WINDOW,
    ),
}

_BINARY_SENSOR_DESCRIPTIONS_BY_DEVICE_AND_PARAM: Mapping[
    tuple[str | tuple[str, ...], str], EntityDescription
] = {
    ("HmIP-DSD-PCB", "STATE"): HmBinarySensorEntityDescription(
        key="STATE",
        device_class=BinarySensorDeviceClass.OCCUPANCY,
    ),
    (
        ("HmIP-SCI", "HmIP-FCI1", "HmIP-FCI6"),
        "STATE",
    ): HmBinarySensorEntityDescription(
        key="STATE",
        device_class=BinarySensorDeviceClass.OPENING,
    ),
    ("HM-Sec-SD", "STATE"): HmBinarySensorEntityDescription(
        key="STATE",
        device_class=BinarySensorDeviceClass.SMOKE,
    ),
    (
        (
            "HmIP-SWD",
            "HmIP-SWDO",
            "HmIP-SWDM",
            "HM-Sec-SC",
            "HM-SCI-3-FM",
            "ZEL STG RM FFK",
        ),
        "STATE",
    ): HmBinarySensorEntityDescription(
        key="STATE",
        device_class=BinarySensorDeviceClass.WINDOW,
    ),
    ("HM-Sen-RD-O", "STATE"): HmBinarySensorEntityDescription(
        key="STATE",
        device_class=BinarySensorDeviceClass.MOISTURE,
    ),
    ("HM-Sec-Win", "WORKING"): HmBinarySensorEntityDescription(
        key="WORKING",
        device_class=BinarySensorDeviceClass.RUNNING,
        entity_registry_enabled_default=False,
    ),
}


_BUTTOM_DESCRIPTIONS_BY_PARAM: Mapping[str | tuple[str, ...], EntityDescription] = {
    "RESET_MOTION": HmButtonEntityDescription(
        key="RESET_MOTION",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
    "RESET_PRESENCE": HmButtonEntityDescription(
        key="RESET_PRESENCE",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
}

_COVER_DESCRIPTIONS_BY_DEVICE: Mapping[str | tuple[str, ...], EntityDescription] = {
    ("HmIP-BBL", "HmIP-FBL", "HmIP-DRBLI4", "HmIPW-DRBL4"): CoverEntityDescription(
        key="BLIND",
        device_class=CoverDeviceClass.BLIND,
    ),
    ("HmIP-BROLL", "HmIP-FROLL"): CoverEntityDescription(
        key="SHUTTER",
        device_class=CoverDeviceClass.SHUTTER,
    ),
    "HmIP-HDM1": CoverEntityDescription(
        key="HmIP-HDM1",
        device_class=CoverDeviceClass.SHADE,
    ),
    ("HmIP-MOD-HO", "HmIP-MOD-TM"): CoverEntityDescription(
        key="GARAGE-HO",
        device_class=CoverDeviceClass.GARAGE,
    ),
    "HM-Sec-Win": CoverEntityDescription(
        key="HM-Sec-Win",
        device_class=CoverDeviceClass.WINDOW,
    ),
}

_SIREN_DESCRIPTIONS_BY_DEVICE: Mapping[str | tuple[str, ...], EntityDescription] = {
    "HmIP-SWSD": SirenEntityDescription(
        key="SWSD",
        entity_registry_enabled_default=False,
    ),
}

_SWITCH_DESCRIPTIONS_BY_DEVICE: Mapping[str | tuple[str, ...], EntityDescription] = {
    "HmIP-PS": SwitchEntityDescription(
        key="OUTLET",
        device_class=SwitchDeviceClass.OUTLET,
    ),
}

_SWITCH_DESCRIPTIONS_BY_PARAM: Mapping[str | tuple[str, ...], EntityDescription] = {
    "INHIBIT": SwitchEntityDescription(
        key="INHIBIT",
        device_class=SwitchDeviceClass.SWITCH,
        entity_registry_enabled_default=False,
    ),
    ("MOTION_DETECTION_ACTIVE", "PRESENCE_DETECTION_ACTIVE"): SwitchEntityDescription(
        key="MOTION_DETECTION_ACTIVE",
        device_class=SwitchDeviceClass.SWITCH,
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
}

_LOCK_DESCRIPTIONS_BY_POSTFIX: Mapping[str | tuple[str, ...], EntityDescription] = {
    "BUTTON_LOCK": LockEntityDescription(
        key="BUTTON_LOCK",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
        translation_key="button_lock",
    ),
}

_ENTITY_DESCRIPTION_BY_DEVICE: Mapping[
    DataPointCategory, Mapping[str | tuple[str, ...], EntityDescription]
] = {
    DataPointCategory.COVER: _COVER_DESCRIPTIONS_BY_DEVICE,
    DataPointCategory.SIREN: _SIREN_DESCRIPTIONS_BY_DEVICE,
    DataPointCategory.SWITCH: _SWITCH_DESCRIPTIONS_BY_DEVICE,
}

_ENTITY_DESCRIPTION_BY_PARAM: Mapping[
    DataPointCategory, Mapping[str | tuple[str, ...], EntityDescription]
] = {
    DataPointCategory.BINARY_SENSOR: _BINARY_SENSOR_DESCRIPTIONS_BY_PARAM,
    DataPointCategory.BUTTON: _BUTTOM_DESCRIPTIONS_BY_PARAM,
    DataPointCategory.NUMBER: _NUMBER_DESCRIPTIONS_BY_PARAM,
    DataPointCategory.SELECT: _SELECT_DESCRIPTIONS_BY_PARAM,
    DataPointCategory.SENSOR: _SENSOR_DESCRIPTIONS_BY_PARAM,
    DataPointCategory.SWITCH: _SWITCH_DESCRIPTIONS_BY_PARAM,
}

_ENTITY_DESCRIPTION_BY_POSTFIX: Mapping[
    DataPointCategory, Mapping[str | tuple[str, ...], EntityDescription]
] = {
    DataPointCategory.LOCK: _LOCK_DESCRIPTIONS_BY_POSTFIX,
}

_ENTITY_DESCRIPTION_BY_DEVICE_AND_PARAM: Mapping[
    DataPointCategory, Mapping[tuple[str | tuple[str, ...], str], EntityDescription]
] = {
    DataPointCategory.BINARY_SENSOR: _BINARY_SENSOR_DESCRIPTIONS_BY_DEVICE_AND_PARAM,
    DataPointCategory.NUMBER: _NUMBER_DESCRIPTIONS_BY_DEVICE_AND_PARAM,
    DataPointCategory.SENSOR: _SENSOR_DESCRIPTIONS_BY_DEVICE_AND_PARAM,
}


_DEFAULT_PLATFORM_DESCRIPTION: Mapping[DataPointCategory, EntityDescription] = {
    DataPointCategory.BUTTON: HmButtonEntityDescription(
        key="button_default",
        entity_registry_enabled_default=False,
        translation_key="button_press",
    ),
    DataPointCategory.SWITCH: SwitchEntityDescription(
        key="switch_default",
        device_class=SwitchDeviceClass.SWITCH,
    ),
    DataPointCategory.SELECT: SelectEntityDescription(
        key="select_default", entity_category=EntityCategory.CONFIG
    ),
    DataPointCategory.HUB_BUTTON: HmButtonEntityDescription(
        key="hub_button_default",
        entity_registry_enabled_default=False,
        translation_key="button_press",
    ),
    DataPointCategory.HUB_SWITCH: SwitchEntityDescription(
        key="hub_switch_default",
        device_class=SwitchDeviceClass.SWITCH,
    ),
}


def get_entity_description(
    data_point: HmGenericDataPoint | GenericHubDataPoint | CustomDataPoint,
) -> EntityDescription | None:
    """Get the entity_description."""
    if entity_desc := _find_entity_description(data_point=data_point):
        name, translation_key = get_name_and_translation_key(
            data_point=data_point, entity_desc=entity_desc
        )
        enabled_default = (
            entity_desc.entity_registry_enabled_default if data_point.enabled_default else False
        )
        return dataclasses.replace(
            entity_desc,
            name=name,
            translation_key=translation_key,
            has_entity_name=True,
            entity_registry_enabled_default=enabled_default,
        )

    return None


def get_name_and_translation_key(
    data_point: HmGenericDataPoint | GenericHubDataPoint | CustomDataPoint,
    entity_desc: EntityDescription,
) -> tuple[str | UndefinedType | None, str | None]:
    """Get the name and translation_key."""
    if isinstance(data_point, GenericDataPoint):
        if isinstance(entity_desc, HmEntityDescription) and entity_desc.translation_key is None:
            if entity_desc.name_source == HmNameSource.PARAMETER:
                return None, data_point.parameter.lower()
            if entity_desc.name_source == HmNameSource.DEVICE_CLASS:
                return UNDEFINED, None

        if entity_desc.translation_key is None:
            return None, data_point.parameter.lower()
        return None, entity_desc.translation_key

    if isinstance(data_point, CustomDataPoint):
        if entity_desc.translation_key is None and data_point.name_data.parameter_name:
            return None, data_point.name_data.parameter_name.lower()
        return None, entity_desc.translation_key

    # custom data points use the customizable name from the CCU WebUI,
    # that does not need to be translated in HA
    return data_point.name, None


def _find_entity_description(
    data_point: HmGenericDataPoint | GenericHubDataPoint | CustomDataPoint,
) -> EntityDescription | None:
    """Find the entity_description for platform."""
    if isinstance(data_point, GenericDataPoint):
        if entity_desc := _get_entity_description_by_model_and_param(data_point=data_point):
            return entity_desc

        if entity_desc := _get_entity_description_by_param(data_point=data_point):
            return entity_desc

        if (
            data_point.category == DataPointCategory.SENSOR
            and data_point.unit
            and (entity_desc := _SENSOR_DESCRIPTIONS_BY_UNIT.get(data_point.unit))
        ):
            return entity_desc

    if isinstance(data_point, CustomDataPoint):
        if entity_desc := _get_entity_description_by_model(data_point=data_point):
            return entity_desc

        if entity_desc := _get_entity_description_by_postfix(data_point=data_point):
            return entity_desc

    return _DEFAULT_PLATFORM_DESCRIPTION.get(data_point.category)


def _get_entity_description_by_model_and_param(
    data_point: GenericDataPoint,
) -> EntityDescription | None:
    """Get entity_description by model and parameter."""
    if platform_device_and_param_descriptions := _ENTITY_DESCRIPTION_BY_DEVICE_AND_PARAM.get(  # noqa: E501
        data_point.category
    ):
        for data, entity_desc in platform_device_and_param_descriptions.items():
            if data[1] == data_point.parameter and (
                element_matches_key(
                    search_elements=data[0],
                    compare_with=data_point.device.model,
                )
            ):
                return entity_desc
    return None


def _get_entity_description_by_param(
    data_point: GenericDataPoint,
) -> EntityDescription | None:
    """Get entity_description by model and parameter."""
    if platform_param_descriptions := _ENTITY_DESCRIPTION_BY_PARAM.get(data_point.category):
        for params, entity_desc in platform_param_descriptions.items():
            if _param_in_list(params=params, parameter=data_point.parameter):
                return entity_desc
    return None


def _get_entity_description_by_postfix(
    data_point: CustomDataPoint,
) -> EntityDescription | None:
    """Get entity_description by model and parameter."""
    if platform_postfix_descriptions := _ENTITY_DESCRIPTION_BY_POSTFIX.get(data_point.category):
        for postfix, entity_desc in platform_postfix_descriptions.items():
            if _param_in_list(params=postfix, parameter=data_point.data_point_name_postfix):
                return entity_desc
    return None


def _get_entity_description_by_model(
    data_point: HmGenericDataPoint,
) -> EntityDescription | None:
    """Get entity_description by model."""
    if platform_device_descriptions := _ENTITY_DESCRIPTION_BY_DEVICE.get(data_point.category):
        for devices, entity_desc in platform_device_descriptions.items():
            if element_matches_key(
                search_elements=devices,
                compare_with=data_point.device.model,
            ):
                return entity_desc
    return None


def _param_in_list(params: str | tuple[str, ...], parameter: str) -> bool:
    """Return if parameter is in set."""
    if isinstance(params, str):
        return parameter.lower() == params.lower()
    if isinstance(params, tuple):
        for device in params:
            if parameter.lower() == device.lower():
                return True
    return False
