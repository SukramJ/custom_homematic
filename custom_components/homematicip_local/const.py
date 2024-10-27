"""Constants."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from hahomematic.const import CATEGORIES

from homeassistant.const import Platform

DOMAIN: Final = "homematicip_local"
HMIP_LOCAL_MIN_HA_VERSION: Final = "2024.10.0dev0"
HMIP_LOCAL_HAHOMEMATIC_VERSION: Final = "2024.10.16"

DEFAULT_DEVICE_FIRMWARE_CHECK_ENABLED: Final = True
DEFAULT_DEVICE_FIRMWARE_CHECK_INTERVAL: Final = 21600  # 6h
DEFAULT_DEVICE_FIRMWARE_DELIVERING_CHECK_INTERVAL: Final = 3600  # 1h
DEFAULT_DEVICE_FIRMWARE_UPDATING_CHECK_INTERVAL: Final = 300  # 5m
DEFAULT_ENABLE_SYSTEM_NOTIFICATIONS: Final = True
DEFAULT_LISTEN_ON_ALL_IP: Final = False
DEFAULT_PROGRAM_SCAN_ENABLED: Final = True
DEFAULT_SYSVAR_SCAN_ENABLED: Final = True
DEFAULT_SYS_SCAN_INTERVAL: Final = 30
DEFAULT_UN_IGNORE: Final[list[str]] = []

LEARN_MORE_URL_XMLRPC_SERVER_RECEIVES_NO_EVENTS: Final = "https://github.com/danielperna84/custom_homematic#what-is-the-meaning-of-xmlrpc-server-received-no-events"
LEARN_MORE_URL_PONG_MISMATCH: Final = "https://github.com/danielperna84/custom_homematic#what-is-the-meaning-of-pingpong-mismatch-on-interface"


CONF_ADVANCED_CONFIG: Final = "advanced_config"
CONF_CALLBACK_HOST: Final = "callback_host"
CONF_LISTEN_ON_ALL_IP: Final = "listen_on_all_ip"
CONF_CALLBACK_PORT: Final = "callback_port"
CONF_ENABLE_SYSTEM_NOTIFICATIONS: Final = "enable_system_notifications"
CONF_EVENT_TYPE: Final = "event_type"
CONF_INSTANCE_NAME: Final = "instance_name"
CONF_INTERFACE: Final = "interface"
CONF_INTERFACE_ID: Final = "interface_id"
CONF_JSON_PORT: Final = "json_port"
CONF_SUBTYPE: Final = "subtype"
CONF_PROGRAM_SCAN_ENABLED: Final = "program_scan_enabled"
CONF_SYSVAR_SCAN_ENABLED: Final = "sysvar_scan_enabled"
CONF_SYS_SCAN_INTERVAL: Final = "sysvar_scan_interval"
CONF_TLS: Final = "tls"
CONF_UN_IGNORE: Final = "un_ignore"
CONF_VERIFY_TLS: Final = "verify_tls"

EVENT_DEVICE_ID: Final = "device_id"
EVENT_ERROR: Final = "error"
EVENT_ERROR_VALUE: Final = "error_value"
EVENT_IDENTIFIER: Final = "identifier"
EVENT_MESSAGE: Final = "message"
EVENT_MODEL: Final = "model"
EVENT_NAME: Final = "name"
EVENT_TITLE: Final = "title"
EVENT_UNAVAILABLE: Final = "unavailable"

SERVICE_CLEAR_CACHE: Final = "clear_cache"
SERVICE_COPY_SCHEDULE: Final = "copy_schedule"
SERVICE_COPY_SCHEDULE_PROFILE: Final = "copy_schedule_profile"
SERVICE_CREATE_CENTRAL_LINKS: Final = "create_central_links"
SERVICE_DISABLE_AWAY_MODE: Final = "disable_away_mode"
SERVICE_ENABLE_AWAY_MODE_BY_CALENDAR: Final = "enable_away_mode_by_calendar"
SERVICE_ENABLE_AWAY_MODE_BY_DURATION: Final = "enable_away_mode_by_duration"
SERVICE_EXPORT_DEVICE_DEFINITION: Final = "export_device_definition"
SERVICE_FETCH_SYSTEM_VARIABLES: Final = "fetch_system_variables"
SERVICE_FORCE_DEVICE_AVAILABILITY: Final = "force_device_availability"
SERVICE_GET_DEVICE_VALUE: Final = "get_device_value"
SERVICE_GET_LINK_PARAMSET: Final = "get_link_paramset"
SERVICE_GET_LINK_PEERS: Final = "get_link_peers"
SERVICE_GET_PARAMSET: Final = "get_paramset"
SERVICE_GET_SCHEDULE_PROFILE: Final = "get_schedule_profile"
SERVICE_GET_SCHEDULE_PROFILE_WEEKDAY: Final = "get_schedule_profile_weekday"
SERVICE_LIGHT_SET_ON_TIME: Final = "light_set_on_time"
SERVICE_PUT_LINK_PARAMSET: Final = "put_link_paramset"
SERVICE_PUT_PARAMSET: Final = "put_paramset"
SERVICE_REMOVE_CENTRAL_LINKS: Final = "remove_central_links"
SERVICE_SET_COVER_COMBINED_POSITION: Final = "set_cover_combined_position"
SERVICE_SET_DEVICE_VALUE: Final = "set_device_value"
SERVICE_SET_INSTALL_MODE: Final = "set_install_mode"
SERVICE_SET_SCHEDULE_PROFILE: Final = "set_schedule_profile"
SERVICE_SET_SCHEDULE_PROFILE_WEEKDAY: Final = "set_schedule_profile_weekday"
SERVICE_SET_SCHEDULE_SIMPLE_PROFILE: Final = "set_schedule_simple_profile"
SERVICE_SET_SCHEDULE_SIMPLE_PROFILE_WEEKDAY: Final = "set_schedule_simple_profile_weekday"
SERVICE_SET_VARIABLE_VALUE: Final = "set_variable_value"
SERVICE_SWITCH_SET_ON_TIME: Final = "switch_set_on_time"
SERVICE_TURN_ON_SIREN: Final = "turn_on_siren"
SERVICE_UPDATE_DEVICE_FIRMWARE_DATA: Final = "update_device_firmware_data"

HMIP_LOCAL_SERVICES: Final = (
    SERVICE_CLEAR_CACHE,
    SERVICE_COPY_SCHEDULE,
    SERVICE_COPY_SCHEDULE_PROFILE,
    SERVICE_CREATE_CENTRAL_LINKS,
    SERVICE_DISABLE_AWAY_MODE,
    SERVICE_ENABLE_AWAY_MODE_BY_CALENDAR,
    SERVICE_ENABLE_AWAY_MODE_BY_DURATION,
    SERVICE_EXPORT_DEVICE_DEFINITION,
    SERVICE_FETCH_SYSTEM_VARIABLES,
    SERVICE_FORCE_DEVICE_AVAILABILITY,
    SERVICE_GET_DEVICE_VALUE,
    SERVICE_GET_LINK_PARAMSET,
    SERVICE_GET_LINK_PEERS,
    SERVICE_GET_PARAMSET,
    SERVICE_GET_SCHEDULE_PROFILE,
    SERVICE_GET_SCHEDULE_PROFILE_WEEKDAY,
    SERVICE_LIGHT_SET_ON_TIME,
    SERVICE_PUT_LINK_PARAMSET,
    SERVICE_PUT_PARAMSET,
    SERVICE_REMOVE_CENTRAL_LINKS,
    SERVICE_SET_COVER_COMBINED_POSITION,
    SERVICE_SET_DEVICE_VALUE,
    SERVICE_SET_INSTALL_MODE,
    SERVICE_SET_SCHEDULE_PROFILE,
    SERVICE_SET_SCHEDULE_PROFILE_WEEKDAY,
    SERVICE_SET_SCHEDULE_SIMPLE_PROFILE,
    SERVICE_SET_SCHEDULE_SIMPLE_PROFILE_WEEKDAY,
    SERVICE_SET_VARIABLE_VALUE,
    SERVICE_SWITCH_SET_ON_TIME,
    SERVICE_TURN_ON_SIREN,
    SERVICE_UPDATE_DEVICE_FIRMWARE_DATA,
)

TOTAL_SYSVAR: Final[tuple[str, ...]] = (
    "svEnergyCounter_",
    "svHmIPRainCounter_",
    "svHmIPSunshineCounter_",
)

# filter out event error parameters, that should not be displayed in logbook
FILTER_ERROR_EVENT_PARAMETERS: Final[tuple[str, ...]] = ("ERROR_CODE",)


class HmEntityState(StrEnum):
    """Enum with homematic entity states."""

    NOT_VALID = "not valid"
    RESTORED = "restored"
    UNCERTAIN = "uncertain"
    VALID = "valid"


BLOCKED_CATEGORIES: Final[tuple[str, ...]] = ()


def _get_hmip_local_platforms() -> tuple[Platform, ...]:
    """Return relevant Homematic(IP) Local platforms."""
    return tuple(
        Platform(pf)
        for pf in list(Platform)
        if pf in [category.value for category in CATEGORIES if category not in BLOCKED_CATEGORIES]
    )


HMIP_LOCAL_PLATFORMS: Final[tuple[Platform, ...]] = _get_hmip_local_platforms()
