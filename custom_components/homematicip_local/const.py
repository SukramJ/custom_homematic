"""Constants."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from hahomematic.const import CATEGORIES

from homeassistant.const import Platform

DOMAIN: Final = "homematicip_local"
HMIP_LOCAL_MIN_HA_VERSION: Final = "2024.12.0"
ENABLE_EXPERIMENTAL_FEATURES: Final = False

HMIP_LOCAL_HAHOMEMATIC_VERSION: Final = "2025.2.0"

DEFAULT_ENABLE_DEVICE_FIRMWARE_CHECK: Final = True
DEFAULT_ENABLE_SYSTEM_NOTIFICATIONS: Final = True
DEFAULT_LISTEN_ON_ALL_IP: Final = False
DEFAULT_ENABLE_MQTT: Final = False
DEFAULT_MQTT_PREFIX: Final = ""

LEARN_MORE_URL_XMLRPC_SERVER_RECEIVES_NO_EVENTS: Final = "https://github.com/sukramj/custom_homematic?tab=readme-ov-file#what-is-the-meaning-of-xmlrpc-server-received-no-events--xmlrpc-server-empf%C3%A4ngt-keine-ereignisse"
LEARN_MORE_URL_PONG_MISMATCH: Final = "https://github.com/sukramj/custom_homematic#what-is-the-meaning-of-pending-pong-mismatch-on-interface--austehende-pong-ereignisse-auf-interface"

CONF_ADVANCED_CONFIG: Final = "advanced_config"
CONF_CALLBACK_HOST: Final = "callback_host"
CONF_CALLBACK_PORT: Final = "callback_port"
CONF_ENABLE_MQTT: Final = "mqtt_enabled"
CONF_ENABLE_PROGRAM_SCAN: Final = "program_scan_enabled"
CONF_ENABLE_SYSTEM_NOTIFICATIONS: Final = "enable_system_notifications"
CONF_ENABLE_SYSVAR_SCAN: Final = "sysvar_scan_enabled"
CONF_EVENT_TYPE: Final = "event_type"
CONF_INSTANCE_NAME: Final = "instance_name"
CONF_INTERFACE: Final = "interface"
CONF_INTERFACE_ID: Final = "interface_id"
CONF_JSON_PORT: Final = "json_port"
CONF_LISTEN_ON_ALL_IP: Final = "listen_on_all_ip"
CONF_MQTT_PREFIX: Final = "mqtt_prefix"
CONF_PROGRAM_MARKERS: Final = "program_markers"
CONF_SUBTYPE: Final = "subtype"
CONF_SYSVAR_MARKERS: Final = "sysvar_markers"
CONF_SYS_SCAN_INTERVAL: Final = "sysvar_scan_interval"
CONF_TLS: Final = "tls"
CONF_UN_IGNORES: Final = "un_ignore"
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


class HmipLocalServices(StrEnum):
    """Enum with services."""

    CLEAR_CACHE = "clear_cache"
    COPY_SCHEDULE = "copy_schedule"
    COPY_SCHEDULE_PROFILE = "copy_schedule_profile"
    CREATE_CENTRAL_LINKS = "create_central_links"
    DISABLE_AWAY_MODE = "disable_away_mode"
    ENABLE_AWAY_MODE_BY_CALENDAR = "enable_away_mode_by_calendar"
    ENABLE_AWAY_MODE_BY_DURATION = "enable_away_mode_by_duration"
    EXPORT_DEVICE_DEFINITION = "export_device_definition"
    FETCH_SYSTEM_VARIABLES = "fetch_system_variables"
    FORCE_DEVICE_AVAILABILITY = "force_device_availability"
    GET_DEVICE_VALUE = "get_device_value"
    GET_LINK_PARAMSET = "get_link_paramset"
    GET_LINK_PEERS = "get_link_peers"
    GET_PARAMSET = "get_paramset"
    GET_SCHEDULE_PROFILE = "get_schedule_profile"
    GET_SCHEDULE_PROFILE_WEEKDAY = "get_schedule_profile_weekday"
    GET_VARIABLE_VALUE = "get_variable_value"
    LIGHT_SET_ON_TIME = "light_set_on_time"
    PUT_LINK_PARAMSET = "put_link_paramset"
    PUT_PARAMSET = "put_paramset"
    REMOVE_CENTRAL_LINKS = "remove_central_links"
    SET_COVER_COMBINED_POSITION = "set_cover_combined_position"
    SET_DEVICE_VALUE = "set_device_value"
    SET_SCHEDULE_PROFILE = "set_schedule_profile"
    SET_SCHEDULE_PROFILE_WEEKDAY = "set_schedule_profile_weekday"
    SET_SCHEDULE_SIMPLE_PROFILE = "set_schedule_simple_profile"
    SET_SCHEDULE_SIMPLE_PROFILE_WEEKDAY = "set_schedule_simple_profile_weekday"
    SET_VARIABLE_VALUE = "set_variable_value"
    SWITCH_SET_ON_TIME = "switch_set_on_time"
    TURN_ON_SIREN = "turn_on_siren"
    UPDATE_DEVICE_FIRMWARE_DATA = "update_device_firmware_data"


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
