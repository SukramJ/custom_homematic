"""Homematic(IP) local is a Python 3 module for Home Assistant and Homematic(IP) devices."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import datetime, timedelta
import logging
from types import UnionType
from typing import Any, Final, TypeVar, cast

from hahomematic.central import INTERFACE_EVENT_SCHEMA, CentralConfig, CentralUnit
from hahomematic.client import InterfaceConfig
from hahomematic.const import (
    CALLBACK_TYPE,
    CONF_PASSWORD,
    CONF_USERNAME,
    IP_ANY_V4,
    PORT_ANY,
    BackendSystemEvent,
    DataPointCategory,
    DeviceFirmwareState,
    EventKey,
    EventType,
    Interface,
    InterfaceEventType,
    Manufacturer,
    Parameter,
    SystemInformation,
)
from hahomematic.exceptions import BaseHomematicException
from hahomematic.model.data_point import CallbackDataPoint
from hahomematic.support import check_config

from homeassistant.const import CONF_HOST, CONF_PATH, CONF_PORT
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import aiohttp_client, device_registry as dr
from homeassistant.helpers.device_registry import DeviceEntry, DeviceEntryType, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.issue_registry import (
    IssueSeverity,
    async_create_issue,
    async_delete_issue,
)

from .const import (
    CONF_ADVANCED_CONFIG,
    CONF_CALLBACK_HOST,
    CONF_CALLBACK_PORT,
    CONF_ENABLE_SYSTEM_NOTIFICATIONS,
    CONF_INSTANCE_NAME,
    CONF_INTERFACE,
    CONF_JSON_PORT,
    CONF_LISTEN_ON_ALL_IP,
    CONF_MQTT_ENABLED,
    CONF_MQTT_PREFIX,
    CONF_PROGRAM_SCAN_ENABLED,
    CONF_SYS_SCAN_INTERVAL,
    CONF_SYSVAR_SCAN_ENABLED,
    CONF_TLS,
    CONF_UN_IGNORE,
    CONF_VERIFY_TLS,
    DEFAULT_DEVICE_FIRMWARE_CHECK_ENABLED,
    DEFAULT_DEVICE_FIRMWARE_CHECK_INTERVAL,
    DEFAULT_DEVICE_FIRMWARE_DELIVERING_CHECK_INTERVAL,
    DEFAULT_DEVICE_FIRMWARE_UPDATING_CHECK_INTERVAL,
    DEFAULT_ENABLE_SYSTEM_NOTIFICATIONS,
    DEFAULT_LISTEN_ON_ALL_IP,
    DEFAULT_MQTT_ENABLED,
    DEFAULT_MQTT_PREFIX,
    DEFAULT_PROGRAM_SCAN_ENABLED,
    DEFAULT_SYS_SCAN_INTERVAL,
    DEFAULT_SYSVAR_SCAN_ENABLED,
    DEFAULT_UN_IGNORE,
    DOMAIN,
    EVENT_DEVICE_ID,
    EVENT_ERROR,
    EVENT_ERROR_VALUE,
    EVENT_IDENTIFIER,
    EVENT_MESSAGE,
    EVENT_NAME,
    EVENT_TITLE,
    EVENT_UNAVAILABLE,
    FILTER_ERROR_EVENT_PARAMETERS,
    LEARN_MORE_URL_PONG_MISMATCH,
    LEARN_MORE_URL_XMLRPC_SERVER_RECEIVES_NO_EVENTS,
)
from .mqtt import MQTTConsumer
from .support import (
    CLICK_EVENT_SCHEMA,
    DEVICE_AVAILABILITY_EVENT_SCHEMA,
    DEVICE_ERROR_EVENT_SCHEMA,
    InvalidConfig,
    cleanup_click_event_data,
    is_valid_event,
)

_LOGGER = logging.getLogger(__name__)
_DATA_POINT_T = TypeVar("_DATA_POINT_T", bound=CallbackDataPoint)


class BaseControlUnit:
    """Base central point to control a central unit."""

    def __init__(self, control_config: ControlConfig) -> None:
        """Init the control unit."""
        self._config: Final = control_config
        self._hass = control_config.hass
        self._entry_id = control_config.entry_id
        self._default_callback_port = control_config.default_callback_port
        self._start_direct = control_config.start_direct
        self._instance_name = control_config.instance_name
        self._enable_system_notifications = control_config.enable_system_notifications
        self._central: CentralUnit = self._create_central()
        self._attr_device_info: DeviceInfo | None = None
        self._unregister_callbacks: list[CALLBACK_TYPE] = []

    async def start_central(self) -> None:
        """Start the central unit."""
        _LOGGER.debug(
            "Starting central unit %s",
            self._instance_name,
        )
        try:
            await self._central.start()
            _LOGGER.info("Started central unit for %s", self._instance_name)
        except BaseHomematicException:
            _LOGGER.warning(
                "START_CENTRAL: Failed to start central unit for %s", self._instance_name
            )

    async def stop_central(self, *args: Any) -> None:
        """Stop the control unit."""
        _LOGGER.debug(
            "Stopping central unit %s",
            self._instance_name,
        )
        if self._central.started:
            await self._central.stop()
            _LOGGER.info("Stopped central unit for %s", self._instance_name)

    @property
    def central(self) -> CentralUnit:
        """Return the Homematic(IP) Local central unit instance."""
        return self._central

    @property
    def config(self) -> ControlConfig:
        """Return the Homematic(IP) Local central unit instance."""
        return self._config

    @property
    def device_info(self) -> DeviceInfo | None:
        """Return device specific attributes."""
        if not self._attr_device_info:
            self._attr_device_info = DeviceInfo(
                identifiers={
                    (
                        DOMAIN,
                        self._central.name,
                    )
                },
                manufacturer=Manufacturer.EQ3,
                model=self._central.model,
                name=self._central.name,
                serial_number=self._central.system_information.serial,
                sw_version=self._central.version,
            )
        return self._attr_device_info

    def _create_central(self) -> CentralUnit:
        """Create the central unit for ccu callbacks."""
        interface_configs: set[InterfaceConfig] = set()
        for interface_name in self._config.interface_config:
            interface = self._config.interface_config[interface_name]
            interface_configs.add(
                InterfaceConfig(
                    central_name=self._instance_name,
                    interface=Interface(interface_name),
                    port=interface.get(CONF_PORT),
                    remote_path=interface.get(CONF_PATH),
                )
            )
        # use last 10 chars of entry_id for central_id uniqueness
        central_id = self._entry_id[-10:]
        return CentralConfig(
            callback_host=self._config.callback_host
            if self._config.callback_host != IP_ANY_V4
            else None,
            callback_port=self._config.callback_port
            if self._config.callback_port != PORT_ANY
            else None,
            central_id=central_id,
            client_session=aiohttp_client.async_get_clientsession(self._hass),
            listen_ip_addr=IP_ANY_V4 if self._config.listen_on_all_ip else None,
            default_callback_port=self._default_callback_port,
            host=self._config.host,
            interface_configs=interface_configs,
            json_port=self._config.json_port,
            max_read_workers=1,
            name=self._instance_name,
            password=self._config.password,
            program_scan_enabled=self._config.program_scan_enabled,
            start_direct=self._start_direct,
            storage_folder=get_storage_folder(self._hass),
            sysvar_scan_enabled=self._config.sysvar_scan_enabled,
            tls=self._config.tls,
            un_ignore_list=self._config.un_ignore,
            username=self._config.username,
            verify_tls=self._config.verify_tls,
        ).create_central()


class ControlUnit(BaseControlUnit):
    """Unit to control a central unit."""

    def __init__(self, control_config: ControlConfig) -> None:
        """Init the control unit."""
        super().__init__(control_config=control_config)
        self._scheduler = HmScheduler(
            hass=self._hass,
            control_unit=self,
        )
        self._mqtt_consumer: MQTTConsumer | None = None

    async def start_central(self) -> None:
        """Start the central unit."""
        self._unregister_callbacks.append(
            self._central.register_backend_system_callback(cb=self._async_backend_system_callback)
        )

        self._unregister_callbacks.append(
            self._central.register_homematic_callback(cb=self._async_homematic_callback)
        )
        await super().start_central()
        self._async_add_central_to_device_registry()
        if self.config.mqtt_enabled:
            self._mqtt_consumer = MQTTConsumer(
                hass=self._hass, central=self._central, mqtt_prefix=self.config.mqtt_prefix
            )
            await self._mqtt_consumer.subscribe()

    async def stop_central(self, *args: Any) -> None:
        """Stop the central unit."""
        if self._mqtt_consumer:
            self._mqtt_consumer.unsubscribe()
        if self._scheduler.initialized:
            self._scheduler.de_init()

        for unregister in self._unregister_callbacks:
            if unregister is not None:
                unregister()

        await super().stop_central(*args)

    @callback
    def _async_add_central_to_device_registry(self) -> None:
        """Add the central to device registry."""
        device_registry = dr.async_get(self._hass)
        device_registry.async_get_or_create(
            config_entry_id=self._entry_id,
            identifiers={
                (
                    DOMAIN,
                    self._central.name,
                )
            },
            manufacturer=Manufacturer.EQ3,
            model=self._central.model,
            sw_version=self._central.version,
            name=self._central.name,
            entry_type=DeviceEntryType.SERVICE,
            configuration_url=self._central.central_url,
        )

    @callback
    def _async_add_virtual_remotes_to_device_registry(self) -> None:
        """Add the virtual remotes to device registry."""
        if not self._central.has_clients:
            _LOGGER.error(
                "Cannot create ControlUnit %s virtual remote devices. No clients",
                self._instance_name,
            )
            return

        device_registry = dr.async_get(self._hass)
        for virtual_remote in self._central.get_virtual_remotes():
            device_registry.async_get_or_create(
                config_entry_id=self._entry_id,
                identifiers={
                    (
                        DOMAIN,
                        virtual_remote.identifier,
                    )
                },
                manufacturer=Manufacturer.EQ3,
                name=virtual_remote.name,
                model=virtual_remote.model,
                sw_version=virtual_remote.firmware,
                # Link to the homematic control unit.
                via_device=cast(tuple[str, str], self._central.name),
            )

    @callback
    def _async_backend_system_callback(
        self, system_event: BackendSystemEvent, **kwargs: Any
    ) -> None:
        """Execute the callback for system based events."""
        _LOGGER.debug(
            "callback_system_event: Received system event %s for event for %s",
            system_event,
            self._instance_name,
        )

        # Handle event of new device creation in Homematic(IP) Local.
        if system_event == BackendSystemEvent.DEVICES_CREATED:
            for platform, data_points in kwargs["new_data_points"].items():
                if data_points and len(data_points) > 0:
                    async_dispatcher_send(
                        self._hass,
                        signal_new_data_point(entry_id=self._entry_id, platform=platform),
                        data_points,
                    )
            for channel_events in kwargs["new_channel_events"]:
                async_dispatcher_send(
                    self._hass,
                    signal_new_data_point(
                        entry_id=self._entry_id, platform=DataPointCategory.EVENT
                    ),
                    channel_events,
                )
            self._async_add_virtual_remotes_to_device_registry()
        elif system_event == BackendSystemEvent.HUB_REFRESHED:
            if not self._scheduler.initialized:
                self._hass.create_task(target=self._scheduler.init())

            # Handle event of new hub entity creation in Homematic(IP) Local.
            for platform, hub_data_points in kwargs["new_hub_data_points"].items():
                if hub_data_points and len(hub_data_points) > 0:
                    async_dispatcher_send(
                        self._hass,
                        signal_new_data_point(entry_id=self._entry_id, platform=platform),
                        hub_data_points,
                    )
            return
        return

    @callback
    def _async_homematic_callback(self, event_type: EventType, event_data: dict[str, Any]) -> None:
        """Execute the callback used for device related events."""

        interface_id = event_data[EventKey.INTERFACE_ID]
        if event_type == EventType.INTERFACE:
            interface_event_type = event_data[EventKey.TYPE]
            issue_id = f"{interface_event_type}-{interface_id}"
            event_data = cast(dict[str, Any], INTERFACE_EVENT_SCHEMA(event_data))
            data = event_data[EventKey.DATA]
            if interface_event_type == InterfaceEventType.CALLBACK:
                if not self._enable_system_notifications:
                    _LOGGER.debug("SYSTEM NOTIFICATION disabled for CALLBACK")
                    return
                if data[EventKey.AVAILABLE]:
                    async_delete_issue(hass=self._hass, domain=DOMAIN, issue_id=issue_id)
                else:
                    async_create_issue(
                        hass=self._hass,
                        domain=DOMAIN,
                        issue_id=issue_id,
                        is_fixable=False,
                        learn_more_url=LEARN_MORE_URL_XMLRPC_SERVER_RECEIVES_NO_EVENTS,
                        severity=IssueSeverity.WARNING,
                        translation_key="xmlrpc_server_receives_no_events",
                        translation_placeholders={
                            EventKey.INTERFACE_ID: interface_id,
                            EventKey.SECONDS_SINCE_LAST_EVENT: data[
                                EventKey.SECONDS_SINCE_LAST_EVENT
                            ],
                        },
                    )
            elif interface_event_type == InterfaceEventType.PENDING_PONG:
                if not self._enable_system_notifications:
                    _LOGGER.debug("SYSTEM NOTIFICATION disabled for PENDING_PONG")
                    return
                if data[EventKey.PONG_MISMATCH_COUNT] == 0:
                    async_delete_issue(
                        hass=self._hass,
                        domain=DOMAIN,
                        issue_id=issue_id,
                    )
                else:
                    async_create_issue(
                        hass=self._hass,
                        domain=DOMAIN,
                        issue_id=issue_id,
                        is_fixable=False,
                        learn_more_url=LEARN_MORE_URL_PONG_MISMATCH,
                        severity=IssueSeverity.WARNING,
                        translation_key="pending_pong_mismatch",
                        translation_placeholders={
                            CONF_INSTANCE_NAME: self._instance_name,
                            EventKey.INTERFACE_ID: interface_id,
                        },
                    )
            elif interface_event_type == InterfaceEventType.PROXY:
                if data[EventKey.AVAILABLE]:
                    async_delete_issue(hass=self._hass, domain=DOMAIN, issue_id=issue_id)
                else:
                    async_create_issue(
                        hass=self._hass,
                        domain=DOMAIN,
                        issue_id=issue_id,
                        is_fixable=False,
                        severity=IssueSeverity.WARNING,
                        translation_key="interface_not_reachable",
                        translation_placeholders={
                            EventKey.INTERFACE_ID: interface_id,
                        },
                    )
            elif interface_event_type == InterfaceEventType.FETCH_DATA:
                async_create_issue(
                    hass=self._hass,
                    domain=DOMAIN,
                    issue_id=issue_id,
                    is_fixable=False,
                    severity=IssueSeverity.WARNING,
                    translation_key="fetch_data",
                    translation_placeholders={
                        EventKey.INTERFACE_ID: interface_id,
                    },
                )
        else:
            device_address = event_data[EventKey.ADDRESS]
            name: str | None = None
            if device_entry := self._async_get_device_entry(device_address=device_address):
                name = device_entry.name_by_user or device_entry.name
                event_data.update({EVENT_DEVICE_ID: device_entry.id, EVENT_NAME: name})
            if event_type in (EventType.IMPULSE, EventType.KEYPRESS):
                event_data = cleanup_click_event_data(event_data=event_data)
                if is_valid_event(event_data=event_data, schema=CLICK_EVENT_SCHEMA):
                    self._hass.bus.fire(
                        event_type=event_type.value,
                        event_data=event_data,
                    )
            elif event_type == EventType.DEVICE_AVAILABILITY:
                parameter = event_data[EventKey.PARAMETER]
                unavailable = event_data[EventKey.VALUE]
                if parameter in (Parameter.STICKY_UN_REACH, Parameter.UN_REACH):
                    title = f"{DOMAIN.upper()} Device not reachable"
                    event_data.update(
                        {
                            EVENT_IDENTIFIER: f"{device_address}_DEVICE_AVAILABILITY",
                            EVENT_TITLE: title,
                            EVENT_MESSAGE: f"{name}/{device_address} "
                            f"on interface {interface_id}",
                            EVENT_UNAVAILABLE: unavailable,
                        }
                    )
                    if is_valid_event(
                        event_data=event_data,
                        schema=DEVICE_AVAILABILITY_EVENT_SCHEMA,
                    ):
                        self._hass.bus.fire(
                            event_type=event_type.value,
                            event_data=event_data,
                        )
            elif event_type == EventType.DEVICE_ERROR:
                error_parameter = event_data[EventKey.PARAMETER]
                if error_parameter in FILTER_ERROR_EVENT_PARAMETERS:
                    return
                error_parameter_display = error_parameter.replace("_", " ").title()
                title = f"{DOMAIN.upper()} Device Error"
                error_message: str = ""
                error_value = event_data[EventKey.VALUE]
                display_error: bool = False
                if isinstance(error_value, bool):
                    display_error = error_value
                    error_message = (
                        f"{name}/{device_address} on interface {interface_id}: "
                        f"{error_parameter_display}"
                    )
                if isinstance(error_value, int):
                    display_error = error_value != 0
                    error_message = (
                        f"{name}/{device_address} on interface {interface_id}: "
                        f"{error_parameter_display} {error_value}"
                    )
                event_data.update(
                    {
                        EVENT_IDENTIFIER: f"{device_address}_{error_parameter}",
                        EVENT_TITLE: title,
                        EVENT_MESSAGE: error_message,
                        EVENT_ERROR_VALUE: error_value,
                        EVENT_ERROR: display_error,
                    }
                )
                if is_valid_event(event_data=event_data, schema=DEVICE_ERROR_EVENT_SCHEMA):
                    self._hass.bus.fire(
                        event_type=event_type.value,
                        event_data=event_data,
                    )

    @callback
    def _async_get_device_entry(self, device_address: str) -> DeviceEntry | None:
        """Return the device of the ha device."""
        if (hm_device := self._central.get_device(address=device_address)) is None:
            return None
        device_registry = dr.async_get(self._hass)
        return device_registry.async_get_device(
            identifiers={
                (
                    DOMAIN,
                    hm_device.identifier,
                )
            }
        )

    async def fetch_all_system_variables(self) -> None:
        """Fetch all system variables from CCU / Homegear."""
        if not self._scheduler.initialized:
            _LOGGER.debug("Hub scheduler for %s is not initialized", self._instance_name)
            return

        await self._scheduler.fetch_sysvars()

    def get_new_data_points(
        self,
        data_point_type: type[_DATA_POINT_T] | UnionType,
    ) -> tuple[_DATA_POINT_T, ...]:
        """Return all data points by type."""
        category = (
            data_point_type.__args__[0].default_category()
            if isinstance(data_point_type, UnionType)
            else data_point_type.default_category()
        )
        return cast(
            tuple[_DATA_POINT_T, ...],
            self.central.get_data_points(
                category=category,
                exclude_no_create=True,
                registered=False,
            ),
        )

    def get_new_hub_data_points(
        self,
        data_point_type: type[_DATA_POINT_T],
    ) -> tuple[_DATA_POINT_T, ...]:
        """Return all data points by type."""
        return cast(
            tuple[_DATA_POINT_T, ...],
            self.central.get_hub_data_points(
                category=data_point_type.default_category(),
                registered=False,
            ),
        )


class ControlUnitTemp(BaseControlUnit):
    """Central unit to control a central unit for temporary usage."""

    async def stop_central(self, *args: Any) -> None:
        """Stop the control unit."""
        await self._central.clear_caches()
        await super().stop_central(*args)


class ControlConfig:
    """Config for a ControlUnit."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry_id: str,
        data: Mapping[str, Any],
        default_port: int = PORT_ANY,
        start_direct: bool = False,
        device_firmware_check_enabled: bool = DEFAULT_DEVICE_FIRMWARE_CHECK_ENABLED,
        device_firmware_check_interval: int = DEFAULT_DEVICE_FIRMWARE_CHECK_INTERVAL,
        device_firmware_delivering_check_interval: int = DEFAULT_DEVICE_FIRMWARE_DELIVERING_CHECK_INTERVAL,
        device_firmware_updating_check_interval: int = DEFAULT_DEVICE_FIRMWARE_UPDATING_CHECK_INTERVAL,
    ) -> None:
        """Create the required config for the ControlUnit."""
        self.hass: Final = hass
        self.entry_id: Final = entry_id
        self._data: Final = data
        self.default_callback_port: Final = default_port
        self.start_direct: Final = start_direct
        self.device_firmware_check_enabled: Final = device_firmware_check_enabled
        self.device_firmware_check_interval: Final = device_firmware_check_interval
        self.device_firmware_delivering_check_interval: Final = (
            device_firmware_delivering_check_interval
        )
        self.device_firmware_updating_check_interval: Final = (
            device_firmware_updating_check_interval
        )

        # central
        self.instance_name = data[CONF_INSTANCE_NAME]
        self.host = data[CONF_HOST]
        self.username = data[CONF_USERNAME]
        self.password = data[CONF_PASSWORD]
        self.tls = data[CONF_TLS]
        self.verify_tls = data[CONF_VERIFY_TLS]
        self.callback_host = data.get(CONF_CALLBACK_HOST)
        self.callback_port = data.get(CONF_CALLBACK_PORT)
        self.json_port = data.get(CONF_JSON_PORT)

        # interface_config
        self.interface_config = data.get(CONF_INTERFACE, {})
        # advanced_config
        advanced_config = data.get(CONF_ADVANCED_CONFIG, {})
        self.enable_system_notifications = advanced_config.get(
            CONF_ENABLE_SYSTEM_NOTIFICATIONS, DEFAULT_ENABLE_SYSTEM_NOTIFICATIONS
        )
        self.sysvar_scan_enabled: Final = advanced_config.get(
            CONF_SYSVAR_SCAN_ENABLED, DEFAULT_SYSVAR_SCAN_ENABLED
        )
        self.program_scan_enabled: Final = advanced_config.get(
            CONF_PROGRAM_SCAN_ENABLED, DEFAULT_PROGRAM_SCAN_ENABLED
        )
        self.sys_scan_interval: Final = advanced_config.get(
            CONF_SYS_SCAN_INTERVAL, DEFAULT_SYS_SCAN_INTERVAL
        )

        self.listen_on_all_ip = advanced_config.get(
            CONF_LISTEN_ON_ALL_IP, DEFAULT_LISTEN_ON_ALL_IP
        )
        self.mqtt_enabled: Final = advanced_config.get(CONF_MQTT_ENABLED, DEFAULT_MQTT_ENABLED)
        self.mqtt_prefix: Final = advanced_config.get(CONF_MQTT_PREFIX, DEFAULT_MQTT_PREFIX)
        self.un_ignore: Final = advanced_config.get(CONF_UN_IGNORE, DEFAULT_UN_IGNORE)

    def check_config(self) -> None:
        """Check config. Throws BaseHomematicException on failure."""
        if config_failures := check_config(
            central_name=self.instance_name,
            host=self.host,
            username=self.username,
            password=self.password,
            callback_host=self.callback_host,
            callback_port=self.callback_port,
            json_port=self.json_port,
            storage_folder=get_storage_folder(self.hass),
        ):
            failures = ", ".join(config_failures)
            raise InvalidConfig(failures)

    def create_control_unit(self) -> ControlUnit:
        """Identify the used client."""
        return ControlUnit(self)

    def create_control_unit_temp(self) -> ControlUnitTemp:
        """Identify the used client."""
        return ControlUnitTemp(self._temporary_config)

    @property
    def _temporary_config(self) -> ControlConfig:
        """Return a config for validation."""
        temporary_data: dict[str, Any] = deepcopy(dict(self._data))
        temporary_data[CONF_INSTANCE_NAME] = "temporary_instance"
        return ControlConfig(
            hass=self.hass,
            entry_id="hmip_local_temporary",
            data=temporary_data,
            start_direct=True,
        )


class HmScheduler:
    """The Homematic(IP) Local hub scheduler. (CCU/HomeGear)."""

    def __init__(
        self,
        hass: HomeAssistant,
        control_unit: ControlUnit,
    ) -> None:
        """Initialize Homematic(IP) Local hub scheduler."""
        self._hass = hass
        self._control: ControlUnit = control_unit
        self._central: CentralUnit = control_unit.central
        self._initialized = False
        self._remove_device_firmware_check_listener: Callable | None = None
        self._remove_device_firmware_delivering_check_listener: Callable | None = None
        self._remove_device_firmware_updating_check_listener: Callable | None = None
        self._remove_sys_listener: Callable | None = None
        self._sema_init: Final = asyncio.Semaphore()

    @property
    def initialized(self) -> bool:
        """Return initialized state."""
        return self._initialized

    async def init(self) -> None:
        """Execute the initial data refresh."""
        async with self._sema_init:
            if self._initialized:
                return
            self._initialized = True
            if (
                self._control.config.sysvar_scan_enabled
                or self._control.config.program_scan_enabled
            ):
                # sys_scan_interval == 0 means sysvar scanning is disabled
                self._remove_sys_listener = async_track_time_interval(
                    hass=self._hass,
                    action=self._fetch_sys_data,
                    interval=timedelta(seconds=self._control.config.sys_scan_interval),
                    cancel_on_shutdown=True,
                )

            if self._control.config.device_firmware_check_enabled:
                self._remove_device_firmware_check_listener = async_track_time_interval(
                    hass=self._hass,
                    action=self._fetch_device_firmware_update_data,
                    interval=timedelta(
                        seconds=self._control.config.device_firmware_check_interval
                    ),
                    cancel_on_shutdown=True,
                )
                self._remove_device_firmware_delivering_check_listener = async_track_time_interval(
                    hass=self._hass,
                    action=self._fetch_device_firmware_update_data_in_delivery,
                    interval=timedelta(
                        seconds=self._control.config.device_firmware_delivering_check_interval
                    ),
                    cancel_on_shutdown=True,
                )
                self._remove_device_firmware_updating_check_listener = async_track_time_interval(
                    hass=self._hass,
                    action=self._fetch_device_firmware_update_data_in_update,
                    interval=timedelta(
                        seconds=self._control.config.device_firmware_updating_check_interval
                    ),
                )
            await self._central.refresh_firmware_data()

    def de_init(self) -> None:
        """De_init the hub scheduler."""
        if self._remove_sys_listener and callable(self._remove_sys_listener):
            self._remove_sys_listener()
        if self._remove_device_firmware_check_listener and callable(
            self._remove_device_firmware_check_listener
        ):
            self._remove_device_firmware_check_listener()
        if self._remove_device_firmware_delivering_check_listener and callable(
            self._remove_device_firmware_delivering_check_listener
        ):
            self._remove_device_firmware_delivering_check_listener()
        if self._remove_device_firmware_updating_check_listener and callable(
            self._remove_device_firmware_updating_check_listener
        ):
            self._remove_device_firmware_updating_check_listener()
        self._initialized = False

    async def _fetch_sys_data(self, now: datetime) -> None:
        """Fetch data from backend."""
        await self._central.fetch_program_data(scheduled=True)
        await self._central.fetch_sysvar_data(scheduled=True)

    async def fetch_sysvars(self) -> None:
        """Fetch sysvars from backend."""
        await self._central.fetch_sysvar_data(scheduled=False)

    async def _fetch_device_firmware_update_data(self, now: datetime) -> None:
        """Fetch device firmware update data from backend."""
        _LOGGER.debug(
            "Scheduled fetching of device firmware update data for %s",
            self._central.name,
        )
        await self._central.refresh_firmware_data()

    async def _fetch_device_firmware_update_data_in_delivery(self, now: datetime) -> None:
        """Fetch device firmware update data from backend for delivering devices."""
        _LOGGER.debug(
            "Scheduled fetching of device firmware update data for delivering devices for %s",
            self._central.name,
        )
        await self._central.refresh_firmware_data_by_state(
            device_firmware_states=(
                DeviceFirmwareState.DELIVER_FIRMWARE_IMAGE,
                DeviceFirmwareState.LIVE_DELIVER_FIRMWARE_IMAGE,
            )
        )

    async def _fetch_device_firmware_update_data_in_update(self, now: datetime) -> None:
        """Fetch device firmware update data from backend for updating devices."""
        _LOGGER.debug(
            "Scheduled fetching of device firmware update data for updating devices for %s",
            self._central.name,
        )
        await self._central.refresh_firmware_data_by_state(
            device_firmware_states=(
                DeviceFirmwareState.READY_FOR_UPDATE,
                DeviceFirmwareState.DO_UPDATE_PENDING,
                DeviceFirmwareState.PERFORMING_UPDATE,
            )
        )


def signal_new_data_point(entry_id: str, platform: DataPointCategory) -> str:
    """Gateway specific event to signal new device."""
    return f"{DOMAIN}-new-data-point-{entry_id}-{platform.value}"


async def validate_config_and_get_system_information(
    control_config: ControlConfig,
) -> SystemInformation | None:
    """Validate the control configuration."""
    if control_unit := control_config.create_control_unit_temp():
        return await control_unit.central.validate_config_and_get_system_information()
    return None


def get_storage_folder(hass: HomeAssistant) -> str:
    """Return the base path where to store files for this integration."""
    return f"{hass.config.config_dir}/{DOMAIN}"
