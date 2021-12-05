"""
hahomematic is a Python 3 (>= 3.6) module for Home Assistant to interact with
HomeMatic and homematic IP devices.
Some other devices (f.ex. Bosch, Intertechno) might be supported as well.
https://github.com/danielperna84/hahomematic
"""
from __future__ import annotations

from datetime import timedelta
import logging
from types import MappingProxyType
from typing import Any

from hahomematic import config
from hahomematic.central_unit import CentralConfig, CentralUnit
from hahomematic.client import Client, ClientConfig
from hahomematic.const import (
    ATTR_ADDRESS,
    ATTR_CALLBACK_HOST,
    ATTR_CALLBACK_PORT,
    ATTR_HOST,
    ATTR_JSON_PORT,
    ATTR_PASSWORD,
    ATTR_PORT,
    ATTR_TLS,
    ATTR_USERNAME,
    ATTR_VERIFY_TLS,
    AVAILABLE_HM_PLATFORMS,
    HH_EVENT_DELETE_DEVICES,
    HH_EVENT_DEVICES_CREATED,
    HH_EVENT_ERROR,
    HH_EVENT_LIST_DEVICES,
    HH_EVENT_NEW_DEVICES,
    HH_EVENT_RE_ADDED_DEVICE,
    HH_EVENT_REPLACE_DEVICE,
    HH_EVENT_UPDATE_DEVICE,
    IP_ANY_V4,
    PORT_ANY,
    HmEventType,
    HmPlatform,
)
from hahomematic.entity import BaseEntity
from hahomematic.hub import HmHub
from hahomematic.xml_rpc_server import register_xml_rpc_server

from homeassistant.const import CONF_DEVICE_ID
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import aiohttp_client, device_registry as dr
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity import Entity
from homeassistant.util import slugify

from .const import (
    ATTR_INSTANCE_NAME,
    ATTR_INTERFACE,
    ATTR_JSON_TLS,
    ATTR_PATH,
    DOMAIN,
    HAHM_PLATFORMS,
)

_LOGGER = logging.getLogger(__name__)
SCAN_INTERVAL = timedelta(seconds=30)


class ControlUnit:
    """
    Central point to control a Homematic CCU.
    """

    def __init__(self, control_config):
        self._hass = control_config.hass
        self._entry_id = control_config.entry_id
        self._data = control_config.data
        self.enable_virtual_channels = control_config.enable_virtual_channels
        self.enable_sensors_for_system_variables = (
            control_config.enable_sensors_for_system_variables
        )
        self._central: CentralUnit = None
        self._active_hm_entities: dict[str, BaseEntity] = {}
        self._hub = None

    async def start(self) -> None:
        """Start the control unit."""
        _LOGGER.debug("Starting HAHM ControlUnit %s", self._data[ATTR_INSTANCE_NAME])
        config.CACHE_DIR = "cache"

        self.create_central()
        await self.create_clients()
        await self.init_hub()
        self._central.create_devices()
        await self.init_clients()
        self._central.start_connection_checker()

    async def stop(self) -> None:
        """Stop the control unit."""
        _LOGGER.debug("Stopping HAHM ControlUnit %s", self._data[ATTR_INSTANCE_NAME])
        await self._central.stop_connection_checker()
        for client in self._central.clients.values():
            await client.proxy_de_init()
        await self._central.stop()

    async def init_hub(self) -> None:
        """Init the hub."""
        await self._central.init_hub()
        self._hub = HaHub(self._hass, self)
        await self._hub.init()
        hm_entities = [self._central.hub.hub_entities.values()]
        args = [hm_entities]

        async_dispatcher_send(
            self._hass,
            self.async_signal_new_hm_entity(self._entry_id, "hub"),
            *args,  # Don't send device if None, it would override default value in listeners
        )

    @property
    def hub(self) -> HaHub:
        """Return the Hub."""
        return self._hub

    async def init_clients(self):
        """Init clients related to control unit."""
        for client in self._central.clients.values():
            await client.proxy_init()

    @property
    def central(self) -> CentralUnit:
        """return the HAHM central_unit instance."""
        return self._central

    def get_new_hm_entities(self, new_entities) -> dict[HmPlatform, list[BaseEntity]]:
        """
        Return all hm-entities by requested unique_ids
        """
        # init dict
        hm_entities: dict[HmPlatform, list[BaseEntity]] = {}
        for hm_platform in AVAILABLE_HM_PLATFORMS:
            hm_entities[hm_platform] = []

        for entity in new_entities:
            if (
                entity.unique_id not in self._active_hm_entities
                and entity.create_in_ha
                and entity.platform.value in HAHM_PLATFORMS
            ):
                hm_entities[entity.platform].append(entity)

        return hm_entities

    def get_hm_entities_by_platform(self, platform: HmPlatform) -> list[BaseEntity]:
        """
        Return all hm-entities by platform
        """
        hm_entities = []
        for entity in self._central.hm_entities.values():
            if (
                entity.unique_id not in self._active_hm_entities
                and entity.create_in_ha
                and entity.platform == platform
            ):
                hm_entities.append(entity)

        return hm_entities

    def add_hm_entity(self, hm_entity) -> None:
        """add entity to active entities"""
        self._active_hm_entities[hm_entity.unique_id] = hm_entity

    def remove_hm_entity(self, hm_entity) -> None:
        """remove entity from active entities"""
        del self._active_hm_entities[hm_entity.unique_id]

    # pylint: disable=no-self-use
    @callback
    def async_signal_new_hm_entity(self, entry_id: str, device_type) -> str:
        """Gateway specific event to signal new device."""
        return f"hahm-new-entity-{entry_id}-{device_type}"

    @callback
    def _callback_system_event(self, src: str, *args):
        """Callback for ccu based events."""
        if src == HH_EVENT_DEVICES_CREATED:
            new_entity_unique_ids = args[1]
            # Handle event of new device creation in HAHM.
            for (platform, hm_entities) in self.get_new_hm_entities(
                new_entity_unique_ids
            ).items():
                if hm_entities and len(hm_entities) > 0:
                    async_dispatcher_send(
                        self._hass,
                        self.async_signal_new_hm_entity(self._entry_id, platform),
                        [
                            hm_entities
                        ],  # Don't send device if None, it would override default value in listeners
                    )
        elif src == HH_EVENT_NEW_DEVICES:
            # ignore
            return
        elif src == HH_EVENT_DELETE_DEVICES:
            # Handle event of device removed in HAHM.
            for address in args[1]:
                if entity := self._get_active_entity_by_address(address):
                    entity.remove_entity()
            return
        elif src == HH_EVENT_ERROR:
            return
        elif src == HH_EVENT_LIST_DEVICES:
            return
        elif src == HH_EVENT_RE_ADDED_DEVICE:
            return
        elif src == HH_EVENT_REPLACE_DEVICE:
            return
        elif src == HH_EVENT_UPDATE_DEVICE:
            return

    @callback
    def _callback_click_event(
        self, hm_event_type: HmEventType, event_data: dict[str, Any]
    ):
        """Fire event on click."""
        if device_id := self._get_device_id(event_data[ATTR_ADDRESS]):
            event_data[CONF_DEVICE_ID] = device_id

        self._hass.bus.fire(
            hm_event_type.value,
            event_data,
        )

    @callback
    def _callback_alarm_event(
        self, hm_event_type: HmEventType, event_data: dict[str, Any]
    ):
        """Fire event on alarm."""
        if device_id := self._get_device_id(event_data[ATTR_ADDRESS]):
            event_data[CONF_DEVICE_ID] = device_id

        self._hass.bus.fire(
            hm_event_type.value,
            event_data,
        )

    def _get_device_id(self, address: str) -> str | None:
        """Return the device id of the hahm device."""
        hm_device = self.central.hm_devices.get(address)
        identifiers = hm_device.device_info.get("identifiers")
        device_registry = dr.async_get(self._hass)
        device = device_registry.async_get_device(identifiers)
        return device.id if device else None

    def create_central(self) -> None:
        """create the central unit for ccu callbacks."""
        xml_rpc_server = register_xml_rpc_server(
            local_ip=self._data.get(ATTR_CALLBACK_HOST),
            local_port=self._data.get(ATTR_CALLBACK_PORT),
        )
        client_session = aiohttp_client.async_get_clientsession(self._hass)
        self._central = CentralConfig(
            name=self._data[ATTR_INSTANCE_NAME],
            entry_id=self._entry_id,
            loop=self._hass.loop,
            xml_rpc_server=xml_rpc_server,
            host=self._data[ATTR_HOST],
            username=self._data[ATTR_USERNAME],
            password=self._data[ATTR_PASSWORD],
            tls=self._data[ATTR_TLS],
            verify_tls=self._data[ATTR_VERIFY_TLS],
            client_session=client_session,
            json_port=self._data[ATTR_JSON_PORT],
            json_tls=self._data[ATTR_JSON_TLS],
            enable_virtual_channels=self.enable_virtual_channels,
            enable_sensors_for_system_variables=self.enable_sensors_for_system_variables,
        ).get_central()
        # register callback
        self._central.callback_system_event = self._callback_system_event
        self._central.callback_click_event = self._callback_click_event
        self._central.callback_alarm_event = self._callback_alarm_event

    async def create_clients(self) -> set[Client]:
        """create clients for the central unit."""
        clients: set[Client] = set()
        for interface_name in self._data[ATTR_INTERFACE]:
            interface = self._data[ATTR_INTERFACE][interface_name]
            clients.add(
                await ClientConfig(
                    central=self.central,
                    name=interface_name,
                    port=interface[ATTR_PORT],
                    path=interface[ATTR_PATH],
                    callback_host=self._data.get(ATTR_CALLBACK_HOST)
                    if not self._data.get(ATTR_CALLBACK_HOST) == IP_ANY_V4
                    else None,
                    callback_port=self._data.get(ATTR_CALLBACK_PORT)
                    if not self._data.get(ATTR_CALLBACK_PORT) == PORT_ANY
                    else None,
                ).get_client()
            )
        return clients

    def _get_active_entity_by_address(self, address: str) -> BaseEntity:
        for entity in self._active_hm_entities.values():
            if entity.address == address:
                return entity


class ControlConfig:
    """Config for a ControlUnit."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry_id: str,
        data: MappingProxyType[str, Any],
        enable_virtual_channels: bool = False,
        enable_sensors_for_system_variables: bool = False,
    ) -> None:
        self.hass = hass
        self.entry_id = entry_id
        self.data = data
        self.enable_virtual_channels = enable_virtual_channels
        self.enable_sensors_for_system_variables = enable_sensors_for_system_variables

    def get_control_unit(self) -> ControlUnit:
        """Identify the used client."""
        return ControlUnit(self)


class HaHub(Entity):
    """The HomeMatic hub. (CCU2/HomeGear)."""

    def __init__(self, hass, cu: ControlUnit):
        """Initialize HomeMatic hub."""
        self.hass = hass
        self._cu: ControlUnit = cu
        self._hm_hub: HmHub = self._cu.central.hub
        self._name = self._cu.central.instance_name
        self.entity_id = f"{DOMAIN}.{slugify(self._name.lower())}"
        self._hm_hub.register_update_callback(self._update_hub)

    async def init(self) -> None:
        """Init fetch scheduler."""
        self.hass.helpers.event.async_track_time_interval(
            self._fetch_data, SCAN_INTERVAL
        )
        await self._hm_hub.fetch_data()

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self._hm_hub.available

    @property
    def name(self) -> str:
        """Return the name of the device."""
        return self._name

    @property
    def should_poll(self) -> bool:
        """Return false. HomeMatic Hub object updates variables."""
        return False

    async def _fetch_data(self, now) -> None:
        """Fetch data from backend."""
        await self._hm_hub.fetch_data()

    @property
    def state(self):
        """Return the state of the entity."""
        return self._hm_hub.state

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        return self._hm_hub.extra_state_attributes

    @property
    def icon(self) -> str:
        """Return the icon to use in the frontend, if any."""
        return "mdi:gradient-vertical"

    async def set_variable(self, name: str, value) -> None:
        """Set variable value on CCU/Homegear."""
        sensor = self._hm_hub.hub_entities.get(name)
        if not sensor or name in self.extra_state_attributes:
            _LOGGER.error("Variable %s not found on %s", name, self.name)
            return

        old_value = None
        if sensor:
            old_value = sensor.state
        if old_value is None:
            old_value = self.extra_state_attributes.get(name)

        value = cv.boolean(value) if isinstance(old_value, bool) else float(value)
        await self._hm_hub.set_system_variable(name, value)

    @callback
    def _update_hub(self, *args) -> None:
        """Update the HA hub."""
        self.async_schedule_update_ha_state(True)
