"""
hahomematic is a Python 3 (>= 3.6) module for Home Assistant to interact with
HomeMatic and homematic IP devices.
Some other devices (f.ex. Bosch, Intertechno) might be supported as well.
https://github.com/danielperna84/hahomematic
"""

import logging
from datetime import timedelta

from hahomematic import config
from hahomematic.client import Client, ClientConfig

from hahomematic.const import (
    ATTR_CALLBACK_HOST,
    ATTR_CALLBACK_PORT,
    ATTR_HOST,
    ATTR_JSON_PORT,
    ATTR_PASSWORD,
    ATTR_PATH,
    ATTR_PORT,
    ATTR_TLS,
    ATTR_USERNAME,
    ATTR_VERIFY_TLS,
    HA_DOMAIN,
    HA_PLATFORMS,
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
)
from hahomematic.entity import BaseEntity
from hahomematic.central_unit import CentralUnit, CentralConfig
from hahomematic.xml_rpc_server import register_xml_rpc_server

import homeassistant.helpers.config_validation as cv
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity import Entity
from homeassistant.util import slugify

from .const import (
    ATTR_INSTANCE_NAME,
    ATTR_INTERFACE,
    ATTR_JSON_TLS,
    CONF_ENABLE_VIRTUAL_CHANNELS,
    CONF_ENABLE_SENSORS_FOR_OWN_SYSTEM_VARIABLES,
)

_LOGGER = logging.getLogger(__name__)
SCAN_INTERVAL_HUB = timedelta(seconds=300)
SCAN_INTERVAL_VARIABLES = timedelta(seconds=30)


class ControlUnit:
    """
    Central point to control a Homematic CCU.
    """

    def __init__(self, hass: HomeAssistant, data=None, entry: ConfigEntry = None):
        if data is None:
            data = {}
        self._hass = hass
        self._data = data
        if entry:
            self._entry = entry
            self._entry_id = entry.entry_id
            self._data = self._entry.data
            self.enable_virtual_channels = self._entry.options.get(
                CONF_ENABLE_VIRTUAL_CHANNELS, False
            )
            self.enable_sensors_for_own_system_variables = self._entry.options.get(
                CONF_ENABLE_SENSORS_FOR_OWN_SYSTEM_VARIABLES, False
            )
        else:
            self._entry_id = "solo"
            self.enable_virtual_channels = False
            self.enable_sensors_for_own_system_variables = False
        self._central: CentralUnit = None
        self._active_hm_entities: dict[str, BaseEntity] = {}

    async def start(self):
        """Start the control unit."""
        _LOGGER.debug("Starting HAHM ControlUnit %s", self._data[ATTR_INSTANCE_NAME])
        config.CACHE_DIR = "cache"

        self.create_central()
        await self.create_clients()
        await self.init_hub()
        self._central.create_devices()
        await self.init_clients()

        self._central.start_connection_checker()

    async def stop(self):
        """Stop the control unit."""
        _LOGGER.debug("Stopping HAHM ControlUnit %s", self._data[ATTR_INSTANCE_NAME])
        await self._central.stop_connection_checker()
        for client in self._central.clients.values():
            await client.proxy_de_init()
        await self._central.stop()

    async def init_hub(self):
        """Init the hub."""
        await self._central.init_hub()
        hm_entities = [self._central.hub]
        args = [[hm_entities]]

        async_dispatcher_send(
            self._hass,
            self.async_signal_new_hm_entity(self._entry_id, "hub"),
            *args,  # Don't send device if None, it would override default value in listeners
        )

    @property
    def hub(self):
        """Return the Hub."""
        return self._central.hub

    async def init_clients(self):
        """Init clients related to control unit."""
        for client in self._central.clients.values():
            await client.proxy_init()

    @property
    def central(self):
        """return the HAHM central_unit instance."""
        return self._central

    async def reconnect(self):
        """Reinit all Clients."""
        if self._central:
            await self._central.reconnect()

    async def get_all_system_variables(self):
        """Get all system variables from CCU / Homegear"""
        if self._central:
            return await self._central.get_all_system_variables()

    async def get_system_variable(self, name):
        """Get single system variable from CCU / Homegear"""
        if self._central:
            return await self._central.get_system_variable(name)

    async def set_system_variable(self, name, value):
        """Set a system variable on CCU / Homegear"""
        if self._central:
            return await self._central.set_system_variable(name, value)

    async def get_service_messages(self):
        """Get service messages from CCU / Homegear"""
        if self._central:
            return await self._central.get_service_messages()

    async def get_install_mode(self, interface_id):
        """Get remaining time in seconds install mode is active from CCU / Homegear"""
        if self._central:
            return await self._central.get_install_mode(interface_id)

    async def set_install_mode(self, interface_id, on=True, t=60, mode=1, address=None):
        """Activate or deactivate installmode on CCU / Homegear"""
        if self._central:
            return await self._central.set_install_mode(
                interface_id, on, t, mode, address
            )

    async def put_paramset(self, interface_id, address, paramset, value, rx_mode=None):
        """Set paramsets manually"""
        if self._central:
            return await self._central.put_paramset(
                interface_id, address, paramset, value, rx_mode
            )

    def get_new_hm_entities(self, new_entities):
        """
        Return all hm-entities by requested unique_ids
        """
        # init dict
        hm_entities = {}
        for platform in HA_PLATFORMS:
            hm_entities[platform] = []

        for entity in new_entities:
            if (
                entity.unique_id not in self._active_hm_entities
                and entity.create_in_ha
                and entity.platform in HA_PLATFORMS
            ):
                hm_entities[entity.platform].append(entity)

        return hm_entities

    def get_hm_entities_by_platform(self, platform):
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

    def add_hm_entity(self, hm_entity):
        """add entity to active entities"""
        self._active_hm_entities[hm_entity.unique_id] = hm_entity

    def remove_hm_entity(self, hm_entity):
        """remove entity from active entities"""
        del self._active_hm_entities[hm_entity.unique_id]

    @callback
    def async_signal_new_hm_entity(self, entry_id, device_type) -> str:
        """Gateway specific event to signal new device."""
        return f"hahm-new-entity-{entry_id}-{device_type}"

    @callback
    def _callback_system_event(self, src, *args):
        """Callback for ccu based events."""
        if src == HH_EVENT_DEVICES_CREATED:
            new_entity_unique_ids = args[1]
            """Handle event of new device creation in HAHM."""
            for (platform, hm_entities) in self.get_new_hm_entities(
                new_entity_unique_ids
            ).items():
                args = []
                if hm_entities and len(hm_entities) > 0:
                    args.append([hm_entities])
                    async_dispatcher_send(
                        self._hass,
                        self.async_signal_new_hm_entity(self._entry_id, platform),
                        *args,  # Don't send device if None, it would override default value in listeners
                    )
            return
        elif src == HH_EVENT_NEW_DEVICES:
            # ignore
            return
        elif src == HH_EVENT_DELETE_DEVICES:
            """Handle event of device removed in HAHM."""
            for address in args[1]:
                entity = self._get_active_entity_by_address(address)
                if entity:
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
    def _callback_click_event(self, event_type, event_data):
        self._hass.bus.fire(
            event_type,
            event_data,
        )
        return

    @callback
    def _callback_alarm_event(self, event_type, event_data):
        self._hass.bus.fire(
            event_type,
            event_data,
        )
        return

    def create_central(self):
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
            enable_sensors_for_own_system_variables=self.enable_sensors_for_own_system_variables,
        ).get_central()
        # register callback
        self._central.callback_system_event = self._callback_system_event
        self._central.callback_click_event = self._callback_click_event
        self._central.callback_alarm_event = self._callback_alarm_event

    async def create_clients(self):
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

    def _get_active_entity_by_address(self, address):
        for entity in self._active_hm_entities.values():
            if entity.address == address:
                return entity


class HMHub2(Entity):
    """The HomeMatic hub. (CCU2/HomeGear)."""

    def __init__(self, hass, cu: ControlUnit):
        """Initialize HomeMatic hub."""
        self.hass = hass
        self._cu: ControlUnit = cu
        self._name = self._cu.central.instance_name
        self.entity_id = f"{HA_DOMAIN}.{slugify(self._name.lower())}"
        self._variables = {}
        self._state = None

        # Load data
        self.hass.helpers.event.track_time_interval(self._update_hub, SCAN_INTERVAL_HUB)
        self.hass.async_add_job(self._update_hub, None)

        self.hass.helpers.event.track_time_interval(
            self._update_variables, SCAN_INTERVAL_VARIABLES
        )
        self.hass.async_add_job(self._update_variables, None)

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self._cu.central.available

    @property
    def name(self):
        """Return the name of the device."""
        return self._name

    @property
    def should_poll(self):
        """Return false. HomeMatic Hub object updates variables."""
        return False

    @property
    def state(self):
        """Return the state of the entity."""
        return self._state

    @property
    def extra_state_attributes(self):
        """Return the state attributes."""
        return self._variables.copy()

    @property
    def icon(self):
        """Return the icon to use in the frontend, if any."""
        return "mdi:gradient-vertical"

    async def _update_hub(self, now):
        """Retrieve latest state."""
        service_message = await self._cu.get_service_messages()
        state = 0 if service_message is None else len(service_message)

        # state have change?
        if self._state != state:
            self._state = state
            self.async_schedule_update_ha_state()

    async def _update_variables(self, now):
        """Retrieve all variable data and update hmvariable states."""
        variables = None
        if self.available:
            variables = await self._cu.get_all_system_variables()
        if variables is None:
            return

        state_change = False
        for key, value in variables.items():
            if key in self._variables and value == self._variables[key]:
                continue

            state_change = True
            self._variables.update({key: value})

        if state_change:
            self.async_schedule_update_ha_state()

    async def set_variable(self, name, value):
        """Set variable value on CCU/Homegear."""
        if name not in self._variables:
            _LOGGER.error("Variable %s not found on %s", name, self.name)
            return
        old_value = self._variables.get(name)
        if isinstance(old_value, bool):
            value = cv.boolean(value)
        elif isinstance(old_value, str):
            value = str(value)
        else:
            value = float(value)
        await self._cu.set_system_variable(name, value)

        self._variables.update({name: value})
        self.async_schedule_update_ha_state()
