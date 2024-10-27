"""Module with hahomematic services."""

from __future__ import annotations

from datetime import datetime
import logging
from typing import TYPE_CHECKING, Final, cast

from hahomematic.const import ForcedDeviceAvailability, ParamsetKey
from hahomematic.exceptions import BaseHomematicException
from hahomematic.model.device import Device
from hahomematic.support import get_device_address, to_bool
import hahomematic.validator as haval
import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_DEVICE_ID, CONF_MODE
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.device_registry import DeviceEntry
from homeassistant.helpers.service import async_register_admin_service, verify_domain_control

from .const import (
    DOMAIN,
    HMIP_LOCAL_SERVICES,
    SERVICE_CLEAR_CACHE,
    SERVICE_CREATE_CENTRAL_LINKS,
    SERVICE_EXPORT_DEVICE_DEFINITION,
    SERVICE_FETCH_SYSTEM_VARIABLES,
    SERVICE_FORCE_DEVICE_AVAILABILITY,
    SERVICE_GET_DEVICE_VALUE,
    SERVICE_GET_LINK_PARAMSET,
    SERVICE_GET_LINK_PEERS,
    SERVICE_GET_PARAMSET,
    SERVICE_PUT_LINK_PARAMSET,
    SERVICE_PUT_PARAMSET,
    SERVICE_REMOVE_CENTRAL_LINKS,
    SERVICE_SET_DEVICE_VALUE,
    SERVICE_SET_INSTALL_MODE,
    SERVICE_SET_VARIABLE_VALUE,
    SERVICE_UPDATE_DEVICE_FIRMWARE_DATA,
)
from .control_unit import ControlUnit
from .support import get_device_address_at_interface_from_identifiers

if TYPE_CHECKING:
    from . import HomematicConfigEntry

_LOGGER = logging.getLogger(__name__)

CONF_ADDRESS: Final = "address"
CONF_CHANNEL: Final = "channel"
CONF_CHANNEL_ADDRESS: Final = "channel_address"
CONF_DEVICE_ADDRESS: Final = "device_address"
CONF_ENTRY_ID: Final = "entry_id"
CONF_INTERFACE_ID: Final = "interface_id"
CONF_NAME: Final = "name"
CONF_PARAMETER: Final = "parameter"
CONF_PARAMSET: Final = "paramset"
CONF_PARAMSET_KEY: Final = "paramset_key"
CONF_RECEIVER_CHANNEL_ADDRESS: Final = "receiver_channel_address"
CONF_RX_MODE: Final = "rx_mode"
CONF_SENDER_CHANNEL_ADDRESS: Final = "sender_channel_address"
CONF_TIME: Final = "time"
CONF_VALUE: Final = "value"
CONF_VALUE_TYPE: Final = "value_type"
CONF_WAIT_FOR_CALLBACK: Final = "wait_for_callback"

DEFAULT_CHANNEL: Final = 1

BASE_SCHEMA_DEVICE = vol.Schema(
    {
        vol.Optional(CONF_DEVICE_ID): cv.string,
        vol.Optional(CONF_DEVICE_ADDRESS): haval.device_address,
    }
)

SCHEMA_SERVICE_CREATE_CENTRAL_LINKS = vol.All(
    cv.has_at_least_one_key(CONF_DEVICE_ID, CONF_ENTRY_ID),
    cv.has_at_most_one_key(CONF_DEVICE_ID, CONF_ENTRY_ID),
    vol.Schema(
        {
            vol.Optional(CONF_ENTRY_ID): cv.string,
            vol.Optional(CONF_DEVICE_ID): cv.string,
        }
    ),
)

SCHEMA_SERVICE_CLEAR_CACHE = vol.Schema(
    {
        vol.Required(CONF_ENTRY_ID): cv.string,
    }
)

SCHEMA_SERVICE_EXPORT_DEVICE_DEFINITION = vol.Schema(
    {
        vol.Required(CONF_DEVICE_ID): cv.string,
    }
)

SCHEMA_SERVICE_FETCH_SYSTEM_VARIABLES = vol.Schema(
    {
        vol.Required(CONF_ENTRY_ID): cv.string,
    }
)

SCHEMA_SERVICE_FORCE_DEVICE_AVAILABILITY = vol.All(
    cv.has_at_least_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    cv.has_at_most_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    BASE_SCHEMA_DEVICE,
)

SCHEMA_SERVICE_GET_DEVICE_VALUE = vol.All(
    cv.has_at_least_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    cv.has_at_most_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    BASE_SCHEMA_DEVICE.extend(
        {
            vol.Required(CONF_CHANNEL, default=DEFAULT_CHANNEL): haval.channel_no,
            vol.Required(CONF_PARAMETER): vol.All(cv.string, vol.Upper),
        }
    ),
)

SCHEMA_SERVICE_GET_LINK_PEERS = vol.All(
    cv.has_at_least_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    cv.has_at_most_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    BASE_SCHEMA_DEVICE.extend(
        {
            vol.Optional(CONF_CHANNEL): haval.channel_no,
        }
    ),
)

SCHEMA_SERVICE_GET_LINK_PARAMSET = vol.All(
    {
        vol.Optional(CONF_RECEIVER_CHANNEL_ADDRESS): haval.channel_address,
        vol.Optional(CONF_SENDER_CHANNEL_ADDRESS): haval.channel_address,
    }
)

SCHEMA_SERVICE_GET_PARAMSET = vol.All(
    cv.has_at_least_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    cv.has_at_most_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    BASE_SCHEMA_DEVICE.extend(
        {
            vol.Optional(CONF_CHANNEL): haval.channel_no,
            vol.Required(CONF_PARAMSET_KEY): vol.All(
                haval.paramset_key, vol.In(["MASTER", "VALUES"])
            ),
        }
    ),
)

SCHEMA_SERVICE_REMOVE_CENTRAL_LINKS = vol.All(
    cv.has_at_least_one_key(CONF_DEVICE_ID, CONF_ENTRY_ID),
    cv.has_at_most_one_key(CONF_DEVICE_ID, CONF_ENTRY_ID),
    vol.Schema(
        {
            vol.Optional(CONF_ENTRY_ID): cv.string,
            vol.Optional(CONF_DEVICE_ID): cv.string,
        }
    ),
)

SCHEMA_SERVICE_SET_VARIABLE_VALUE = vol.Schema(
    {
        vol.Required(CONF_ENTRY_ID): cv.string,
        vol.Required(CONF_NAME): cv.string,
        vol.Required(CONF_VALUE): cv.match_all,
    }
)

SCHEMA_SERVICE_SET_INSTALL_MODE = vol.Schema(
    {
        vol.Required(CONF_INTERFACE_ID): cv.string,
        vol.Optional(CONF_TIME, default=60): cv.positive_int,
        vol.Optional(CONF_MODE, default=1): vol.All(vol.Coerce(int), vol.In([1, 2])),
        vol.Optional(CONF_ADDRESS): haval.device_address,
    }
)

SCHEMA_SERVICE_SET_DEVICE_VALUE = vol.All(
    cv.has_at_least_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    cv.has_at_most_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    BASE_SCHEMA_DEVICE.extend(
        {
            vol.Required(CONF_CHANNEL, default=DEFAULT_CHANNEL): haval.channel_no,
            vol.Required(CONF_PARAMETER): vol.All(cv.string, vol.Upper),
            vol.Required(CONF_VALUE): cv.match_all,
            vol.Optional(CONF_WAIT_FOR_CALLBACK): haval.wait_for,
            vol.Optional(CONF_VALUE_TYPE): vol.In(
                ["boolean", "dateTime.iso8601", "double", "int", "string"]
            ),
            vol.Optional(CONF_RX_MODE): vol.All(cv.string, vol.Upper),
        }
    ),
)

SCHEMA_SERVICE_PUT_LINK_PARAMSET = vol.All(
    {
        vol.Optional(CONF_RECEIVER_CHANNEL_ADDRESS): haval.channel_address,
        vol.Optional(CONF_SENDER_CHANNEL_ADDRESS): haval.channel_address,
        vol.Required(CONF_PARAMSET): dict,
        vol.Optional(CONF_RX_MODE): vol.All(cv.string, vol.Upper),
    }
)

SCHEMA_SERVICE_PUT_PARAMSET = vol.All(
    cv.has_at_least_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    cv.has_at_most_one_key(CONF_DEVICE_ID, CONF_DEVICE_ADDRESS),
    BASE_SCHEMA_DEVICE.extend(
        {
            vol.Optional(CONF_CHANNEL): haval.channel_no,
            vol.Required(CONF_PARAMSET_KEY): vol.All(
                haval.paramset_key, vol.In(["MASTER", "VALUES"])
            ),
            vol.Required(CONF_PARAMSET): dict,
            vol.Optional(CONF_WAIT_FOR_CALLBACK): haval.wait_for,
            vol.Optional(CONF_RX_MODE): vol.All(cv.string, vol.Upper),
        }
    ),
)

SCHEMA_SERVICE_UPDATE_DEVICE_FIRMWARE_DATA = vol.Schema(
    {
        vol.Required(CONF_ENTRY_ID): cv.string,
    }
)


async def async_setup_services(hass: HomeAssistant) -> None:
    """Create the hahomematic services."""

    @verify_domain_control(hass, DOMAIN)
    async def async_call_hmip_local_service(service: ServiceCall) -> ServiceResponse:
        """Call correct Homematic(IP) Local service."""
        service_name = service.service

        if service_name == SERVICE_CREATE_CENTRAL_LINKS:
            await _async_service_create_central_link(hass=hass, service=service)
        elif service_name == SERVICE_CLEAR_CACHE:
            await _async_service_clear_cache(hass=hass, service=service)
        elif service_name == SERVICE_EXPORT_DEVICE_DEFINITION:
            await _async_service_export_device_definition(hass=hass, service=service)
        elif service_name == SERVICE_FETCH_SYSTEM_VARIABLES:
            await _async_service_fetch_system_variables(hass=hass, service=service)
        elif service_name == SERVICE_FORCE_DEVICE_AVAILABILITY:
            await _async_service_force_device_availability(hass=hass, service=service)
        elif service_name == SERVICE_GET_DEVICE_VALUE:
            return await _async_service_get_device_value(hass=hass, service=service)
        elif service_name == SERVICE_GET_LINK_PEERS:
            return await _async_service_get_link_peers(hass=hass, service=service)
        elif service_name == SERVICE_GET_LINK_PARAMSET:
            return await _async_service_get_link_paramset(hass=hass, service=service)
        elif service_name == SERVICE_GET_PARAMSET:
            return await _async_service_get_paramset(hass=hass, service=service)
        elif service_name == SERVICE_PUT_LINK_PARAMSET:
            await _async_service_put_link_paramset(hass=hass, service=service)
        elif service_name == SERVICE_PUT_PARAMSET:
            await _async_service_put_paramset(hass=hass, service=service)
        elif service_name == SERVICE_REMOVE_CENTRAL_LINKS:
            await _async_service_remove_central_link(hass=hass, service=service)
        elif service_name == SERVICE_SET_INSTALL_MODE:
            await _async_service_set_install_mode(hass=hass, service=service)
        elif service_name == SERVICE_SET_DEVICE_VALUE:
            await _async_service_set_device_value(hass=hass, service=service)
        elif service_name == SERVICE_SET_VARIABLE_VALUE:
            await _async_service_set_variable_value(hass=hass, service=service)
        elif service_name == SERVICE_UPDATE_DEVICE_FIRMWARE_DATA:
            await _async_service_update_device_firmware_data(hass=hass, service=service)
        return None

    async_register_admin_service(
        hass=hass,
        domain=DOMAIN,
        service=SERVICE_CREATE_CENTRAL_LINKS,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_CREATE_CENTRAL_LINKS,
    )

    async_register_admin_service(
        hass=hass,
        domain=DOMAIN,
        service=SERVICE_CLEAR_CACHE,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_CLEAR_CACHE,
    )

    async_register_admin_service(
        hass=hass,
        domain=DOMAIN,
        service=SERVICE_EXPORT_DEVICE_DEFINITION,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_EXPORT_DEVICE_DEFINITION,
    )

    async_register_admin_service(
        hass=hass,
        domain=DOMAIN,
        service=SERVICE_FETCH_SYSTEM_VARIABLES,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_FETCH_SYSTEM_VARIABLES,
    )

    async_register_admin_service(
        hass=hass,
        domain=DOMAIN,
        service=SERVICE_FORCE_DEVICE_AVAILABILITY,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_FORCE_DEVICE_AVAILABILITY,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_GET_DEVICE_VALUE,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_GET_DEVICE_VALUE,
        supports_response=SupportsResponse.OPTIONAL,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_GET_LINK_PEERS,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_GET_LINK_PEERS,
        supports_response=SupportsResponse.OPTIONAL,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_GET_LINK_PARAMSET,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_GET_LINK_PARAMSET,
        supports_response=SupportsResponse.OPTIONAL,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_GET_PARAMSET,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_GET_PARAMSET,
        supports_response=SupportsResponse.OPTIONAL,
    )

    async_register_admin_service(
        hass=hass,
        domain=DOMAIN,
        service=SERVICE_REMOVE_CENTRAL_LINKS,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_REMOVE_CENTRAL_LINKS,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_SET_VARIABLE_VALUE,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_SET_VARIABLE_VALUE,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_SET_DEVICE_VALUE,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_SET_DEVICE_VALUE,
    )

    async_register_admin_service(
        hass=hass,
        domain=DOMAIN,
        service=SERVICE_SET_INSTALL_MODE,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_SET_INSTALL_MODE,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_PUT_LINK_PARAMSET,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_PUT_LINK_PARAMSET,
    )

    hass.services.async_register(
        domain=DOMAIN,
        service=SERVICE_PUT_PARAMSET,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_PUT_PARAMSET,
    )

    async_register_admin_service(
        hass=hass,
        domain=DOMAIN,
        service=SERVICE_UPDATE_DEVICE_FIRMWARE_DATA,
        service_func=async_call_hmip_local_service,
        schema=SCHEMA_SERVICE_UPDATE_DEVICE_FIRMWARE_DATA,
    )


async def async_unload_services(hass: HomeAssistant) -> None:
    """Unload Homematic(IP) Local services."""
    if len(async_get_loaded_config_entries(hass=hass)) > 0:
        return

    for hmip_local_service in HMIP_LOCAL_SERVICES:
        hass.services.async_remove(domain=DOMAIN, service=hmip_local_service)


async def _async_service_create_central_link(hass: HomeAssistant, service: ServiceCall) -> None:
    """Service to create central links for Homematic(IP) Local devices."""
    try:
        if (entry_id := service.data.get(CONF_ENTRY_ID)) is not None and (
            control := _async_get_control_unit(hass=hass, entry_id=entry_id)
        ) is not None:
            await control.central.create_central_links()
        elif hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
            await hm_device.create_central_links()
    except BaseHomematicException as ex:
        raise HomeAssistantError(ex) from ex
    _LOGGER.debug("Called create_central_links")


async def _async_service_remove_central_link(hass: HomeAssistant, service: ServiceCall) -> None:
    """Service to remove central links for Homematic(IP) Local devices."""
    try:
        if (entry_id := service.data.get(CONF_ENTRY_ID)) is not None and (
            control := _async_get_control_unit(hass=hass, entry_id=entry_id)
        ) is not None:
            await control.central.remove_central_links()
        elif hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
            await hm_device.remove_central_links()
    except BaseHomematicException as ex:
        raise HomeAssistantError(ex) from ex
    _LOGGER.debug("Called remove_central_links")


async def _async_service_export_device_definition(
    hass: HomeAssistant, service: ServiceCall
) -> None:
    """Service to call setValue method for Homematic(IP) Local devices."""
    if hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
        try:
            await hm_device.export_device_definition()
        except BaseHomematicException as ex:
            raise HomeAssistantError(ex) from ex

        _LOGGER.debug(
            "Called export_device_definition: %s, %s",
            hm_device.name,
            hm_device.address,
        )


async def _async_service_force_device_availability(
    hass: HomeAssistant, service: ServiceCall
) -> None:
    """Service to force device availability on a Homematic(IP) Local devices."""
    if hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
        hm_device.set_forced_availability(forced_availability=ForcedDeviceAvailability.FORCE_TRUE)
        _LOGGER.debug(
            "Called force_device_availability: %s, %s",
            hm_device.name,
            hm_device.address,
        )


async def _async_service_get_device_value(
    hass: HomeAssistant, service: ServiceCall
) -> ServiceResponse:
    """Service to call getValue method for Homematic(IP) Local devices."""
    channel_no = service.data[CONF_CHANNEL]
    parameter = service.data[CONF_PARAMETER]

    if hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
        try:
            if (
                value := await hm_device.client.get_value(
                    channel_address=f"{hm_device.address}:{channel_no}",
                    paramset_key=ParamsetKey.VALUES,
                    parameter=parameter,
                )
            ) is not None:
                return {"result": value}
        except BaseHomematicException as ex:
            raise HomeAssistantError(ex) from ex
    return None


async def _async_service_get_link_peers(
    hass: HomeAssistant, service: ServiceCall
) -> ServiceResponse:
    """Service to call the getLinkPeers method on a Homematic(IP) Local connection."""
    channel_no = service.data.get(CONF_CHANNEL)

    if hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
        address = (
            f"{hm_device.address}:{channel_no}" if channel_no is not None else hm_device.address
        )
        try:
            return cast(
                ServiceResponse, {address: await hm_device.client.get_link_peers(address=address)}
            )
        except BaseHomematicException as ex:
            raise HomeAssistantError(ex) from ex
    return None


async def _async_service_get_link_paramset(
    hass: HomeAssistant, service: ServiceCall
) -> ServiceResponse:
    """Service to call the getParamset method for links on a Homematic(IP) Local connection."""
    sender_channel_address = service.data[CONF_SENDER_CHANNEL_ADDRESS]
    receiver_channel_address = service.data[CONF_RECEIVER_CHANNEL_ADDRESS]

    if hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
        try:
            return dict(
                await hm_device.client.get_paramset(
                    address=receiver_channel_address,
                    paramset_key=sender_channel_address,
                )
            )
        except BaseHomematicException as ex:
            raise HomeAssistantError(ex) from ex
    return None


async def _async_service_get_paramset(
    hass: HomeAssistant, service: ServiceCall
) -> ServiceResponse:
    """Service to call the getParamset method on a Homematic(IP) Local connection."""
    channel_no = service.data.get(CONF_CHANNEL)
    paramset_key = ParamsetKey(service.data[CONF_PARAMSET_KEY])

    if hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
        address = (
            f"{hm_device.address}:{channel_no}" if channel_no is not None else hm_device.address
        )
        try:
            return dict(
                await hm_device.client.get_paramset(
                    address=address,
                    paramset_key=paramset_key,
                )
            )
        except BaseHomematicException as ex:
            raise HomeAssistantError(ex) from ex
    return None


async def _async_service_set_device_value(hass: HomeAssistant, service: ServiceCall) -> None:
    """Service to call setValue method for Homematic(IP) Local devices."""
    channel_no = service.data[CONF_CHANNEL]
    parameter = service.data[CONF_PARAMETER]
    value = service.data[CONF_VALUE]
    value_type = service.data.get(CONF_VALUE_TYPE)
    wait_for_callback = service.data.get(CONF_WAIT_FOR_CALLBACK)
    rx_mode = service.data.get(CONF_RX_MODE)
    if value_type:
        # Convert value into correct XML-RPC Type.
        # https://docs.python.org/3/library/xmlrpc.client.html#xmlrpc.client.ServerProxy
        if value_type == "int":
            value = int(value)
        elif value_type == "double":
            value = float(value)
        elif value_type == "boolean":
            value = to_bool(value)
        elif value_type == "dateTime.iso8601":
            value = datetime.strptime(value, "%Y%m%dT%H:%M:%S")
        else:
            # Default is 'string'
            value = str(value)

    if hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
        try:
            await hm_device.client.set_value(
                channel_address=f"{hm_device.address}:{channel_no}",
                paramset_key=ParamsetKey.VALUES,
                parameter=parameter,
                value=value,
                wait_for_callback=wait_for_callback,
                rx_mode=rx_mode,
                check_against_pd=True,
            )
        except BaseHomematicException as ex:
            raise HomeAssistantError(ex) from ex


async def _async_service_set_variable_value(hass: HomeAssistant, service: ServiceCall) -> None:
    """Service to call setValue method for Homematic(IP) Local system variable."""
    entry_id = service.data[CONF_ENTRY_ID]
    name = service.data[CONF_NAME]
    value = service.data[CONF_VALUE]

    if control := _async_get_control_unit(hass=hass, entry_id=entry_id):
        await control.central.set_system_variable(name=name, value=value)


async def _async_service_set_install_mode(hass: HomeAssistant, service: ServiceCall) -> None:
    """Service to set interface_id into install mode."""
    interface_id = service.data[CONF_INTERFACE_ID]
    mode: int = service.data.get(CONF_MODE, 1)
    time: int = service.data.get(CONF_TIME, 60)
    device_address = service.data.get(CONF_ADDRESS)

    if control_unit := _async_get_cu_by_interface_id(hass=hass, interface_id=interface_id):
        await control_unit.central.set_install_mode(
            interface_id, t=time, mode=mode, device_address=device_address
        )


async def _async_service_clear_cache(hass: HomeAssistant, service: ServiceCall) -> None:
    """Service to clear the cache."""
    entry_id = service.data[CONF_ENTRY_ID]
    if control := _async_get_control_unit(hass=hass, entry_id=entry_id):
        await control.central.clear_caches()


async def _async_service_fetch_system_variables(hass: HomeAssistant, service: ServiceCall) -> None:
    """Service to fetch system variables from backend."""
    entry_id = service.data[CONF_ENTRY_ID]
    if control := _async_get_control_unit(hass=hass, entry_id=entry_id):
        await control.fetch_all_system_variables()


async def _async_service_put_link_paramset(hass: HomeAssistant, service: ServiceCall) -> None:
    """Service to call the putParamset method for link manipulation on a Homematic(IP) Local connection."""
    sender_channel_address = service.data[CONF_SENDER_CHANNEL_ADDRESS]
    receiver_channel_address = service.data[CONF_RECEIVER_CHANNEL_ADDRESS]
    # When passing in the paramset from a YAML file we get an OrderedDict
    # here instead of a dict, so add this explicit cast.
    # The service schema makes sure that this cast works.
    values = dict(service.data[CONF_PARAMSET])
    rx_mode = service.data.get(CONF_RX_MODE)

    if hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
        try:
            await hm_device.client.put_paramset(
                channel_address=receiver_channel_address,
                paramset_key=sender_channel_address,
                values=values,
                rx_mode=rx_mode,
                check_against_pd=True,
            )
        except BaseHomematicException as ex:
            raise HomeAssistantError(ex) from ex


async def _async_service_put_paramset(hass: HomeAssistant, service: ServiceCall) -> None:
    """Service to call the putParamset method on a Homematic(IP) Local connection."""
    channel_no = service.data.get(CONF_CHANNEL)
    paramset_key = ParamsetKey(service.data[CONF_PARAMSET_KEY])
    # When passing in the paramset from a YAML file we get an OrderedDict
    # here instead of a dict, so add this explicit cast.
    # The service schema makes sure that this cast works.
    values = dict(service.data[CONF_PARAMSET])
    wait_for_callback = service.data.get(CONF_WAIT_FOR_CALLBACK)
    rx_mode = service.data.get(CONF_RX_MODE)

    if hm_device := _async_get_hm_device_by_service_data(hass=hass, service=service):
        channel_address = (
            f"{hm_device.address}:{channel_no}" if channel_no is not None else hm_device.address
        )
        try:
            await hm_device.client.put_paramset(
                channel_address=channel_address,
                paramset_key=paramset_key,
                values=values,
                wait_for_callback=wait_for_callback,
                rx_mode=rx_mode,
                check_against_pd=True,
            )
        except BaseHomematicException as ex:
            raise HomeAssistantError(ex) from ex


async def _async_service_update_device_firmware_data(
    hass: HomeAssistant, service: ServiceCall
) -> None:
    """Service to clear the cache."""
    entry_id = service.data[CONF_ENTRY_ID]
    if control := _async_get_control_unit(hass=hass, entry_id=entry_id):
        await control.central.refresh_firmware_data()


@callback
def _async_get_control_unit(hass: HomeAssistant, entry_id: str) -> ControlUnit | None:
    """Get ControlUnit by entry_id."""
    entry: HomematicConfigEntry | None = hass.config_entries.async_get_entry(entry_id=entry_id)
    if entry and (control_unit := entry.runtime_data):
        return control_unit

    _LOGGER.warning("Config entry %s is deactivated or not available", entry_id)
    return None


@callback
def _async_get_hm_device_by_service_data(
    hass: HomeAssistant, service: ServiceCall
) -> Device | None:
    """Service to force device availability on a Homematic(IP) Local devices."""
    hm_device: Device | None = None
    message = "No device found"

    if device_id := service.data.get(CONF_DEVICE_ID):
        hm_device = _asnyc_get_hm_device_by_id(hass=hass, device_id=device_id)
        if not hm_device:
            message = f"No device found by device_id {device_id} for service {service.domain}.{service.service}"
    elif device_address := service.data.get(CONF_DEVICE_ADDRESS):
        hm_device = _async_get_hm_device_by_address(hass=hass, device_address=device_address)
        if not hm_device:
            message = f"No device found by device_address {device_address} for service {service.domain}.{service.service}"
    elif channel_address := service.data.get(CONF_CHANNEL_ADDRESS):
        hm_device = _async_get_hm_device_by_address(
            hass=hass, device_address=get_device_address(address=channel_address)
        )
        if not hm_device:
            message = f"No device found by channel_address {channel_address} for service {service.domain}.{service.service}"
    elif receiver_channel_address := service.data.get(CONF_RECEIVER_CHANNEL_ADDRESS):
        hm_device = _async_get_hm_device_by_address(
            hass=hass, device_address=get_device_address(address=receiver_channel_address)
        )
        if not hm_device:
            message = f"No device found by receiver_channel_address {receiver_channel_address} for service {service.domain}.{service.service}"
    if not hm_device:
        _LOGGER.warning(message)
        raise HomeAssistantError(message)
    return hm_device


@callback
def async_get_config_entries(hass: HomeAssistant) -> list[HomematicConfigEntry]:
    """Get config entries for HomematicIP local."""
    return hass.config_entries.async_entries(
        domain=DOMAIN, include_ignore=False, include_disabled=False
    )


@callback
def async_get_loaded_config_entries(hass: HomeAssistant) -> list[HomematicConfigEntry]:
    """Get config entries for HomematicIP local."""
    return [
        entry
        for entry in hass.config_entries.async_entries(
            domain=DOMAIN, include_ignore=False, include_disabled=False
        )
        if entry.state == ConfigEntryState.LOADED
    ]


@callback
def _async_get_control_units(hass: HomeAssistant) -> list[ControlUnit]:
    """Get control units for HomematicIP local."""
    return [entry.runtime_data for entry in async_get_config_entries(hass=hass)]


@callback
def _async_get_hm_device_by_address(hass: HomeAssistant, device_address: str) -> Device | None:
    """Return the homematic device."""
    for control_unit in _async_get_control_units(hass=hass):
        if hm_device := control_unit.central.get_device(address=device_address):
            return hm_device
    return None


@callback
def _async_get_cu_by_interface_id(hass: HomeAssistant, interface_id: str) -> ControlUnit | None:
    """Get ControlUnit by interface_id."""
    for control_unit in _async_get_control_units(hass=hass):
        if control_unit.central.has_client(interface_id=interface_id):
            return control_unit
    return None


@callback
def _asnyc_get_hm_device_by_id(hass: HomeAssistant, device_id: str) -> Device | None:
    """Return the homematic device."""
    device_entry: DeviceEntry | None = dr.async_get(hass).async_get(device_id)
    if not device_entry:
        return None
    if (
        data := get_device_address_at_interface_from_identifiers(
            identifiers=device_entry.identifiers
        )
    ) is None:
        return None
    device_address, interface_id = data
    for control_unit in _async_get_control_units(hass=hass):
        if control_unit.central.has_client(interface_id=interface_id) and (
            hm_device := control_unit.central.get_device(address=device_address)
        ):
            return hm_device
    return None
