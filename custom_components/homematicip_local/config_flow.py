"""Config flow for Homematic(IP) local integration."""

from __future__ import annotations

import logging
from pprint import pformat
from typing import Any, Final, cast
from urllib.parse import urlparse

from hahomematic.const import (
    DEFAULT_PROGRAM_SCAN_ENABLED,
    DEFAULT_SYS_SCAN_INTERVAL,
    DEFAULT_SYSVAR_SCAN_ENABLED,
    DEFAULT_TLS,
    DEFAULT_UN_IGNORES,
    Interface,
    SystemInformation,
)
from hahomematic.exceptions import AuthFailure, BaseHomematicException
import voluptuous as vol
from voluptuous.schema_builder import UNDEFINED, Schema

from homeassistant.components import ssdp
from homeassistant.config_entries import (
    CONN_CLASS_LOCAL_PUSH,
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import (
    CONF_HOST,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_PATH,
    CONF_PORT,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
from homeassistant.helpers.typing import ConfigType

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
    CONF_UN_IGNORES,
    CONF_VERIFY_TLS,
    DEFAULT_ENABLE_SYSTEM_NOTIFICATIONS,
    DEFAULT_LISTEN_ON_ALL_IP,
    DEFAULT_MQTT_ENABLED,
    DEFAULT_MQTT_PREFIX,
    DOMAIN,
    ENABLE_EXPERIMENTAL_FEATURES,
)
from .control_unit import ControlConfig, ControlUnit, validate_config_and_get_system_information
from .support import InvalidConfig

_LOGGER = logging.getLogger(__name__)

CONF_BIDCOS_RF_ENABLED: Final = "bidcos_rf_enabled"
CONF_BIDCOS_RF_PORT: Final = "bidcos_rf_port"
CONF_BIDCOS_WIRED_ENABLED: Final = "bidcos_wired_enabled"
CONF_BIDCOS_WIRED_PORT: Final = "bidcos_wired_port"
CONF_CCU_JACK_ENABLED: Final = "ccu_jack_enabled"
CONF_CUXD_ENABLED: Final = "cuxd_enabled"
CONF_HMIP_RF_ENABLED: Final = "hmip_rf_enabled"
CONF_HMIP_RF_PORT: Final = "hmip_rf_port"
CONF_VIRTUAL_DEVICES_ENABLED: Final = "virtual_devices_enabled"
CONF_VIRTUAL_DEVICES_PATH: Final = "virtual_devices_path"
CONF_VIRTUAL_DEVICES_PORT: Final = "virtual_devices_port"

IF_BIDCOS_RF_PORT: Final = 2001
IF_BIDCOS_RF_TLS_PORT: Final = 42001
IF_BIDCOS_WIRED_PORT: Final = 2000
IF_BIDCOS_WIRED_TLS_PORT: Final = 42000
IF_HMIP_RF_PORT: Final = 2010
IF_HMIP_RF_TLS_PORT: Final = 42010
IF_VIRTUAL_DEVICES_PORT: Final = 9292
IF_VIRTUAL_DEVICES_TLS_PORT: Final = 49292
IF_VIRTUAL_DEVICES_PATH: Final = "/groups"

TEXT_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT))
PASSWORD_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
BOOLEAN_SELECTOR = BooleanSelector()
PORT_SELECTOR = vol.All(
    NumberSelector(NumberSelectorConfig(mode=NumberSelectorMode.BOX, min=1, max=65535)),
    vol.Coerce(int),
)
PORT_SELECTOR_OPTIONAL = vol.All(
    NumberSelector(NumberSelectorConfig(mode=NumberSelectorMode.BOX, min=0, max=65535)),
    vol.Coerce(int),
)
SCAN_INTERVAL_SELECTOR = vol.All(
    NumberSelector(
        NumberSelectorConfig(
            mode=NumberSelectorMode.BOX, min=5, step="any", unit_of_measurement="sec"
        )
    ),
    vol.Coerce(int),
)


def get_domain_schema(data: ConfigType) -> Schema:
    """Return the interface schema with or without tls ports."""
    return vol.Schema(
        {
            vol.Required(
                CONF_INSTANCE_NAME, default=data.get(CONF_INSTANCE_NAME) or UNDEFINED
            ): TEXT_SELECTOR,
            vol.Required(CONF_HOST, default=data.get(CONF_HOST)): TEXT_SELECTOR,
            vol.Required(CONF_USERNAME, default=data.get(CONF_USERNAME)): TEXT_SELECTOR,
            vol.Required(CONF_PASSWORD, default=data.get(CONF_PASSWORD)): PASSWORD_SELECTOR,
            vol.Required(CONF_TLS, default=data.get(CONF_TLS, DEFAULT_TLS)): BOOLEAN_SELECTOR,
            vol.Required(
                CONF_VERIFY_TLS, default=data.get(CONF_VERIFY_TLS, False)
            ): BOOLEAN_SELECTOR,
            vol.Optional(
                CONF_CALLBACK_HOST, default=data.get(CONF_CALLBACK_HOST) or UNDEFINED
            ): TEXT_SELECTOR,
            vol.Optional(
                CONF_CALLBACK_PORT, default=data.get(CONF_CALLBACK_PORT) or UNDEFINED
            ): PORT_SELECTOR_OPTIONAL,
            vol.Optional(
                CONF_JSON_PORT, default=data.get(CONF_JSON_PORT) or UNDEFINED
            ): PORT_SELECTOR_OPTIONAL,
        }
    )


def get_options_schema(data: ConfigType) -> Schema:
    """Return the options schema."""
    options_schema = get_domain_schema(data=data)
    del options_schema.schema[CONF_INSTANCE_NAME]
    return options_schema


def get_interface_schema(use_tls: bool, data: ConfigType, from_config_flow: bool) -> Schema:
    """Return the interface schema with or without tls ports."""
    interfaces = data.get(CONF_INTERFACE, {})
    # HmIP-RF
    if Interface.HMIP_RF in interfaces:
        hmip_rf_enabled = interfaces.get(Interface.HMIP_RF) is not None
    else:
        hmip_rf_enabled = True
    hmip_port = IF_HMIP_RF_TLS_PORT if use_tls else IF_HMIP_RF_PORT

    # BidCos-RF
    if Interface.BIDCOS_RF in interfaces:
        bidcos_rf_enabled = interfaces.get(Interface.BIDCOS_RF) is not None
    else:
        bidcos_rf_enabled = True
    bidcos_rf_port = IF_BIDCOS_RF_TLS_PORT if use_tls else IF_BIDCOS_RF_PORT

    # Virtual devices
    if Interface.VIRTUAL_DEVICES in interfaces:
        virtual_devices_enabled = interfaces.get(Interface.VIRTUAL_DEVICES) is not None
    else:
        virtual_devices_enabled = False
    virtual_devices_port = IF_VIRTUAL_DEVICES_TLS_PORT if use_tls else IF_VIRTUAL_DEVICES_PORT

    # BidCos-Wired
    if Interface.BIDCOS_WIRED in interfaces:
        bidcos_wired_enabled = interfaces.get(Interface.BIDCOS_WIRED) is not None
    else:
        bidcos_wired_enabled = False
    bidcos_wired_port = IF_BIDCOS_WIRED_TLS_PORT if use_tls else IF_BIDCOS_WIRED_PORT

    # CCU-Jack
    if Interface.CCU_JACK in interfaces:
        ccu_jack_enabled = interfaces.get(Interface.CCU_JACK) is not None
    else:
        ccu_jack_enabled = False

    # CUxD
    if Interface.CUXD in interfaces:
        cuxd_enabled = interfaces.get(Interface.CUXD) is not None
    else:
        cuxd_enabled = False

    advanced_config = bool(data.get(CONF_ADVANCED_CONFIG))
    interface_schema = vol.Schema(
        {
            vol.Required(CONF_HMIP_RF_ENABLED, default=hmip_rf_enabled): BOOLEAN_SELECTOR,
            vol.Required(CONF_HMIP_RF_PORT, default=hmip_port): PORT_SELECTOR,
            vol.Required(CONF_BIDCOS_RF_ENABLED, default=bidcos_rf_enabled): BOOLEAN_SELECTOR,
            vol.Required(CONF_BIDCOS_RF_PORT, default=bidcos_rf_port): PORT_SELECTOR,
            vol.Required(
                CONF_VIRTUAL_DEVICES_ENABLED, default=virtual_devices_enabled
            ): BOOLEAN_SELECTOR,
            vol.Required(CONF_VIRTUAL_DEVICES_PORT, default=virtual_devices_port): PORT_SELECTOR,
            vol.Required(
                CONF_VIRTUAL_DEVICES_PATH, default=IF_VIRTUAL_DEVICES_PATH
            ): TEXT_SELECTOR,
            vol.Required(
                CONF_BIDCOS_WIRED_ENABLED, default=bidcos_wired_enabled
            ): BOOLEAN_SELECTOR,
            vol.Required(CONF_BIDCOS_WIRED_PORT, default=bidcos_wired_port): PORT_SELECTOR,
            vol.Required(CONF_CCU_JACK_ENABLED, default=ccu_jack_enabled): BOOLEAN_SELECTOR,
            vol.Required(CONF_CUXD_ENABLED, default=cuxd_enabled): BOOLEAN_SELECTOR,
            vol.Required(CONF_ADVANCED_CONFIG, default=advanced_config): BOOLEAN_SELECTOR,
        }
    )
    if from_config_flow:
        del interface_schema.schema[CONF_ADVANCED_CONFIG]

    if not ENABLE_EXPERIMENTAL_FEATURES:
        del interface_schema.schema[CONF_CCU_JACK_ENABLED]
        del interface_schema.schema[CONF_CUXD_ENABLED]
    return interface_schema


def get_advanced_schema(data: ConfigType, all_un_ignore_parameters: list[str]) -> Schema:
    """Return the advanced schema."""
    existing_parameters: list[str] = [
        p
        for p in data.get(CONF_ADVANCED_CONFIG, {}).get(CONF_UN_IGNORES, DEFAULT_UN_IGNORES)
        if p in all_un_ignore_parameters
    ]

    advanced_schema = vol.Schema(
        {
            vol.Required(
                CONF_PROGRAM_SCAN_ENABLED,
                default=data.get(CONF_ADVANCED_CONFIG, {}).get(
                    CONF_PROGRAM_SCAN_ENABLED, DEFAULT_PROGRAM_SCAN_ENABLED
                ),
            ): BOOLEAN_SELECTOR,
            vol.Required(
                CONF_SYSVAR_SCAN_ENABLED,
                default=data.get(CONF_ADVANCED_CONFIG, {}).get(
                    CONF_SYSVAR_SCAN_ENABLED, DEFAULT_SYSVAR_SCAN_ENABLED
                ),
            ): BOOLEAN_SELECTOR,
            vol.Required(
                CONF_SYS_SCAN_INTERVAL,
                default=data.get(CONF_ADVANCED_CONFIG, {}).get(
                    CONF_SYS_SCAN_INTERVAL, DEFAULT_SYS_SCAN_INTERVAL
                ),
            ): SCAN_INTERVAL_SELECTOR,
            vol.Required(
                CONF_ENABLE_SYSTEM_NOTIFICATIONS,
                default=data.get(CONF_ADVANCED_CONFIG, {}).get(
                    CONF_ENABLE_SYSTEM_NOTIFICATIONS, DEFAULT_ENABLE_SYSTEM_NOTIFICATIONS
                ),
            ): BOOLEAN_SELECTOR,
            vol.Required(
                CONF_LISTEN_ON_ALL_IP,
                default=data.get(CONF_ADVANCED_CONFIG, {}).get(
                    CONF_LISTEN_ON_ALL_IP, DEFAULT_LISTEN_ON_ALL_IP
                ),
            ): BOOLEAN_SELECTOR,
            vol.Required(
                CONF_MQTT_ENABLED,
                default=data.get(CONF_ADVANCED_CONFIG, {}).get(
                    CONF_MQTT_ENABLED, DEFAULT_MQTT_ENABLED
                ),
            ): BOOLEAN_SELECTOR,
            vol.Optional(
                CONF_MQTT_PREFIX,
                default=data.get(CONF_ADVANCED_CONFIG, {}).get(
                    CONF_MQTT_PREFIX, DEFAULT_MQTT_PREFIX
                ),
            ): TEXT_SELECTOR,
            vol.Optional(
                CONF_UN_IGNORES,
                default=existing_parameters,
            ): SelectSelector(
                config=SelectSelectorConfig(
                    mode=SelectSelectorMode.DROPDOWN,
                    multiple=True,
                    sort=False,
                    options=all_un_ignore_parameters,
                )
            ),
        }
    )
    if not all_un_ignore_parameters:
        del advanced_schema.schema[CONF_UN_IGNORES]
    if not ENABLE_EXPERIMENTAL_FEATURES:
        del advanced_schema.schema[CONF_MQTT_ENABLED]
        del advanced_schema.schema[CONF_MQTT_PREFIX]
    return advanced_schema


async def _async_validate_config_and_get_system_information(
    hass: HomeAssistant, data: ConfigType
) -> SystemInformation | None:
    """Validate the user input allows us to connect."""
    if control_config := ControlConfig(hass=hass, entry_id="validate", data=data):
        control_config.check_config()
        return await validate_config_and_get_system_information(control_config=control_config)
    return None


class DomainConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the instance flow for Homematic(IP) Local."""

    VERSION = 7
    CONNECTION_CLASS = CONN_CLASS_LOCAL_PUSH

    def __init__(self) -> None:
        """Init the ConfigFlow."""
        self.data: ConfigType = {}
        self.serial: str | None = None

    async def async_step_user(self, user_input: ConfigType | None = None) -> ConfigFlowResult:
        """Handle the initial step."""
        return await self.async_step_central(user_input=user_input)

    async def async_step_central(self, user_input: ConfigType | None = None) -> ConfigFlowResult:
        """Handle the initial step."""
        if user_input is not None:
            self.data = _get_ccu_data(self.data, user_input=user_input)
            return await self.async_step_interface()

        return self.async_show_form(
            step_id="central", data_schema=get_domain_schema(data=self.data)
        )

    async def async_step_interface(
        self,
        interface_input: ConfigType | None = None,
    ) -> ConfigFlowResult:
        """Handle the interface step."""
        if interface_input is not None:
            _update_interface_input(data=self.data, interface_input=interface_input)
            if interface_input.get(CONF_ADVANCED_CONFIG):
                return await self.async_step_advanced()
            return await self._validate_and_finish_config_flow()

        _LOGGER.debug("ConfigFlow.step_interface, no user input")
        return self.async_show_form(
            step_id="interface",
            data_schema=get_interface_schema(
                use_tls=self.data[CONF_TLS],
                data=self.data,
                from_config_flow=False,
            ),
        )

    async def async_step_advanced(
        self,
        advanced_input: ConfigType | None = None,
    ) -> ConfigFlowResult:
        """Handle the advanced step."""
        if advanced_input is None:
            _LOGGER.debug("ConfigFlow.step_advanced, no user input")
            return self.async_show_form(
                step_id="advanced",
                data_schema=get_advanced_schema(
                    data=self.data,
                    all_un_ignore_parameters=[],
                ),
            )
        _update_advanced_input(data=self.data, advanced_input=advanced_input)
        return await self._validate_and_finish_config_flow()

    async def _validate_and_finish_config_flow(self) -> ConfigFlowResult:
        """Validate and finish the config flow."""

        errors = {}
        description_placeholders = {}

        try:
            system_information = await _async_validate_config_and_get_system_information(
                self.hass, self.data
            )
            if system_information is not None:
                await self.async_set_unique_id(system_information.serial)
            self._abort_if_unique_id_configured()
        except AuthFailure:
            errors["base"] = "invalid_auth"
        except InvalidConfig as ic:
            errors["base"] = "invalid_config"
            description_placeholders["invalid_items"] = ic.args[0]
        except BaseHomematicException:
            errors["base"] = "cannot_connect"
        else:
            return self.async_create_entry(title=self.data[CONF_INSTANCE_NAME], data=self.data)

        return self.async_show_form(
            step_id="central",
            data_schema=get_domain_schema(data=self.data),
            errors=errors,
            description_placeholders=description_placeholders,
        )

    async def async_step_ssdp(self, discovery_info: ssdp.SsdpServiceInfo) -> ConfigFlowResult:
        """Handle a discovered HomeMatic CCU."""
        _LOGGER.debug("Homematic(IP) Local SSDP discovery %s", pformat(discovery_info))
        instance_name = (
            _get_instance_name(friendly_name=discovery_info.upnp.get("friendlyName")) or "CCU"
        )
        serial = _get_serial(model_description=discovery_info.upnp.get("modelDescription"))

        host = cast(str, urlparse(discovery_info.ssdp_location).hostname)
        await self.async_set_unique_id(serial)

        self._abort_if_unique_id_configured()

        self.data = {CONF_INSTANCE_NAME: instance_name, CONF_HOST: host}
        self.context["title_placeholders"] = {CONF_NAME: instance_name, CONF_HOST: host}
        return await self.async_step_user()

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return HomematicIPLocalOptionsFlowHandler(config_entry)


class HomematicIPLocalOptionsFlowHandler(OptionsFlow):
    """Handle Homematic(IP) Local options."""

    def __init__(self, entry: ConfigEntry) -> None:
        """Initialize Homematic(IP) Local options flow."""
        self.entry = entry
        self._control_unit: ControlUnit = entry.runtime_data
        self.data: ConfigType = dict(self.entry.data.items())

    async def async_step_init(self, user_input: ConfigType | None = None) -> ConfigFlowResult:
        """Manage the Homematic(IP) Local options."""
        return await self.async_step_central(user_input=user_input)

    async def async_step_central(self, user_input: ConfigType | None = None) -> ConfigFlowResult:
        """Manage the Homematic(IP) Local devices options."""
        if user_input is not None:
            self.data = _get_ccu_data(self.data, user_input=user_input)
            return await self.async_step_interface()

        return self.async_show_form(
            step_id="central",
            data_schema=get_options_schema(data=self.data),
        )

    async def async_step_interface(
        self,
        interface_input: ConfigType | None = None,
    ) -> ConfigFlowResult:
        """Handle the interface step."""
        if interface_input is not None:
            _update_interface_input(data=self.data, interface_input=interface_input)
            if interface_input.get(CONF_ADVANCED_CONFIG):
                return await self.async_step_advanced()
            return await self._validate_and_finish_options_flow()

        _LOGGER.debug("ConfigFlow.step_interface, no user input")
        return self.async_show_form(
            step_id="interface",
            data_schema=get_interface_schema(
                use_tls=self.data[CONF_TLS],
                data=self.data,
                from_config_flow=False,
            ),
        )

    async def async_step_advanced(
        self,
        advanced_input: ConfigType | None = None,
    ) -> ConfigFlowResult:
        """Handle the advanced step."""
        if advanced_input is None:
            _LOGGER.debug("ConfigFlow.step_advanced, no user input")
            return self.async_show_form(
                step_id="advanced",
                data_schema=get_advanced_schema(
                    data=self.data,
                    all_un_ignore_parameters=self._control_unit.central.get_un_ignore_candidates(
                        include_master=True
                    ),
                ),
            )
        _update_advanced_input(data=self.data, advanced_input=advanced_input)
        return await self._validate_and_finish_options_flow()

    async def _validate_and_finish_options_flow(self) -> ConfigFlowResult:
        """Validate and finish the options flow."""

        errors = {}
        description_placeholders = {}

        try:
            system_information = await _async_validate_config_and_get_system_information(
                self.hass, self.data
            )
        except AuthFailure:
            errors["base"] = "invalid_auth"
        except InvalidConfig as ic:
            errors["base"] = "invalid_config"
            description_placeholders["invalid_items"] = ic.args[0]
        except BaseHomematicException:
            errors["base"] = "cannot_connect"
        else:
            if system_information is not None:
                self.hass.config_entries.async_update_entry(
                    entry=self.entry,
                    unique_id=system_information.serial,
                    data=self.data,
                )
            return self.async_create_entry(title="", data={})

        return self.async_show_form(
            step_id="central",
            data_schema=get_options_schema(data=self.data),
            errors=errors,
            description_placeholders=description_placeholders,
        )


def _get_ccu_data(data: ConfigType, user_input: ConfigType) -> ConfigType:
    ccu_data = {
        CONF_INSTANCE_NAME: user_input.get(CONF_INSTANCE_NAME, data.get(CONF_INSTANCE_NAME)),
        CONF_HOST: user_input[CONF_HOST],
        CONF_USERNAME: user_input[CONF_USERNAME],
        CONF_PASSWORD: user_input[CONF_PASSWORD],
        CONF_TLS: user_input[CONF_TLS],
        CONF_VERIFY_TLS: user_input[CONF_VERIFY_TLS],
        CONF_INTERFACE: data.get(CONF_INTERFACE, {}),
        CONF_ADVANCED_CONFIG: data.get(CONF_ADVANCED_CONFIG, {}),
    }
    if (callback_host := user_input.get(CONF_CALLBACK_HOST)) and callback_host.strip() != "":
        ccu_data[CONF_CALLBACK_HOST] = callback_host
    if callback_port := user_input.get(CONF_CALLBACK_PORT):
        ccu_data[CONF_CALLBACK_PORT] = callback_port
    if json_port := user_input.get(CONF_JSON_PORT):
        ccu_data[CONF_JSON_PORT] = json_port

    return ccu_data


def _update_interface_input(data: ConfigType, interface_input: ConfigType) -> None:
    if not interface_input:
        return

    data[CONF_INTERFACE] = {}
    if interface_input[CONF_HMIP_RF_ENABLED] is True:
        data[CONF_INTERFACE][Interface.HMIP_RF] = {
            CONF_PORT: interface_input[CONF_HMIP_RF_PORT],
        }
    if interface_input[CONF_BIDCOS_RF_ENABLED] is True:
        data[CONF_INTERFACE][Interface.BIDCOS_RF] = {
            CONF_PORT: interface_input[CONF_BIDCOS_RF_PORT],
        }
    if interface_input[CONF_VIRTUAL_DEVICES_ENABLED] is True:
        data[CONF_INTERFACE][Interface.VIRTUAL_DEVICES] = {
            CONF_PORT: interface_input[CONF_VIRTUAL_DEVICES_PORT],
            CONF_PATH: interface_input.get(CONF_VIRTUAL_DEVICES_PATH),
        }
    if interface_input[CONF_BIDCOS_WIRED_ENABLED] is True:
        data[CONF_INTERFACE][Interface.BIDCOS_WIRED] = {
            CONF_PORT: interface_input[CONF_BIDCOS_WIRED_PORT],
        }
    if ENABLE_EXPERIMENTAL_FEATURES:
        if interface_input[CONF_CCU_JACK_ENABLED] is True:
            data[CONF_INTERFACE][Interface.CCU_JACK] = {}
        if interface_input[CONF_CUXD_ENABLED] is True:
            data[CONF_INTERFACE][Interface.CUXD] = {}

    if interface_input[CONF_ADVANCED_CONFIG] is False:
        data[CONF_ADVANCED_CONFIG] = {}


def _update_advanced_input(data: ConfigType, advanced_input: ConfigType) -> None:
    if not advanced_input:
        return

    data[CONF_ADVANCED_CONFIG] = {}
    data[CONF_ADVANCED_CONFIG][CONF_PROGRAM_SCAN_ENABLED] = advanced_input[
        CONF_PROGRAM_SCAN_ENABLED
    ]
    data[CONF_ADVANCED_CONFIG][CONF_SYSVAR_SCAN_ENABLED] = advanced_input[CONF_SYSVAR_SCAN_ENABLED]
    data[CONF_ADVANCED_CONFIG][CONF_SYS_SCAN_INTERVAL] = advanced_input[CONF_SYS_SCAN_INTERVAL]
    data[CONF_ADVANCED_CONFIG][CONF_ENABLE_SYSTEM_NOTIFICATIONS] = advanced_input[
        CONF_ENABLE_SYSTEM_NOTIFICATIONS
    ]
    data[CONF_ADVANCED_CONFIG][CONF_LISTEN_ON_ALL_IP] = advanced_input[CONF_LISTEN_ON_ALL_IP]

    if ENABLE_EXPERIMENTAL_FEATURES:
        data[CONF_ADVANCED_CONFIG][CONF_MQTT_ENABLED] = advanced_input[CONF_MQTT_ENABLED]
        data[CONF_ADVANCED_CONFIG][CONF_MQTT_PREFIX] = advanced_input[CONF_MQTT_PREFIX]

    if advanced_input.get(CONF_UN_IGNORES):
        data[CONF_ADVANCED_CONFIG][CONF_UN_IGNORES] = advanced_input[CONF_UN_IGNORES]


def _get_instance_name(friendly_name: Any | None) -> str | None:
    """Return the instance name from the friendly_name."""
    if not friendly_name:
        return None
    name = str(friendly_name)
    if name.startswith("HomeMatic Central - "):
        return name.replace("HomeMatic Central - ", "")
    if name.startswith("HomeMatic Central "):
        return name.replace("HomeMatic Central ", "")
    return name


def _get_serial(model_description: Any | None) -> str | None:
    """Return the serial from the model_description."""
    if not model_description:
        return None
    model_desc = str(model_description)
    if len(model_desc) > 10:
        return model_desc[-10:]
    return None
