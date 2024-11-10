"""Test the Homematic(IP) Local config flow."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from hahomematic.const import CONF_PASSWORD, CONF_USERNAME, Interface, SystemInformation
from hahomematic.exceptions import AuthFailure, NoConnectionException
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.homematicip_local.config_flow import (
    CONF_BIDCOS_RF_ENABLED,
    CONF_BIDCOS_RF_PORT,
    CONF_BIDCOS_WIRED_ENABLED,
    CONF_HMIP_RF_ENABLED,
    CONF_INSTANCE_NAME,
    CONF_VIRTUAL_DEVICES_ENABLED,
    InvalidConfig,
    _async_validate_config_and_get_system_information,
    _get_instance_name,
    _get_serial,
)
from custom_components.homematicip_local.const import CONF_TLS, DOMAIN as HMIP_DOMAIN
from homeassistant import config_entries
from homeassistant.components import ssdp
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from tests import const


async def async_check_form(
    hass: HomeAssistant,
    central_data: dict[str, Any] | None = None,
    interface_data: dict[str, Any] | None = None,
    tls: bool = False,
) -> dict[str, Any]:
    """Test we get the form."""
    if central_data is None:
        central_data = {
            CONF_INSTANCE_NAME: const.INSTANCE_NAME,
            CONF_HOST: const.HOST,
            CONF_USERNAME: const.USERNAME,
            CONF_PASSWORD: const.PASSWORD,
            CONF_TLS: tls,
        }

    if interface_data is None:
        interface_data = {}

    result = await hass.config_entries.flow.async_init(
        HMIP_DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] is None

    with (
        patch(
            "custom_components.homematicip_local.config_flow._async_validate_config_and_get_system_information",
            return_value=SystemInformation(
                available_interfaces=[],
                auth_enabled=False,
                https_redirect_enabled=False,
                serial=const.SERIAL,
            ),
        ),
        patch(
            "custom_components.homematicip_local.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_INSTANCE_NAME: const.INSTANCE_NAME,
                CONF_HOST: const.HOST,
                CONF_USERNAME: const.USERNAME,
                CONF_PASSWORD: const.PASSWORD,
                CONF_TLS: tls,
            },
        )
        await hass.async_block_till_done()

        assert result2["type"] == FlowResultType.FORM
        assert result2["handler"] == HMIP_DOMAIN
        assert result2["step_id"] == "interface"

        next(
            flow
            for flow in hass.config_entries.flow.async_progress()
            if flow["flow_id"] == result["flow_id"]
        )

        result3 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            interface_data,
        )
        await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.CREATE_ENTRY
    assert result3["handler"] == HMIP_DOMAIN
    assert result3["title"] == const.INSTANCE_NAME
    data = result3["data"]
    assert data[CONF_INSTANCE_NAME] == const.INSTANCE_NAME
    assert data[CONF_HOST] == const.HOST
    assert data[CONF_USERNAME] == const.USERNAME
    assert data[CONF_PASSWORD] == const.PASSWORD
    return data


async def async_check_options_form(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    central_data: dict[str, Any] | None = None,
    interface_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Test we get the form."""
    if central_data is None:
        central_data = {}

    if interface_data is None:
        interface_data = {}
    mock_config_entry.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] is None

    with (
        patch(
            "custom_components.homematicip_local.config_flow._async_validate_config_and_get_system_information",
            return_value=SystemInformation(
                available_interfaces=[],
                auth_enabled=False,
                https_redirect_enabled=False,
                serial=const.SERIAL,
            ),
        ),
        patch(
            "custom_components.homematicip_local.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.options.async_configure(
            result["flow_id"],
            central_data,
        )
        await hass.async_block_till_done()

        assert result2["type"] == FlowResultType.FORM
        assert result2["handler"] == const.CONFIG_ENTRY_ID
        assert result2["step_id"] == "interface"

        next(
            flow
            for flow in hass.config_entries.options.async_progress()
            if flow["flow_id"] == result["flow_id"]
        )

        result3 = await hass.config_entries.options.async_configure(
            result["flow_id"],
            interface_data,
        )
        await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.CREATE_ENTRY
    assert result3["handler"] == const.CONFIG_ENTRY_ID
    assert result3["title"] == ""
    return mock_config_entry.data


async def test_form(hass: HomeAssistant) -> None:
    """Test we get the form."""
    data = await async_check_form(hass)
    interface = data["interface"]
    if_hmip_rf = interface[Interface.HMIP_RF]
    assert if_hmip_rf[CONF_PORT] == 2010
    if_bidcos_rf = interface[Interface.BIDCOS_RF]
    assert if_bidcos_rf[CONF_PORT] == 2001

    assert interface.get(Interface.VIRTUAL_DEVICES) is None
    assert interface.get(Interface.BIDCOS_WIRED) is None


async def test_options_form(hass: HomeAssistant, mock_config_entry_v2: MockConfigEntry) -> None:
    """Test we get the form."""
    data = await async_check_options_form(
        hass, mock_config_entry=mock_config_entry_v2, interface_data={}
    )
    interface = data["interface"]
    if_hmip_rf = interface[Interface.HMIP_RF]
    assert if_hmip_rf[CONF_PORT] == 2010
    if_bidcos_rf = interface[Interface.BIDCOS_RF]
    assert if_bidcos_rf[CONF_PORT] == 2001

    assert interface.get(Interface.VIRTUAL_DEVICES) is None
    assert interface.get(Interface.BIDCOS_WIRED) is None


async def test_form_no_hmip_other_bidcos_port(hass: HomeAssistant) -> None:
    """Test we get the form."""
    interface_data = {CONF_HMIP_RF_ENABLED: False, CONF_BIDCOS_RF_PORT: 5555}
    data = await async_check_form(hass, interface_data=interface_data)
    interface = data["interface"]
    assert interface.get(Interface.HMIP_RF) is None
    if_bidcos_rf = interface[Interface.BIDCOS_RF]
    assert if_bidcos_rf[CONF_PORT] == 5555
    assert interface.get(Interface.VIRTUAL_DEVICES) is None
    assert interface.get(Interface.BIDCOS_WIRED) is None


async def test_options_form_no_hmip_other_bidcos_port(
    hass: HomeAssistant, mock_config_entry_v2: MockConfigEntry
) -> None:
    """Test we get the form."""
    interface_data = {CONF_HMIP_RF_ENABLED: False, CONF_BIDCOS_RF_PORT: 5555}
    data = await async_check_options_form(
        hass, mock_config_entry=mock_config_entry_v2, interface_data=interface_data
    )
    interface = data["interface"]
    assert interface.get(Interface.HMIP_RF) is None
    if_bidcos_rf = interface[Interface.BIDCOS_RF]
    assert if_bidcos_rf[CONF_PORT] == 5555
    assert interface.get(Interface.VIRTUAL_DEVICES) is None
    assert interface.get(Interface.BIDCOS_WIRED) is None


async def test_form_only_hs485(hass: HomeAssistant) -> None:
    """Test we get the form."""
    interface_data = {
        CONF_HMIP_RF_ENABLED: False,
        CONF_BIDCOS_RF_ENABLED: False,
        CONF_VIRTUAL_DEVICES_ENABLED: False,
        CONF_BIDCOS_WIRED_ENABLED: True,
    }
    data = await async_check_form(hass, interface_data=interface_data)
    interface = data["interface"]
    assert interface.get(Interface.HMIP_RF) is None
    assert interface.get(Interface.BIDCOS_RF) is None
    assert interface.get(Interface.VIRTUAL_DEVICES) is None
    assert interface[Interface.BIDCOS_WIRED][CONF_PORT] == 2000


async def test_form_only_virtual(hass: HomeAssistant) -> None:
    """Test we get the form."""
    interface_data = {
        CONF_HMIP_RF_ENABLED: False,
        CONF_BIDCOS_RF_ENABLED: False,
        CONF_VIRTUAL_DEVICES_ENABLED: True,
        CONF_BIDCOS_WIRED_ENABLED: False,
    }
    data = await async_check_form(hass, interface_data=interface_data)
    interface = data["interface"]
    assert interface.get(Interface.HMIP_RF) is None
    assert interface.get(Interface.BIDCOS_RF) is None
    assert interface.get(Interface.BIDCOS_WIRED) is None
    assert interface[Interface.VIRTUAL_DEVICES][CONF_PORT] == 9292


async def test_options_form_all_interfaces_enabled(
    hass: HomeAssistant, mock_config_entry_v2: MockConfigEntry
) -> None:
    """Test we get the form."""
    mock_config_entry_v2.data["interface"][Interface.VIRTUAL_DEVICES] = {"port": 9292}
    mock_config_entry_v2.data["interface"][Interface.BIDCOS_WIRED] = {"port": 2000}
    mock_config_entry_v2.add_to_hass(hass)

    data = await async_check_options_form(hass, mock_config_entry_v2)
    interface = data["interface"]
    assert interface[Interface.BIDCOS_RF][CONF_PORT] == 2001
    assert interface[Interface.HMIP_RF][CONF_PORT] == 2010
    assert interface[Interface.BIDCOS_WIRED][CONF_PORT] == 2000
    assert interface[Interface.VIRTUAL_DEVICES][CONF_PORT] == 9292


async def test_form_tls(hass: HomeAssistant) -> None:
    """Test we get the form with tls."""
    data = await async_check_form(hass, tls=True)
    interface = data["interface"]

    if_hmip_rf = interface[Interface.HMIP_RF]
    assert if_hmip_rf[CONF_PORT] == 42010
    if_bidcos_rf = interface[Interface.BIDCOS_RF]
    assert if_bidcos_rf[CONF_PORT] == 42001
    assert interface.get(Interface.VIRTUAL_DEVICES) is None
    assert interface.get(Interface.BIDCOS_WIRED) is None


async def test_form_invalid_auth(hass: HomeAssistant) -> None:
    """Test we handle invalid auth."""
    result = await hass.config_entries.flow.async_init(
        HMIP_DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] is None

    with (
        patch(
            "custom_components.homematicip_local.config_flow._async_validate_config_and_get_system_information",
            side_effect=AuthFailure("no pw"),
        ),
        patch(
            "custom_components.homematicip_local.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_INSTANCE_NAME: const.INSTANCE_NAME,
                CONF_HOST: const.HOST,
                CONF_USERNAME: const.USERNAME,
                CONF_PASSWORD: const.PASSWORD,
            },
        )
        await hass.async_block_till_done()

        assert result2["type"] == FlowResultType.FORM
        assert result2["handler"] == HMIP_DOMAIN
        assert result2["step_id"] == "interface"

        next(
            flow
            for flow in hass.config_entries.flow.async_progress()
            if flow["flow_id"] == result["flow_id"]
        )

        result3 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {},
        )
        await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.FORM
    assert result3["errors"] == {"base": "invalid_auth"}


async def test_options_form_invalid_auth(
    hass: HomeAssistant, mock_config_entry_v2: MockConfigEntry
) -> None:
    """Test we handle invalid auth."""
    mock_config_entry_v2.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(mock_config_entry_v2.entry_id)
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] is None

    with (
        patch(
            "custom_components.homematicip_local.config_flow._async_validate_config_and_get_system_information",
            side_effect=AuthFailure("no pw"),
        ),
        patch(
            "custom_components.homematicip_local.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {
                CONF_HOST: const.HOST,
                CONF_USERNAME: const.USERNAME,
                CONF_PASSWORD: const.PASSWORD,
            },
        )
        await hass.async_block_till_done()

        assert result2["type"] == FlowResultType.FORM
        assert result2["handler"] == const.CONFIG_ENTRY_ID
        assert result2["step_id"] == "interface"

        next(
            flow
            for flow in hass.config_entries.options.async_progress()
            if flow["flow_id"] == result["flow_id"]
        )

        result3 = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {},
        )
        await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.FORM
    assert result3["errors"] == {"base": "invalid_auth"}


async def test_form_invalid_password(hass: HomeAssistant) -> None:
    """Test we handle invalid auth."""
    result = await hass.config_entries.flow.async_init(
        HMIP_DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] is None

    with (
        patch(
            "custom_components.homematicip_local.config_flow._async_validate_config_and_get_system_information",
            side_effect=InvalidConfig("wrong char"),
        ),
        patch(
            "custom_components.homematicip_local.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_INSTANCE_NAME: const.INSTANCE_NAME,
                CONF_HOST: const.HOST,
                CONF_USERNAME: const.USERNAME,
                CONF_PASSWORD: const.INVALID_PASSWORD,
            },
        )
        await hass.async_block_till_done()

        assert result2["type"] == FlowResultType.FORM
        assert result2["handler"] == HMIP_DOMAIN
        assert result2["step_id"] == "interface"

        next(
            flow
            for flow in hass.config_entries.flow.async_progress()
            if flow["flow_id"] == result["flow_id"]
        )

        result3 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {},
        )
        await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.FORM
    assert result3["errors"] == {"base": "invalid_config"}


async def test_options_form_invalid_password(
    hass: HomeAssistant, mock_config_entry_v2: MockConfigEntry
) -> None:
    """Test we handle invalid auth."""
    mock_config_entry_v2.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(mock_config_entry_v2.entry_id)
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] is None

    with (
        patch(
            "custom_components.homematicip_local.config_flow._async_validate_config_and_get_system_information",
            side_effect=InvalidConfig("wrong char"),
        ),
        patch(
            "custom_components.homematicip_local.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {
                CONF_HOST: const.HOST,
                CONF_USERNAME: const.USERNAME,
                CONF_PASSWORD: const.INVALID_PASSWORD,
            },
        )
        await hass.async_block_till_done()

        assert result2["type"] == FlowResultType.FORM
        assert result2["handler"] == const.CONFIG_ENTRY_ID
        assert result2["step_id"] == "interface"

        next(
            flow
            for flow in hass.config_entries.options.async_progress()
            if flow["flow_id"] == result["flow_id"]
        )

        result3 = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {},
        )
        await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.FORM
    assert result3["errors"] == {"base": "invalid_config"}


async def test_form_cannot_connect(hass: HomeAssistant) -> None:
    """Test we handle cannot connect error."""
    result = await hass.config_entries.flow.async_init(
        HMIP_DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] is None

    with (
        patch(
            "custom_components.homematicip_local.config_flow._async_validate_config_and_get_system_information",
            side_effect=NoConnectionException("no host"),
        ),
        patch(
            "custom_components.homematicip_local.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_INSTANCE_NAME: const.INSTANCE_NAME,
                CONF_HOST: const.HOST,
                CONF_USERNAME: const.USERNAME,
                CONF_PASSWORD: const.PASSWORD,
            },
        )
        await hass.async_block_till_done()

        assert result2["type"] == FlowResultType.FORM
        assert result2["handler"] == HMIP_DOMAIN
        assert result2["step_id"] == "interface"

        next(
            flow
            for flow in hass.config_entries.flow.async_progress()
            if flow["flow_id"] == result["flow_id"]
        )

        result3 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {},
        )
        await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.FORM
    assert result3["errors"] == {"base": "cannot_connect"}


async def test_options_form_cannot_connect(
    hass: HomeAssistant, mock_config_entry_v2: MockConfigEntry
) -> None:
    """Test we handle cannot connect error."""
    mock_config_entry_v2.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(mock_config_entry_v2.entry_id)

    assert result["type"] == FlowResultType.FORM
    assert result["errors"] is None

    with (
        patch(
            "custom_components.homematicip_local.config_flow._async_validate_config_and_get_system_information",
            side_effect=NoConnectionException("no host"),
        ),
        patch(
            "custom_components.homematicip_local.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {},
        )
        await hass.async_block_till_done()

        assert result2["type"] == FlowResultType.FORM
        assert result2["handler"] == const.CONFIG_ENTRY_ID
        assert result2["step_id"] == "interface"

        next(
            flow
            for flow in hass.config_entries.options.async_progress()
            if flow["flow_id"] == result["flow_id"]
        )

        result3 = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {},
        )
        await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.FORM
    assert result3["errors"] == {"base": "cannot_connect"}


async def test_flow_hassio_discovery(
    hass: HomeAssistant, discovery_info: ssdp.SsdpServiceInfo
) -> None:
    """Test hassio discovery flow works."""

    result = await hass.config_entries.flow.async_init(
        HMIP_DOMAIN,
        data=discovery_info,
        context={"source": config_entries.SOURCE_SSDP},
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "central"
    assert result["description_placeholders"] is None  # {"addon": "Mock Addon"}

    flows = hass.config_entries.flow.async_progress()
    assert len(flows) == 1
    assert flows[0].get("context", {}) == {
        "source": "ssdp",
        "title_placeholders": {"host": const.HOST, "name": const.INSTANCE_NAME},
        "unique_id": const.CONFIG_ENTRY_UNIQUE_ID,
    }

    with (
        patch(
            "custom_components.homematicip_local.config_flow._async_validate_config_and_get_system_information",
            return_value=SystemInformation(
                available_interfaces=[],
                auth_enabled=False,
                https_redirect_enabled=False,
                serial=const.SERIAL,
            ),
        ),
        patch(
            "custom_components.homematicip_local.async_setup_entry",
            return_value=True,
        ),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                CONF_USERNAME: const.USERNAME,
                CONF_PASSWORD: const.PASSWORD,
            },
        )
        await hass.async_block_till_done()
        assert result2["type"] == FlowResultType.FORM
        assert result2["handler"] == HMIP_DOMAIN
        assert result2["step_id"] == "interface"

        next(
            flow
            for flow in hass.config_entries.flow.async_progress()
            if flow["flow_id"] == result["flow_id"]
        )

        result3 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {},
        )
        await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.CREATE_ENTRY
    assert result3["handler"] == HMIP_DOMAIN
    assert result3["title"] == const.INSTANCE_NAME
    data = result3["data"]
    assert data[CONF_INSTANCE_NAME] == const.INSTANCE_NAME
    assert data[CONF_HOST] == const.HOST
    assert data[CONF_USERNAME] == const.USERNAME
    assert data[CONF_PASSWORD] == const.PASSWORD


async def test_hassio_discovery_existing_configuration(
    hass: HomeAssistant,
    mock_config_entry_v2: MockConfigEntry,
    discovery_info: ssdp.SsdpServiceInfo,
) -> None:
    """Test abort on an existing config entry."""
    mock_config_entry_v2.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        HMIP_DOMAIN,
        data=discovery_info,
        context={"source": config_entries.SOURCE_SSDP},
    )
    assert result["type"] == FlowResultType.ABORT


def test_config_flow_helper() -> None:
    """Test the config flow helper."""

    assert _get_instance_name(None) is None
    assert _get_instance_name("0123456789") == "0123456789"
    assert _get_instance_name("HomeMatic Central - test") == "test"
    assert _get_instance_name("HomeMatic Central 0123456789") == "0123456789"
    assert _get_serial(None) is None
    assert _get_serial("1234") is None
    assert _get_serial(f"9876543210{const.SERIAL}") == const.SERIAL


async def test_async_validate_config_and_get_system_information(
    hass: HomeAssistant, entry_data_v5
) -> None:
    """Test backend validation."""
    with patch(
        "custom_components.homematicip_local.config_flow.validate_config_and_get_system_information",
        return_value=SystemInformation(
            available_interfaces=[],
            auth_enabled=False,
            https_redirect_enabled=False,
            serial=const.SERIAL,
        ),
    ):
        result = await _async_validate_config_and_get_system_information(hass, entry_data_v5)
        assert result.serial == const.SERIAL

    entry_data_v5[CONF_PASSWORD] = const.INVALID_PASSWORD

    with pytest.raises(InvalidConfig) as exc:
        await _async_validate_config_and_get_system_information(hass, entry_data_v5)
    assert exc
