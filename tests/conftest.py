"""Initializer helpers for Homematic(IP) Local."""

from __future__ import annotations

import datetime
from typing import Any
from unittest.mock import Mock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.plugins import enable_custom_integrations  # noqa: F401

from custom_components.homematicip_local.const import DOMAIN as HMIP_DOMAIN
from custom_components.homematicip_local.control_unit import ControlConfig, ControlUnit
from homeassistant import config_entries
from homeassistant.components import ssdp
from homeassistant.components.recorder import Recorder
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant

from tests import const, helper

# pylint: disable=protected-access, redefined-outer-name


@pytest.fixture(autouse=True)
def teardown():
    """Clean up."""
    patch.stopall()


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: Any):  # noqa: F811
    """Auto add enable_custom_integrations."""
    return


@pytest.fixture
def entry_data_v1() -> dict[str, Any]:
    """Create data for config entry."""
    return {
        "instance_name": const.INSTANCE_NAME,
        "host": const.HOST,
        "username": const.USERNAME,
        "password": const.PASSWORD,
        "tls": False,
        "verify_tls": False,
        "sysvar_scan_enabled": False,
        "sysvar_scan_interval": 30,
        "callback_host": None,
        "callback_port": None,
        "json_port": None,
        "enable_system_notifications": True,
        "interface": {"HmIP-RF": {"port": 2010}, "BidCos-RF": {"port": 2001}},
    }


@pytest.fixture
def entry_data_v5(entry_data_v1) -> dict[str, Any]:
    """Create data for config entry."""
    entry_data_v5 = entry_data_v1
    entry_data_v5["advanced_config"] = {}
    return entry_data_v5


@pytest.fixture
def mock_config_entry_v1(entry_data_v1) -> config_entries.ConfigEntry:  # )
    """Create a mock config entry for Homematic(IP) Local."""

    entry = MockConfigEntry(
        entry_id=const.CONFIG_ENTRY_ID,
        version=1,
        domain=HMIP_DOMAIN,
        title=const.INSTANCE_NAME,
        data=entry_data_v1,
        options={},
        pref_disable_new_entities=False,
        pref_disable_polling=False,
        source="user",
        unique_id=const.CONFIG_ENTRY_UNIQUE_ID,
        disabled_by=None,
    )
    entry.runtime_data = "123"
    return entry


@pytest.fixture
def mock_config_entry_v2(mock_config_entry_v1, entry_data_v5) -> config_entries.ConfigEntry:  # )
    """Create a mock config entry for Homematic(IP) Local."""

    entry = MockConfigEntry(
        entry_id=const.CONFIG_ENTRY_ID,
        version=2,
        domain=HMIP_DOMAIN,
        title=const.INSTANCE_NAME,
        data=entry_data_v5,
        options={},
        pref_disable_new_entities=False,
        pref_disable_polling=False,
        source="user",
        unique_id=const.CONFIG_ENTRY_UNIQUE_ID,
        disabled_by=None,
    )
    entry.runtime_data = "123"
    return entry


@pytest.fixture
def discovery_info() -> ssdp.SsdpServiceInfo:
    """Create a discovery info for Homematic(IP) Local."""
    return ssdp.SsdpServiceInfo(
        ssdp_usn=f"uuid:upnp-BasicDevice-1_0-3014F711A0001F{const.CONFIG_ENTRY_UNIQUE_ID}::upnp:rootdevice",
        ssdp_st="upnp:rootdevice",
        upnp={
            "deviceType": "urn:schemas-upnp-org:device:Basic:1",
            "presentationURL": None,
            "friendlyName": f"HomeMatic Central - {const.INSTANCE_NAME}",
            "manufacturer": "EQ3",
            "manufacturerURL": "http://www.homematic.com",
            "modelDescription": f"HomeMatic Central 3014F711A0001F{const.CONFIG_ENTRY_UNIQUE_ID}",
            "modelName": "HomeMatic Central",
            "UDN": f"uuid:upnp-BasicDevice-1_0-3014F711A0001F{const.CONFIG_ENTRY_UNIQUE_ID}",
            "UPC": const.CONFIG_ENTRY_UNIQUE_ID,
            "serviceList": {
                "service": {
                    "serviceType": "urn:schemas-upnp-org:service:dummy:1",
                    "serviceId": "urn:upnp-org:serviceId:dummy1",
                    "controlURL": None,
                    "eventSubURL": None,
                    "SCPDURL": None,
                }
            },
        },
        ssdp_location=f"http://{const.HOST}/upnp/basic_dev.cgi",
        ssdp_nt=None,
        ssdp_udn=f"uuid:upnp-BasicDevice-1_0-3014F711A0001F{const.CONFIG_ENTRY_UNIQUE_ID}",
        ssdp_ext="",
        ssdp_server="HomeMatic",
        ssdp_headers={
            "CACHE-CONTROL": "max-age=5000",
            "EXT": "",
            "LOCATION": f"http://{const.HOST}/upnp/basic_dev.cgi",
            "SERVER": "HomeMatic",
            "ST": "upnp:rootdevice",
            "USN": f"uuid:upnp-BasicDevice-1_0-3014F711A0001F{const.CONFIG_ENTRY_UNIQUE_ID}::upnp:rootdevice",
            "_timestamp": datetime.datetime(2023, 8, 9, 10, 25, 39, 669454),
            "_host": const.HOST,
            "_port": 1900,
            "_local_addr": ("0.0.0.0", 40610),
            "_remote_addr": (const.HOST, 1900),
            "_udn": f"uuid:upnp-BasicDevice-1_0-3014F711A0001F{const.CONFIG_ENTRY_UNIQUE_ID}",
            "_location_original": f"http://{const.HOST}/upnp/basic_dev.cgi",
            "location": f"http://{const.HOST}/upnp/basic_dev.cgi",
        },
        x_homeassistant_matching_domains={"homematicip_local"},
    )


@pytest.fixture
def control_config(hass: HomeAssistant, entry_data_v2) -> ControlConfig:
    """Create a config for the control unit."""
    return ControlConfig(
        hass=hass,
        entry_id=const.CONFIG_ENTRY_ID,
        data=entry_data_v2,
        default_port=const.DEFAULT_CALLBACK_PORT,
    )


@pytest.fixture
def mock_control_unit() -> ControlUnit:
    """Create mock control unit."""

    control_unit = Mock(
        spec=ControlUnit,
    )
    control_unit.central.get_data_points.return_value = []
    control_unit.central.get_hub_entities.return_value = []
    control_unit.central.get_channel_events.return_value = []
    control_unit.central.get_update_entities.return_value = []

    control_unit.get_new_data_points.return_value = []
    control_unit.get_new_hub_data_points.return_value = []

    with patch(
        "custom_components.homematicip_local.control_unit.ControlUnit",
        autospec=True,
        return_value=control_unit,
    ):
        yield control_unit


@pytest.fixture
async def mock_loaded_config_entry(
    hass: HomeAssistant,
    mock_config_entry_v2: MockConfigEntry,
    mock_control_unit: ControlUnit,
) -> ControlUnit:
    """Create mock running control unit."""
    with (
        patch("custom_components.homematicip_local.find_free_port", return_value=8765),
        patch(
            "custom_components.homematicip_local.control_unit.ControlConfig.create_control_unit",
            return_value=mock_control_unit,
        ),
    ):
        mock_config_entry_v2.add_to_hass(hass)
        await hass.config_entries.async_setup(mock_config_entry_v2.entry_id)
        await hass.async_block_till_done()
        assert mock_config_entry_v2.state == ConfigEntryState.LOADED
        yield mock_config_entry_v2


@pytest.fixture
async def factory(hass: HomeAssistant, mock_config_entry_v2: MockConfigEntry) -> helper.Factory:
    """Return central factory."""
    return helper.Factory(hass=hass, mock_config_entry=mock_config_entry_v2)


@pytest.fixture
async def factory_with_recorder(
    recorder_mock: Recorder, hass: HomeAssistant, mock_config_entry_v2: MockConfigEntry
) -> helper.Factory:
    """Return central factory with recorder."""
    return helper.Factory(hass=hass, mock_config_entry=mock_config_entry_v2)
