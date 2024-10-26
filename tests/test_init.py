"""Test the Homematic(IP) Local init."""

from __future__ import annotations

from unittest.mock import patch

from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.homematicip_local
from custom_components.homematicip_local.config_flow import DomainConfigFlow
from custom_components.homematicip_local.const import CONF_ADVANCED_CONFIG, DOMAIN as HMIP_DOMAIN
from custom_components.homematicip_local.control_unit import ControlUnit
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant

from tests import const


async def test_setup_entry(
    hass: HomeAssistant,
    mock_config_entry_v2: MockConfigEntry,
    mock_control_unit: ControlUnit,
) -> None:
    """Test setup entry."""
    # no config_entry exists
    assert len(hass.config_entries.async_entries(HMIP_DOMAIN)) == 0
    assert not hass.data.get(HMIP_DOMAIN)

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
        config_entries = hass.config_entries.async_entries(HMIP_DOMAIN)
        assert len(config_entries) == 1
        config_entry = config_entries[0]
        assert config_entry.state == ConfigEntryState.LOADED


async def test_check_min_version(
    hass: HomeAssistant,
    mock_config_entry_v2: MockConfigEntry,
    mock_control_unit: ControlUnit,
) -> None:
    """Test check_min_version."""
    # no config_entry exists

    orig_version = custom_components.homematicip_local.HMIP_LOCAL_MIN_HA_VERSION
    custom_components.homematicip_local.HMIP_LOCAL_MIN_HA_VERSION = "2099.1.1"
    mock_config_entry_v2.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry_v2.entry_id) is False
    custom_components.homematicip_local.HMIP_LOCAL_MIN_HA_VERSION = orig_version


async def test_migrate_entry(
    hass: HomeAssistant,
    mock_config_entry_v1: MockConfigEntry,
    mock_control_unit: ControlUnit,
) -> None:
    """Test setup entry."""
    # no config_entry exists
    assert len(hass.config_entries.async_entries(HMIP_DOMAIN)) == 0
    assert not hass.data.get(HMIP_DOMAIN)

    with (
        patch("custom_components.homematicip_local.find_free_port", return_value=8765),
        patch(
            "custom_components.homematicip_local.control_unit.ControlConfig.create_control_unit",
            return_value=mock_control_unit,
        ),
    ):
        mock_config_entry_v1.add_to_hass(hass)
        await hass.config_entries.async_setup(mock_config_entry_v1.entry_id)
        await hass.async_block_till_done()
        config_entries = hass.config_entries.async_entries(HMIP_DOMAIN)
        assert len(config_entries) == 1
        config_entry = config_entries[0]
        assert config_entry.state == ConfigEntryState.LOADED
        assert config_entry.version == DomainConfigFlow.VERSION
        assert config_entry.data[CONF_ADVANCED_CONFIG] == {
            "enable_system_notifications": True,
            "program_scan_enabled": False,
            "sysvar_scan_enabled": False,
            "sysvar_scan_interval": 30,
            "un_ignore": [],
        }


async def test_unload_entry(
    hass: HomeAssistant, mock_loaded_config_entry: MockConfigEntry
) -> None:
    """Test unload entry."""
    assert hass.data[HMIP_DOMAIN]
    assert mock_loaded_config_entry.state == ConfigEntryState.LOADED
    assert await hass.config_entries.async_unload(mock_loaded_config_entry.entry_id) is True
    assert mock_loaded_config_entry.state == ConfigEntryState.NOT_LOADED
    await hass.async_block_till_done()
    # assert HMIP_DOMAIN not in hass.data
    # retry possible?
    # assert await hass.config_entries.async_unload(mock_loaded_config_entry.entry_id) is False


async def test_remove_entry(
    hass: HomeAssistant, mock_loaded_config_entry: MockConfigEntry
) -> None:
    """Test unload entry."""
    assert hass.data[HMIP_DOMAIN]
    assert mock_loaded_config_entry.state == ConfigEntryState.LOADED
    await hass.config_entries.async_remove(mock_loaded_config_entry.entry_id)
    assert mock_loaded_config_entry.state == ConfigEntryState.NOT_LOADED
    await hass.async_block_till_done()
    # assert HMIP_DOMAIN not in hass.data


async def test_reload_entry(
    hass: HomeAssistant, mock_loaded_config_entry: MockConfigEntry
) -> None:
    """Test unload entry."""
    assert mock_loaded_config_entry.title == const.INSTANCE_NAME
    assert hass.data[HMIP_DOMAIN]
    hass.config_entries.async_update_entry(mock_loaded_config_entry, title="Reload")
    await hass.async_block_till_done()
    assert hass.data[HMIP_DOMAIN]
    assert mock_loaded_config_entry.title == "Reload"
