"""The tests for Homematic(IP) Local device triggers."""

from __future__ import annotations

import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_get_device_automations,
    async_mock_service,
    mock_device_registry,
    mock_registry,
)

from custom_components.homematicip_local import DOMAIN as HMIP_DOMAIN
from homeassistant.components import automation
from homeassistant.const import STATE_OFF, STATE_ON
from homeassistant.helpers import device_registry
from homeassistant.setup import async_setup_component


@pytest.fixture
def device_reg(hass):
    """Return an empty, loaded, registry."""
    return mock_device_registry(hass)


@pytest.fixture
def entity_reg(hass):
    """Return an empty, loaded, registry."""
    return mock_registry(hass)


@pytest.fixture
def calls(hass):
    """Track calls to a mock service."""
    return async_mock_service(hass, "test", "automation")


async def no_test_get_triggers(hass, device_reg, entity_reg):
    """Test we get the expected triggers from a Homematic(IP) Local."""
    config_entry = MockConfigEntry(domain="test", data={})
    config_entry.add_to_hass(hass)
    device_entry = device_reg.async_get_or_create(
        config_entry_id=config_entry.entry_id,
        connections={(device_registry.CONNECTION_NETWORK_MAC, "12:34:56:AB:CD:EF")},
    )
    entity_reg.async_get_or_create(HMIP_DOMAIN, "test", "5678", device_id=device_entry.id)
    await async_get_device_automations(hass, "trigger", device_entry.id)
    # assert_lists_same(triggers, expected_triggers)


async def no_test_if_fires_on_state_change(hass, calls):
    """Test for turn_on and turn_off triggers firing."""
    hass.states.async_set("homematicip_local.entity", STATE_OFF)

    assert await async_setup_component(
        hass,
        automation.HMIP_DOMAIN,
        {
            automation.HMIP_DOMAIN: [
                {
                    "trigger": {
                        "platform": "device",
                        "domain": HMIP_DOMAIN,
                        "device_id": "",
                        "entity_id": "homematicip_local.entity",
                        "type": "turned_on",
                    },
                    "action": {
                        "service": "test.automation",
                        "data_template": {
                            "some": (
                                "turn_on - {{ trigger.platform}} - "
                                "{{ trigger.entity_id}} - {{ trigger.from_state.state}} - "
                                "{{ trigger.to_state.state}} - {{ trigger.for }} - "
                                "{{ trigger.id}}"
                            )
                        },
                    },
                },
                {
                    "trigger": {
                        "platform": "device",
                        "domain": HMIP_DOMAIN,
                        "device_id": "",
                        "entity_id": "homematicip_local.entity",
                        "type": "turned_off",
                    },
                    "action": {
                        "service": "test.automation",
                        "data_template": {
                            "some": (
                                "turn_off - {{ trigger.platform}} - "
                                "{{ trigger.entity_id}} - {{ trigger.from_state.state}} - "
                                "{{ trigger.to_state.state}} - {{ trigger.for }} - "
                                "{{ trigger.id}}"
                            )
                        },
                    },
                },
            ]
        },
    )

    # Fake that the entity is turning on.
    hass.states.async_set("homematicip_local.entity", STATE_ON)
    await hass.async_block_till_done()
    assert len(calls) == 1
    assert calls[0].data["some"] == "turn_on - device - {} - off - on - None - 0".format("homematicip_local.entity")

    # Fake that the entity is turning off.
    hass.states.async_set("homematicip_local.entity", STATE_OFF)
    await hass.async_block_till_done()
    assert len(calls) == 2
    assert calls[1].data["some"] == "turn_off - device - {} - on - off - None - 0".format("homematicip_local.entity")
