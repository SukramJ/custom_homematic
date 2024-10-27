"""Tests for recorder for excluded attributes of hahomematic entities."""

from __future__ import annotations

from hahomematic.const import EVENT_ADDRESS, EVENT_INTERFACE_ID, DeviceFirmwareState
import pytest
from pytest_homeassistant_custom_component.components.recorder.common import (
    async_wait_recording_done,
)

from custom_components.homematicip_local.const import EVENT_MODEL
from custom_components.homematicip_local.generic_entity import (
    ATTR_ADDRESS,
    ATTR_FUNCTION,
    ATTR_INTERFACE_ID,
    ATTR_MODEL,
    ATTR_NAME,
    ATTR_PARAMETER,
    ATTR_VALUE_STATE,
    HmEntityState,
)
from custom_components.homematicip_local.update import ATTR_FIRMWARE_UPDATE_STATE
from homeassistant.components.recorder.history import get_significant_states
from homeassistant.const import STATE_OFF, STATE_UNKNOWN
from homeassistant.util import dt as dt_util

from tests import helper

TEST_DEVICES: dict[str, str] = {
    "VCU5864966": "HmIP-SWDO-I.json",
    "VCU2128127": "HmIP-BSM.json",
}

# pylint: disable=protected-access


@pytest.mark.asyncio
async def no_test_generic_entity_un_recorded(
    factory_with_recorder: helper.Factory,
) -> None:
    """Test HmBinarySensor."""

    entity_id = "binary_sensor.hmip_swdo_i_vcu5864966"
    entity_name = "HmIP-SWDO-I_VCU5864966 "

    hass, control = await factory_with_recorder.setup_environment(TEST_DEVICES)
    ha_state, data_point = helper.get_and_check_state(
        hass=hass, control=control, entity_id=entity_id, entity_name=entity_name
    )

    assert ha_state.state == STATE_OFF
    assert ha_state.attributes[ATTR_ADDRESS] == "VCU5864966:1"
    assert ha_state.attributes[ATTR_FUNCTION] is None
    assert ha_state.attributes[ATTR_INTERFACE_ID] == "CentralTest-BidCos-RF"
    assert ha_state.attributes[ATTR_MODEL] == "HmIP-SWDO-I"
    assert ha_state.attributes[ATTR_PARAMETER] == "STATE"
    assert ha_state.attributes[ATTR_VALUE_STATE] == HmEntityState.UNCERTAIN
    await async_wait_recording_done(hass)

    states = await hass.async_add_executor_job(
        get_significant_states,
        hass,
        dt_util.now(),
        None,
        hass.states.async_entity_ids(),
    )
    assert len(states) == 12
    assert states.get(entity_id)
    for entity_states in states.values():
        for state in entity_states:
            if state.entity_id == entity_id:
                assert ATTR_ADDRESS not in state.attributes
                assert ATTR_FUNCTION not in state.attributes
                assert ATTR_INTERFACE_ID not in state.attributes
                assert ATTR_MODEL not in state.attributes
                assert ATTR_PARAMETER not in state.attributes
                assert ATTR_VALUE_STATE not in state.attributes
                break


@pytest.mark.asyncio
async def no_test_event_entity_un_recorded(
    factory_with_recorder: helper.Factory,
) -> None:
    """Test HmBinarySensor."""

    entity_id = "event.hmip_bsm_vcu2128127_ch1"
    entity_name = "HmIP-BSM_VCU2128127 ch1"

    hass, control = await factory_with_recorder.setup_environment(TEST_DEVICES)
    ha_state, data_point = helper.get_and_check_state(
        hass=hass, control=control, entity_id=entity_id, entity_name=entity_name
    )
    assert ha_state.state == STATE_UNKNOWN
    assert ha_state.attributes[EVENT_ADDRESS] == "VCU2128127:1"
    assert ha_state.attributes[EVENT_INTERFACE_ID] == "CentralTest-BidCos-RF"
    assert ha_state.attributes[EVENT_MODEL] == "HmIP-BSM"
    await async_wait_recording_done(hass)

    states = await hass.async_add_executor_job(
        get_significant_states,
        hass,
        dt_util.now(),
        None,
        hass.states.async_entity_ids(),
    )
    assert len(states) == 12
    assert states.get(entity_id)
    for entity_states in states.values():
        for state in entity_states:
            if state.entity_id == entity_id:
                assert EVENT_ADDRESS not in state.attributes
                assert EVENT_INTERFACE_ID not in state.attributes
                assert EVENT_MODEL not in state.attributes
                break


@pytest.mark.asyncio
async def no_test_update_entity_un_recorded(
    factory_with_recorder: helper.Factory,
) -> None:
    """Test HmBinarySensor."""

    entity_id = "update.hmip_swdo_i_vcu5864966_update"
    entity_name = "HmIP-SWDO-I_VCU5864966 Update"

    hass, control = await factory_with_recorder.setup_environment(TEST_DEVICES)
    ha_state, data_point = helper.get_and_check_state(
        hass=hass, control=control, entity_id=entity_id, entity_name=entity_name
    )

    assert ha_state.state == STATE_OFF
    assert ha_state.attributes[ATTR_FIRMWARE_UPDATE_STATE] == DeviceFirmwareState.UP_TO_DATE
    await async_wait_recording_done(hass)

    states = await hass.async_add_executor_job(
        get_significant_states,
        hass,
        dt_util.now(),
        None,
        hass.states.async_entity_ids(),
    )
    assert len(states) == 12
    assert states.get(entity_id)
    for entity_states in states.values():
        for state in entity_states:
            if state.entity_id == entity_id:
                assert ATTR_FIRMWARE_UPDATE_STATE not in state.attributes
                break


@pytest.mark.asyncio
async def no_test_sysvar_entity_un_recorded(
    factory_with_recorder: helper.Factory,
) -> None:
    """Test HmBinarySensor."""
    entity_id = "binary_sensor.centraltest_sv_logic"
    entity_name = "CentralTest sv_logic"

    hass, control = await factory_with_recorder.setup_environment({}, add_sysvars=True)
    ha_state, data_point = helper.get_and_check_state(
        hass=hass, control=control, entity_id=entity_id, entity_name=entity_name
    )

    assert ha_state.state == STATE_OFF
    assert ha_state.attributes[ATTR_NAME] == "sv_logic"
    await async_wait_recording_done(hass)

    states = await hass.async_add_executor_job(
        get_significant_states,
        hass,
        dt_util.now(),
        None,
        hass.states.async_entity_ids(),
    )
    assert len(states) == 12
    assert states.get(entity_id)
    for entity_states in states.values():
        for state in entity_states:
            if state.entity_id == entity_id:
                assert ATTR_NAME not in state.attributes
                break
