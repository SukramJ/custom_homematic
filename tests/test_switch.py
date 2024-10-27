"""Tests for switch entities of hahomematic."""

from __future__ import annotations

from typing import cast

from hahomematic.model.hub import SysvarDpSwitch
import pytest

from homeassistant.const import STATE_OFF, STATE_ON

from tests import const, helper

TEST_DEVICES: dict[str, str] = {
    "VCU2128127": "HmIP-BSM.json",
}

# pylint: disable=protected-access


@pytest.mark.asyncio
async def test_switch(factory: helper.Factory) -> None:
    """Test CeSwitch."""
    entity_id = "switch.hmip_bsm_vcu2128127"
    entity_name = "HmIP-BSM_VCU2128127"

    hass, control = await factory.setup_environment(TEST_DEVICES)
    ha_state, data_point = helper.get_and_check_state(
        hass=hass, control=control, entity_id=entity_id, entity_name=entity_name
    )
    assert ha_state.state == STATE_OFF

    await control.central.event(const.INTERFACE_ID, "VCU2128127:4", "STATE", 1)
    await hass.async_block_till_done()
    assert hass.states.get(entity_id).state == STATE_ON
    assert data_point.turn_on.call_count == 0
    await hass.services.async_call("switch", "turn_on", {"entity_id": entity_id}, blocking=True)
    assert data_point.turn_on.call_count == 1

    await control.central.event(const.INTERFACE_ID, "VCU2128127:4", "STATE", 0)
    await hass.async_block_till_done()
    assert hass.states.get(entity_id).state == STATE_OFF
    assert data_point.turn_off.call_count == 0
    await hass.services.async_call("switch", "turn_off", {"entity_id": entity_id}, blocking=True)
    assert data_point.turn_off.call_count == 1


@pytest.mark.asyncio
async def test_hmsysvarswitch(factory: helper.Factory) -> None:
    """Test SysvarDpSwitch."""
    entity_id = "switch.centraltest_sv_alarm_ext"
    entity_name = "CentralTest sv_alarm_ext"

    hass, control = await factory.setup_environment({}, add_sysvars=True)
    ha_state, _ = helper.get_and_check_state(
        hass=hass, control=control, entity_id=entity_id, entity_name=entity_name
    )
    data_point: SysvarDpSwitch = cast(
        SysvarDpSwitch, helper.get_data_point(control=control, entity_id=entity_id)
    )
    assert ha_state.state == STATE_OFF

    assert data_point.send_variable.call_count == 0
    await hass.services.async_call("switch", "turn_on", {"entity_id": entity_id}, blocking=True)
    assert data_point.send_variable.call_count == 1
    assert data_point.send_variable.mock_calls[0].args[0] is True

    await hass.services.async_call("switch", "turn_off", {"entity_id": entity_id}, blocking=True)
    assert data_point.send_variable.call_count == 2
    assert data_point.send_variable.mock_calls[1].args[0] is False
