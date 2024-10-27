"""Tests for binary_sensor entities of hahomematic."""

from __future__ import annotations

import pytest

from homeassistant.const import STATE_OFF, STATE_ON

from tests import const, helper

TEST_DEVICES: dict[str, str] = {
    "VCU5864966": "HmIP-SWDO-I.json",
}

# pylint: disable=protected-access


@pytest.mark.asyncio
async def test_hmbinarysensor(
    factory: helper.Factory,
) -> None:
    """Test HmBinarySensor."""

    entity_id = "binary_sensor.hmip_swdo_i_vcu5864966"
    entity_name = "HmIP-SWDO-I_VCU5864966"

    hass, control = await factory.setup_environment(TEST_DEVICES)
    ha_state, data_point = helper.get_and_check_state(
        hass=hass, control=control, entity_id=entity_id, entity_name=entity_name
    )

    assert ha_state.state == STATE_OFF

    await control.central.event(const.INTERFACE_ID, "VCU5864966:1", "STATE", 1)
    await hass.async_block_till_done()
    assert hass.states.get(entity_id).state == STATE_ON

    await control.central.event(const.INTERFACE_ID, "VCU5864966:1", "STATE", 0)
    await hass.async_block_till_done()
    assert hass.states.get(entity_id).state == STATE_OFF

    await control.central.event(const.INTERFACE_ID, "VCU5864966:1", "STATE", None)
    await hass.async_block_till_done()
    assert hass.states.get(entity_id).state == STATE_OFF


@pytest.mark.asyncio
async def test_hmsysvarbinarysensor(
    factory: helper.Factory,
) -> None:
    """Test SysvarDpBinarySensor."""
    entity_id = "binary_sensor.centraltest_sv_logic"
    entity_name = "CentralTest sv_logic"

    hass, control = await factory.setup_environment({}, add_sysvars=True)
    ha_state, data_point = helper.get_and_check_state(
        hass=hass, control=control, entity_id=entity_id, entity_name=entity_name
    )

    assert ha_state.state == STATE_OFF
