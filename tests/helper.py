"""Helpers for tests."""

from __future__ import annotations

import logging
from typing import Any, Final, TypeVar
from unittest.mock import MagicMock, Mock, patch

from hahomematic import const as hahomematic_const
from hahomematic.central import CentralConfig
from hahomematic.client import InterfaceConfig, _ClientConfig
from hahomematic.model.custom import CustomDataPoint
from hahomematic.model.data_point import BaseParameterDataPoint
from hahomematic_support.client_local import ClientLocal, LocalRessources
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.homematicip_local.control_unit import ControlUnit
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant

from tests import const

_LOGGER = logging.getLogger(__name__)

EXCLUDE_METHODS_FROM_MOCKS: Final = [
    "default_category",
    "event",
    "fire_device_removed_callback",
    "fire_data_point_updated_callback",
    "get_event_data",
    "get_on_time_and_cleanup",
    "is_state_change",
    "load_data_point_value",
    "register_device_removed_callback",
    "register_data_point_updated_callback",
    "register_internal_data_point_updated_callback",
    "set_usage",
    "unregister_device_removed_callback",
    "unregister_data_point_updated_callback",
    "unregister_internal_data_point_updated_callback",
    "write_value",
]
T = TypeVar("T")

# pylint: disable=protected-access


class Factory:
    """Factory for a central with one local client."""

    def __init__(self, hass: HomeAssistant, mock_config_entry: MockConfigEntry):
        """Init the central factory."""
        self._hass = hass
        self.mock_config_entry = mock_config_entry
        self.system_event_mock = MagicMock()
        self.entity_event_mock = MagicMock()
        self.ha_event_mock = MagicMock()

    async def setup_environment(
        self,
        address_device_translation: dict[str, str],
        add_sysvars: bool = False,
        add_programs: bool = False,
        ignore_devices_on_create: list[str] | None = None,
        un_ignore_list: list[str] | None = None,
    ) -> tuple[HomeAssistant, ControlUnit]:
        """Return a central based on give address_device_translation."""
        interface_config = InterfaceConfig(
            central_name=const.INSTANCE_NAME,
            interface=hahomematic_const.Interface.BIDCOS_RF,
            port=const.LOCAL_PORT,
        )

        central = CentralConfig(
            name=const.INSTANCE_NAME,
            host=const.HOST,
            username=const.USERNAME,
            password=const.PASSWORD,
            central_id="test1234",
            storage_folder="homematicip_local",
            interface_configs={
                interface_config,
            },
            default_callback_port=54321,
            client_session=None,
            un_ignore_list=un_ignore_list,
            start_direct=True,
        ).create_central()

        central.register_backend_system_callback(self.system_event_mock)
        central.register_backend_parameter_callback(self.entity_event_mock)
        central.register_homematic_callback(self.ha_event_mock)

        client = ClientLocal(
            client_config=_ClientConfig(
                central=central,
                interface_config=interface_config,
            ),
            local_resources=LocalRessources(
                address_device_translation=address_device_translation,
                ignore_devices_on_create=ignore_devices_on_create
                if ignore_devices_on_create
                else [],
            ),
        )
        await client.init_client()

        patch("hahomematic.central.CentralUnit._get_primary_client", return_value=client).start()
        patch("hahomematic.client._ClientConfig.get_client", return_value=client).start()
        patch(
            "hahomematic_support.client_local.ClientLocal.get_all_system_variables",
            return_value=const.SYSVAR_DATA if add_sysvars else [],
        ).start()
        patch(
            "hahomematic_support.client_local.ClientLocal.get_all_programs",
            return_value=const.PROGRAM_DATA if add_programs else [],
        ).start()
        patch(
            "hahomematic.central.CentralUnit._identify_ip_addr",
            return_value="127.0.0.1",
        ).start()

        await central.start()
        await central._init_hub()

        patch("custom_components.homematicip_local.find_free_port", return_value=8765).start()
        patch(
            "custom_components.homematicip_local.control_unit.ControlUnit._create_central",
            return_value=central,
        ).start()
        patch(
            "custom_components.homematicip_local.generic_entity.get_data_point",
            side_effect=get_data_point_mock,
        ).start()
        patch(
            "homeassistant.helpers.entity.Entity.entity_registry_enabled_default",
            return_value=True,
        ).start()

        # Start integration in hass
        self.mock_config_entry.add_to_hass(self._hass)
        await self._hass.config_entries.async_setup(self.mock_config_entry.entry_id)
        await self._hass.async_block_till_done()
        assert self.mock_config_entry.state == ConfigEntryState.LOADED

        control: ControlUnit = self.mock_config_entry.runtime_data
        await self._hass.async_block_till_done()
        if control._scheduler:
            control._scheduler.de_init()
        await self._hass.async_block_till_done()
        return self._hass, control


def get_and_check_state(
    hass: HomeAssistant, control: ControlUnit, entity_id: str, entity_name: str
):
    """Get and test basic device."""
    ha_state = hass.states.get(entity_id)
    assert ha_state is not None
    assert ha_state.name == entity_name
    data_point = get_data_point(control=control, entity_id=entity_id)

    return ha_state, data_point


def get_data_point(control: ControlUnit, entity_id: str):
    """Get the data point by entity id."""
    for dp in control.central.get_data_points():
        if dp.custom_id == entity_id:
            return dp
    for dp in control.central.get_hub_data_points():
        if dp.custom_id == entity_id:
            return dp


def get_mock(instance, **kwargs):
    """Create a mock and copy instance attributes over mock."""
    if isinstance(instance, Mock):
        instance.__dict__.update(instance._mock_wraps.__dict__)
        return instance

    mock = MagicMock(spec=instance, wraps=instance, **kwargs)
    mock.__dict__.update(instance.__dict__)
    return mock


def get_data_point_mock(data_point: T) -> T:
    """Return the mocked homematic entity."""
    try:
        for method_name in _get_mockable_method_names(data_point):
            patch.object(data_point, method_name).start()

        if isinstance(data_point, CustomDataPoint):
            for g_entity in data_point._data_entities.values():
                g_entity._set_last_update()
        elif isinstance(data_point, BaseParameterDataPoint):
            data_point._set_last_update()
        if hasattr(data_point, "is_valid"):
            assert data_point.is_valid is True
        # patch.object(data_point, "is_valid", return_value=True).start()
    except Exception:
        pass
    finally:
        return data_point


def _get_mockable_method_names(data_point: Any) -> list[str]:
    """Return all relevant method names for mocking."""
    method_list: list[str] = []
    for attribute in dir(data_point):
        # Get the attribute value
        attribute_value = getattr(data_point, attribute)
        # Check that it is callable
        if (
            callable(attribute_value)
            and attribute.startswith("_") is False
            and attribute not in EXCLUDE_METHODS_FROM_MOCKS
        ):
            method_list.append(attribute)
    return method_list
