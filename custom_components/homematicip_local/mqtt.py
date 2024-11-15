"""Homematic(IP) local is a Python 3 module for Home Assistant and Homematic(IP) devices."""

from __future__ import annotations

import logging
from typing import Final, cast

from hahomematic.central import CentralUnit

from homeassistant.components.mqtt.models import ReceiveMessage
from homeassistant.components.mqtt.subscription import (
    EntitySubscription,
    async_prepare_subscribe_topics,
    async_subscribe_topics,
    async_unsubscribe_topics,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.util.json import json_loads

_LOGGER = logging.getLogger(__name__)


class MQTTConsumer:
    """The mqtt consumer."""

    _instance: Final[MQTTConsumer | None] = None

    def __init__(self, hass: HomeAssistant) -> None:
        """Init the mqtt consumer."""
        self._hass: Final = hass
        self._centrals: Final[dict[str, CentralUnit]] = {}
        self._sub_state: dict[str, EntitySubscription] | None = None
        self._topics = {
            "events": {
                "topic": "device/status/#",
                "msg_callback": lambda msg: self._on_mqtt_msg_receive(msg=msg),
                "qos": 0,
            }
        }

    def __new__(cls, hass: HomeAssistant) -> MQTTConsumer:  # noqa: PYI034
        """Create new XmlRPC server."""
        if (consumer := cls._instance) is None:
            _LOGGER.debug("Creating MQTT consumer")
            return super().__new__(cls)
        return consumer

    async def _subscribe(self) -> None:
        """Subscribe to events."""
        if not self._mqtt_is_configured():
            return
        if self._sub_state is None:
            self._sub_state = async_prepare_subscribe_topics(
                self._hass, self._sub_state, self._topics
            )
            await async_subscribe_topics(self._hass, self._sub_state)

    def _unsubscribe(self) -> None:
        """Unsubscribe from events."""
        if not self._mqtt_is_configured():
            return
        if self._sub_state:
            async_unsubscribe_topics(self._hass, self._sub_state)

    @callback
    def _on_mqtt_msg_receive(self, msg: ReceiveMessage) -> None:
        """Do something on message receive."""
        _LOGGER.debug("MQTT Message received: %s", msg.payload)
        payload_dict = json_loads(msg.payload)
        if (payload_value := cast(dict, payload_dict).get("v")) is not None:
            for central in self._centrals.values():
                central.data_point_path_event(state_path=msg.topic, value=payload_value)

    def _mqtt_is_configured(self) -> bool:
        """Check if mqtt is configured."""
        return self._hass.data.get("mqtt") is not None

    async def subscribe(self, central: CentralUnit) -> None:
        """Register a central in the mqtt consumer."""
        if not self._centrals.get(central.name):
            await self._subscribe()
            self._centrals[central.name] = central

    def unsubscribe(self, central: CentralUnit) -> None:
        """Unregister a central from mqtt consumer."""
        if self._centrals.get(central.name):
            del self._centrals[central.name]
        if not self._centrals:
            self._unsubscribe()
