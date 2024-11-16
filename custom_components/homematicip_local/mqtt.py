"""Homematic(IP) local is a Python 3 module for Home Assistant and Homematic(IP) devices."""

from __future__ import annotations

import logging
from typing import Any, Final, cast

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

    def __init__(self, hass: HomeAssistant, central: CentralUnit, mqtt_prefix: str) -> None:
        """Init the mqtt consumer."""
        self._hass: Final = hass
        self._central: Final = central
        self._mqtt_prefix: Final = f"{mqtt_prefix}/" if mqtt_prefix else ""
        self._sub_state: dict[str, EntitySubscription] | None = None

    async def subscribe(self) -> None:
        """Subscribe to events."""
        if not self._mqtt_is_configured():
            return
        if self._sub_state is None and (topics := self._get_topics()):
            self._sub_state = async_prepare_subscribe_topics(self._hass, self._sub_state, topics)
            await async_subscribe_topics(self._hass, self._sub_state)

    def unsubscribe(self) -> None:
        """Unsubscribe from events."""
        if not self._mqtt_is_configured():
            return
        if self._sub_state:
            async_unsubscribe_topics(self._hass, self._sub_state)

    @callback
    def _on_mqtt_msg_receive(self, msg: ReceiveMessage) -> None:
        """Do something on message receive."""
        _LOGGER.debug("MQTT Message received: %s", msg.payload)
        state_path = (
            msg.topic[len(self._mqtt_prefix) :]
            if msg.topic.startswith(self._mqtt_prefix)
            else msg.topic
        )
        payload_dict = json_loads(msg.payload)
        if (payload_value := cast(dict, payload_dict).get("v")) is not None:
            self._central.data_point_path_event(state_path=state_path, value=payload_value)

    def _mqtt_is_configured(self) -> bool:
        """Check if mqtt is configured."""
        return self._hass.data.get("mqtt") is not None

    def _get_topics(self) -> dict[str, dict[str, Any]]:
        """Return the topics for the central."""
        topics: dict[str, dict[str, Any]] = {}
        for state_path in self._central.get_data_point_path():
            topics[state_path.replace("/", "_")] = {
                "topic": f"{self._mqtt_prefix}{state_path}",
                "msg_callback": lambda msg: self._on_mqtt_msg_receive(msg=msg),
                "qos": 0,
            }
        return topics
