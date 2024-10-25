# custom_homematic

Homematic(IP) Integration for Home Assistant

[Installation](https://github.com/danielperna84/custom_homematic/wiki/Installation)

[Alternative Installation by J. Maus](https://github.com/jens-maus/RaspberryMatic/wiki/HomeAssistant-Integration)

[Wiki with additional information](https://github.com/danielperna84/hahomematic/wiki)
Please support the community by adding more valuable information to the wiki.delete_device
# ISSUES and DISCUSSIONS

Please report issues in [hahomamatic repo](https://github.com/danielperna84/hahomematic/issues).
New discussions can be started and found in [hahomamatic repo](https://github.com/danielperna84/hahomematic/discussions).
Feature requests can be added as a discussion too.
A good practice is to search in issues and discussions before starting a new one.

# Homematic(IP) Local (documentation)

The [HomeMatic](https://www.homematic.com/) integration provides bi-directional communication with your HomeMatic hub (CCU, Homegear etc.).
It uses an XML-RPC connection to set values on devices and subscribes to receive events the devices and the CCU emit.
You can configure this integration multiple times if you want to integrate multiple HomeMatic hubs into Home Assistant.  
If you are using Homegear with paired [Intertechno](https://intertechno.at/) devices, uni-directional communication is possible as well.

Support for CUxD is not possible due to a missing Python library for BinRPC.

**Please take the time to read the entire documentation before asking for help. It will answer the most common questions that come up while working with this integration.**

## Device support

HomeMatic and HomematicIP devices are integrated by automatically detecting the available parameters, for which suitable entities will be added to the corresponding device-object within Home Assistant.
However, for more complex devices (thermostats, some cover-devices and more) we perform a custom mapping to better represent the devices features. This is an internal detail you usually don't have to care about.
It may become relevant though if new hardware becomes available.
In such a case the automatic mode will be active. Therefore f.ex. a new thermostat-model might not include the `climate` entity.
In such a case you may report the missing customization in the [hahomematic](https://github.com/danielperna84/hahomematic) repository.
Please report missing devices **after** you installed the integration and ensured it is missing or faulty.

### Deactivated Entities

A lot of additional entities were initially created _deactivated_ and can be _activated_, if necessary, in the `advanced settings` of the entity.

## Requirements

### Hardware

This integration can be used with any CCU-compatible HomeMatic hub that exposes the required XML-RPC interface. This includes:

- CCU2/3
- RaspberryMatic
- Debmatic
- Homegear
- Home Assistant OS / Supervised with a suitable add-on + communication device

Due to a bug in previous version of the CCU2 / CCU3, this integration requires at least the following version for usage with homematic IP devices:

- CCU2: 2.53.27
- CCU3: 3.53.26

### Firewall and required ports

To allow communication to your HomeMatic hub, a few ports on the hub have to be accessible from your Home Assistant machine. The relevant default ports are:

- BidCosRF (_old_ wireless devices): `2001` / `42001` (with enabled TLS)
- HomematicIP (wireless and wired): `2010` / `42010` (with enabled TLS)
- HomeMatic wired (_old_ wired devices): `2000` / `42000` (with enabled TLS)
- Virtual thermostat groups: `9292` / `49292` (with enabled TLS)
- JSON-RPC (used to get names and rooms): `80` / `443` (with enabled TLS)

Advanced setups might consider this:

This integration starts a local XmLRPC server within HA, which automatically selects a free port or uses the optionally defined callback port.
This means that the CCU must be able to start a new connection to the system running HA and to the port. So check the firewall of the system running HA (host/VM) to allow communication from the CCU. This Traffic (state updates) is always unencrypted.
If running HA on docker it is recommended to use `network_mode: host`, or specify [callback host/port](https://github.com/danielperna84/custom_homematic#callback_host-and-callback_port).

### Authentication

This integration always passes credentials to the HomeMatic hub when connecting.
For CCU and descendants (RaspberryMatic, debmatic) it is **recommended** to enable authentication for XmlRPC communication (Settings/Control panel/Security/Authentication). JsonRPC communication ia always authenticated.

The account used for communication is **required** to have admin privileges on your HomeMatic hub.
It is important to note though, that special characters within your credentials may break the possibility to authenticate.
Allowed characters for a CCU password are: `A-Z`, `a-z`, `0-9` and `.!$():;#-`.
The CCU WebUI also supports `ÄäÖöÜüß`, but these characters are not supported by the XmlRPC servers.

If you are using Homegear and have not set up authentication, please enter dummy-data to complete the configuration flow.

# Configuration

Adding Homematic(IP) Local to you Home Assistant instance can be done via the user interface, by using this My button: [ADD INTEGRATION](https://my.home-assistant.io/redirect/config_flow_start?domain=homematicip_local)

## Manual configuration steps

- Browse to your Home Assistant instance.
- In the sidebar click on [Configuration](https://my.home-assistant.io/redirect/config)
- From the configuration menu select: [Integrations](https://my.home-assistant.io/redirect/integrations)
- In the bottom right, click on the [Add Integration](https://my.home-assistant.io/redirect/config_flow_start?domain=homematicip_local) button.
- From the list, search and select "Homematic(IP) Local".
- Follow the instruction on screen to complete the set up.

## Auto-discovery

The integration supports auto-discovery for the CCU and compatible hubs like RaspberryMatic. The Home Assistant User Interface will notify you about the integrationg being available for setup. It will pre-fill the instance-name and IP address of your Homematic hub. If you have already set up the integration manually, you can either click the _Ignore_ button or re-configure your existing instance to let Home Assistant know the existing instance is the one it has detected. After re-configuring your instance a HA restart is required.

Autodiscovery uses the last 10-digits of your rf-module's serial to uniquely identify your CCU, but there are rare cases, where the CCU API and the UPNP-Message contains/returns different values. In these cases, where the auto-discovered instance does not disappear after a HA restart, just click on the _Ignore_ button.
Known cases are in combination with the rf-module `HM-MOD-RPI-PCB`.

### Configuration Variables

#### Central

```yaml
instance_name:
  required: true
  description: Name of the HA instance. Allowed characters are a-z and 0-9.
    If you want to connect to the same CCU instance from multiple HA installations this instance_name must be unique on every HA instance.
  type: string
host:
  required: true
  description: Hostname or IP address of your hub.
  type: string
username:
  required: true
  description: Case sensitive. Username of a user in admin-role on your hub.
  type: string
password:
  required: true
  description: Case sensitive. Password of the admin-user on your hub.
  type: string
tls:
  required: true
  description:
    Enable TLS encryption. This will change the default for json_port from 80 to 443.
    TLS must be enabled, if http to https forwarding is enabled in the CCU.
    Traffic from CCU to HA (state updates) is always unencrypted.
  type: boolean
  default: false
verify_tls:
  required: true
  description: Enable TLS verification.
  type: boolean
  default: false
callback_host:
  required: false
  description: Hostname or IP address for callback-connection (only required in special network conditions).
  type: string
callback_port:
  required: false
  description: Port for callback-connection (only required in special network conditions).
  type: integer
json_port:
  required: false
  description: Port used the access the JSON-RPC API.
  type: integer
```

#### Interface

This page always displays the default values, also when reconfiguring the integration.

```yaml
hmip_rf_enabled:
  required: true
  description: Enable HomematicIP (wiredless and wired).
  type: boolean
  default: true
hmip_rf_port:
  required: false
  description: Port for HomematicIP (wireless and wired).
  type: integer
  default: 2010
bidos_rf_enabled:
  required: true
  description: Enable BidCos (HomeMatic wireless).
  type: boolean
  default: true
bidos_rf_port:
  required: false
  description: Port for BidCos (HomeMatic wireless).
  type: integer
  default: 2001
virtual_devices_enabled:
  required: true
  description: Enable heating groups.
  type: boolean
  default: false
virtual_devices_port:
  required: false
  description: Port for heating groups.
  type: integer
  default: 9292
virtual_devices_path:
  required: false
  description: Path for heating groups
  type: string
  default: /groups
hs485d_enabled:
  required: true
  description: Enable HomeMatic wired.
  type: boolean
  default: false
hs485d_port:
  required: false
  description: Port for HomeMatic wired.
  type: integer
  default: 2000
```

#### Advanced (optional)

```yaml
program_scan_enabled:
  required: true
  description: Enable program scanning.
  type: boolean
  default: true
sysvar_scan_enabled:
  required: true
  description: Enable system program scanning.
  type: boolean
  default: true
sysvar_scan_interval:
  required: true
  description:
    Interval in seconds between system variable/program scans. The minimum value is 5.
    Intervals of less than 15s are not recommended, and put a lot of strain on slow backend systems in particular.
    Instead, a higher interval with an on-demand call from the `homematicip_local.fetch_system_variables` action is recommended.
  type: integer
  default: 30
enable_system_notifications:
  required: true
  description:
    Control if system notification should be displayed. Affects CALLBACK and PINGPONG notifications.
    It's not recommended to disable this option, because this would hide problems on your system.
    A better option is to solve the communication problems in your environment.
  type: integer
  default: true
listen_on_all_ip:
  required: true
  description:
    By default the XMLRPC server only listens to the ip address, that is used for the communication to the CCU, because, for security reasons, it's better to only listen on needed ports.
    This works for most of the installations, but in rare cases, when double virtualization is used (Docker on Windows/Mac), this doesn't work.
    In those cases it is necessary, that the XMLRPC server listens an all ('0.0.0.0') ip addresses.
    If you have multiple instances running ensure that all are configured equally.
  type: integer
  default: false
un_ignore: (Only visible when reconfiguring the integration)
  required: false
  description:
    Add additional datapoints/parameters to your instance. See Unignore device parameters
  type: list of strings
  default: []
```


### JSON-RPC Port

The JSON-RPC Port is used to fetch names and room information from the CCU. The default value is `80`. But if you enable TLS the port `443` will be used. You only have to enter a custom value here if you have set up the JSON-RPC API to be available on a different port.  
If you are using Homegear the names are fetched using metadata available via XML-RPC. Hence the JSON-RPC port is irrelevant for Homegear users.
**To reset the JSON-RPC Port it must be set to 0.**

### callback_host and callback_port

These two options are required for _special_ network environments. If for example Home Assistant is running within a Docker container and detects its own IP to be within the Docker network, the CCU won't be able to establish the connection to Home Assistant. In this case you have to specify which address and port the CCU should connect to. This may require forwarding connections on the Docker host machine to the relevant container.

**To reset the callback host it must be set to one blank character.**
**To reset the callback port it must be set to 0.**

## System variables

System variables are fetched every 30 seconds from backend (CCU/Homegear) and belong to a device of type CCU. You could also click on action on the integration's overview in HA.

System variables are initially created as **[deactivated](https://github.com/danielperna84/custom_homematic#deactivated-entities)** entity.

The types of system variables in the CCU are:

- _character string_ (Zeichenkette)
- _list of values_ (Werteliste)
- _number_ (Zahl)
- _logic value_ (Logikwert)
- _alert_ (Alarm)

System variables have a description that can be added in the CCU's UI.
If you add the marker `hahm` to the description extended features for this system variable can be used in HA.
This `hahm` marker is used to control the entity creation in HA.
Switching system variables from DEFAULT -> EXTENDED or EXTENDED -> DEFAULT requires a restart of HA or a reload of the integration.

When using Homegear system variables are handled like the DEFAULT.

### This is how entities are created from system variables:

- DEFAULT: system variables that do **not** have the **marker** `hahm` in description:
  - _character string_, _list of values_, _number_ --> `sensor` entity
  - _alert_, _logic value_ --> `binary_sensor` entity
- EXTENDED: system variables that do have the **marker** `hahm` in description:
  - _list of values_ --> `select` entity
  - _number_ --> `number` entity
  - _alarm_, _logic value_ —> `switch` entity
  - _character string_ —> `text` entity

Using `select`, `number`, `switch` and `text` results in the following advantages:

- System variables can be changed directly in the UI without additional logic.
- The general actions for `select`, `number`, `switch` and `text` can be used.
- The action `homematicip_local.set_variable_value` can, but no longer has to, be used to write system variables.
- Use of device based automations (actions) is possible.

## Actions

The Homematic(IP) Local integration makes various custom actions available.

### `homematicip_local.clear_cache`

Clears the cache for a central unit from Home Assistant. Requires a restart.

### `homematicip_local.create_central_links`

Creates a central link from a device to the backend. This is required for rf-devices to enable button-press events.
[See](https://github.com/danielperna84/custom_homematic?tab=readme-ov-file#events-for-homematicip-devices)

### `homematicip_local.copy_schedule`

__Disclaimer: To much writing to the device MASTER paramset could kill your device's storage.__

Copy the schedule of a climate device to another device

### `homematicip_local.copy_schedule_profile`

__Disclaimer: To much writing to the device MASTER paramset could kill your device's storage.__

Copy the schedule profile of a climate device to another/the same device

### `homematicip_local.disable_away_mode`

Disable the away mode for `climate` devices. This only works with HomematicIP devices.

### `homematicip_local.enable_away_mode_by_calendar`

Enable the away mode immediately or by start date and time (e.g. 2022-09-01 10:00), and specify the end by date and time (e.g. 2022-10-01 10:00). This only works with HomematicIP devices.

### `homematicip_local.enable_away_mode_by_duration`

Enable the away mode immediately, and specify the end time by setting a duration (in hours). This only works with HomematicIP devices.

### `homematicip_local.export_device_definition`

Exports a device definition (2 files) to

- 'Your home-assistant config directory'/homematicip_local/export_device_descriptions/{device_type}.json
- 'Your home-assistant config directory'/homematicip_local/export_paramset_descriptions/{device_type}.json

Please create a pull request with both files at [pydevccu](https://github.com/danielperna84/pydevccu), if the device not exists, to support future development of this component.
This data can be used by the developers to add customized entities for new devices.

### `homematicip_local.fetch_system_variables`

action to fetch system variables on demand from backend independent from default 30s schedule.
Using this action too often could have a negative effect on the stability of your backend.

### `homematicip_local.force_device_availability`

Reactivate a device in Home Assistant that has been made unavailable by an UNREACH event from CCU.
This action will only override the availability status of a device and all its dependent entities. There is no communication to the backend to enforce a reactivation!

This is not a solution for communication problems with homematic devices.
Use this only to reactivate devices with flaky communication to gain control again.

### `homematicip_local.get_device_value`

Get a device parameter via the XML-RPC interface.

### `homematicip_local.get_link_peers`

Call to `getLinkPeers` on the XML-RPC interface.
Returns a dict of direct connection partners

### `homematicip_local.get_paramset`

Call to `getParamset` on the XML-RPC interface.
Returns a paramset

### `homematicip_local.get_link_paramset`

Call to `getParamset` for direct connections on the XML-RPC interface.
Returns a paramset

### `homematicip_local.get_schedule_profile`

Returns the schedule of a climate profile.

### `homematicip_local.get_schedule_profile_weekday`

Returns the schedule of a climate profile for a certain weekday.

### `homematicip_local.put_paramset`

__Disclaimer: To much writing to the device MASTER paramset could kill your device's storage.__

Call to `putParamset` on the XML-RPC interface.

### `homematicip_local.put_link_paramset`

__Disclaimer: To much writing to the device MASTER paramset could kill your device's storage.__

Call to `putParamset` for direct connections on the XML-RPC interface.

### `homematicip_local.remove_central_links`

Removes a central link from the backend. This is required to disable enable button-press events.

### `homematicip_local.set_cover_combined_position`

Move a blind to a specific position and tilt position.

### `homematicip_local.set_device_value`

__Disclaimer: To much writing to the device MASTER paramset could kill your device's storage.__

Set a device parameter via the XML-RPC interface. Preferred when using the UI. Works with device selection.

### `homematicip_local.set_install_mode`

Turn on the install mode on the provided Interface to pair new devices.

### `homematicip_local.set_schedule_profile`

__Disclaimer: To much writing to the device could kill your device's storage.__

Sends the schedule of a climate profile to a device.

Relevant rules for modifying a schedule:
- All rules of `homematicip_local.set_schedule_profile_weekday` are relevant
- The required data structure can be retrieved with `homematicip_local.get_schedule_profile`

### `homematicip_local.set_schedule_profile_weekday`

__Disclaimer: To much writing to the device could kill your device's storage.__

Sends the schedule of a climate profile for a certain weekday to a device.
See the [sample](#sample-for-set_schedule_profile_weekday) below

Remarks:
- Not all devices support schedules. This is currently only supported by this integration for HmIP devices.
- Not all devices support six profiles.
- There is currently no matching UI component or entity component in HA.

Relevant rules for modifying a schedule:
- The content of `weekday_data` looks identically to the [sample](#sample-for-set_schedule_profile_weekday) below. Only the values should be changed.
- All slots (1-13) must be included.
- The temperature must be in the defined temperature range of the device.
- The slot is defined by the end time. The start time is the end time of the previous slot or 0.
- The time of a slot must be equal or higher then the previous slot, and must be in a range between 0 and 1440. If you have retrieved a schedule with `homematicip_local.get_schedule_profile_weekday` this might not be the case, but must be fixed before sending.

### `homematicip_local.set_schedule_simple_profile`

__Disclaimer: To much writing to the device could kill your device's storage.__

Sends the schedule of a climate profile to a device.
This is a simplified version of `homematicip_local.set_schedule_profile` 

### `homematicip_local.set_schedule_simple_profile_weekday`

__Disclaimer: To much writing to the device could kill your device's storage.__

Sends the schedule of a climate profile for a certain weekday to a device.
This is a simplified version of `homematicip_local.set_schedule_profile_weekday` 

### `homematicip_local.set_variable_value`

Set the value of a variable on your HomeMatic hub.

Value lists accept the 0-based list position or the value as input.

For booleans the following values can be used:

- 'true', 'on', '1', 1 -> True
- 'false', 'off', '0', 0 -> False

### `homematicip_local.turn_on_siren`

Turn siren on. Siren can be disabled by siren.turn_off. Useful helpers for siren can be found [here](https://github.com/danielperna84/hahomematic/blob/devel/docs/input_select_helper.md#siren).

### `homematicip_local.light_set_on_time`

Set on time for a light entity. Must be followed by a `light.turn_on`.
Use 0 to reset the on time.

### `homematicip_local.switch_set_on_time`

Set on time for a switch entity. Must be followed by a `switch.turn_on`.
Use 0 to reset the on time.

### `homeassistant.update_entity`

Update the value of an entity (only required for edge cases). An entity can be updated at most every 60 seconds.

This action is not needed to update entities in general, because 99,9% of the entities and values are getting updated by this integration automatically. But with this action, you can manually update the value of an entity - **if you really need this in special cases**, e.g. if the value is not updated or not available, because of design gaps or bugs in the backend or device firmware (e.g. rssi-values of some HM-devices).

Attention: This action gets the value for the entity via a 'getValue' from the backend, so the values are updated afterwards from the backend cache (for battery devices) or directly from the device (for non-battery devices). So even with using this action, the values are still not guaranteed for the battery devices and there is a negative impact on the duty cycle of the backend for non-battery devices.

### `homeassistant.update_device_firmware_data`

Update the firmware data for all devices. For more information see [updating the firmware](https://github.com/danielperna84/custom_homematic#updating-the-firmware)

## Events

Events fired by this integration that can be consumed by users.

### `homematic.keypress`

This event type is used when a key is pressed on a device,
and can be used with device triggers or event entities in automation, so manual event listening is not necessary.

In this context, the following must also be observed: [Events for Homematic(IP) devices](https://github.com/SukramJ/custom_homematic#events-for-homematicip-devices)

The `PRESS*` parameters are evaluated for this event type in the backend.

### `homematic.device_availability`

This event type is used when a device is no longer available or is available again,
and can be used with the blueprint [Support for persistent notifications for unavailable devices](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local_persistent_notification.yaml).

The `UNREACH` parameter is evaluated for this event type in the backend.

### `homematic.device_error`

This event type is used when a device is in an error state.
A sample usage is shown in the blueprint [Show device errors](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local_show_device_error.yaml).

The `ERROR*` parameters are evaluated for this event type in the backend.

## Additional information

### How can a device be removed from Home Assistant

Go to the devices page of the integration and select a device. Click the three-dot menu at the button and press Delete.
This will only delete the device from Home Assistant and not from the CCU.

### What is the meaning of `XmlRPC-Server received no events`?

This integration does not fetch new updates from the backend, it **receives** state changes and new values for devices from the backend by the XmlRPC server.

Therefore the integration additionally checks for the CCU, if this mechanism works:

Regardless of regular device updates, HA checks the availability of the CCU with a `PING` every **15 seconds**, and expects a `PONG` event as a response on the XMLRPC server.
This persistent notification is only displayed in HA if the received PONG events and the device updates are missing for **10 minutes**, but it also disappears again as soon as events are received again.

So the message means there is a problem in the communication from the backend to HA that was **identified** by the integration but not **caused**.

### What is the meaning of `Ping/Pong Mismatch on Interface`?

Only relevant for CCU.

As mentioned above, we send a PING event every 15s to check the connection and expect a corresponding PONG event from the backend.

If everything is OK the number of send PINGs matches the number of received PONGs.

If we receive less PONGs that means that there is another HA Instance with the same instance name, that has been started after this instance, that receives all events, which also includes value update of devices.
Also a communication or CCU problem could be the cause for this.

If we receive more PONGs that means that there is another HA Instance with the same instance name, that has been started before this instance, so this instance also receives events from the other instance.

Solution:
Check if there are multiple instances of this integration running with the same instance name, and re-add the integration on one HA instance with a different instance name.

### Noteworthy about entity states

The integration fetches the states of all devices on initially startup and on reconnect from the backend (CCU/Homegear).
Afterwards, the state updates will be sent by the CCU as events to HA. We don't fetch states, except for system variables, after initial startup.

After a restart of the backend (esp. CCU), the backend has initially no state information about its devices. Some devices are actively polled for updates, but many devices, esp. battery driven devices, cannot be polled, so the backend needs to wait for periodic update send by the device.
This could take seconds, minutes and in rare cases hours.

That's why the last state of an entity will be recovered after a HA restart.
If you want to know how assured the displayed value is, there is an attribute `value_state` at each entity with the following values:

- `valid` the value was either loaded from the CCU or received via an event
- `not valid` there is no value. The state of the entity is `unknown`.
- `restored` the value has been restored from the last saved state after an HA restart
- `uncertain` the value could not be updated from the CCU after restarting the CCU, and no events were received either.

If you want to be sure that the state of the entity is as consistent as possible, you should also check the `value_state` attribute for `valid`.

### Sending state changes to backend

We try to avoid backend calls if value/state doesn't change:

- If an entity (e.g. `switch`) has only **one** parameter that represents its state, then a call to the backend will be made,
  if the parameter value sent is not identical to the current state.
- If an entity (e.g. `cover`, `climate`, `light`) has **multiple** parameters that represent its state, then a call to the backend will be made,
  if one of these parameter values sent is not identical to its current state.
- Not covered by this approach:
  - platforms: lock and siren.
  - actions: `stop_cover`, `stop_cover_tilt`, `enable_away_mode_*`, `disable_away_mode`, `set_on_time_value`
  - system variables

### Rename of device/channel in CCU not reflected in Home Assistant

Option 1: Just rename entity_id and name in HA

Option 2: Reload the Integration or restart HA, that will reload the names from CCU . This will show the the new entity name, if not changed manually in HA. The entity_id will not change.

Option 3: Delete the device in HA (device details). This deletes the device from all caches, and from entity/device_registry. A reload on the integration, or a restart of HA will recreate the device and entities. The new name will be reflected also in the entity_id.

Option 4: Delete and reinstall the Integration. That will recreate all devices and entities with new names (Should only be used on freshly installs systems)

### How rooms of the CCU are assigned to areas in HA

It is possible to assign multiple rooms to a channel in the CCU, but HA only allows one area per device.
Areas are assigned in HA when a single room is assigned to a Homematic device or multiple channels are only assigned to the same room.
If a device's channels are assigned to multiple rooms or nothing is set, the area in HA remains empty

### Unignore device parameters

Not all parameters of a HomeMatic or HomematicIP device are created as entity. These parameters are filtered out to provide a better user experience for the majority of the users. If you need more parameters as entities have a look at [this](https://github.com/danielperna84/hahomematic/blob/devel/docs/unignore.md) description. Starting with version 1.65.0 this can be configured in the reconfiguration flow under advanced options. You use this at your own risk!!!

BUT remember: Some parameters are already created as entities, but are **[deactivated](https://github.com/danielperna84/custom_homematic#deactivated-entities)**.

### Devices with buttons

Devices with buttons (e.g. HM-Sen-MDIR-WM55 and other remote controls) may not be fully visible in the UI. This is intended, as buttons don't have a persistent state. An example: The HM-Sen-MDIR-WM55 motion detector will expose entities for motion detection and brightness (among other entities), but none for the two internal buttons. To use these buttons within automations, you can select the device as the trigger-type, and then select the specific trigger (_Button "1" pressed_ etc.).

### Fixing RSSI values

See this [explanation](https://github.com/danielperna84/hahomematic/blob/devel/docs/rssi_fix.md) how the RSSI values are fixed.

### Changing the default platform for some parameters

#### HmIP-eTRv\* / LEVEL, number to sensor entity

The `LEVEL` parameter of the HmIP-eTRV can be written, i.e. this parameter is created as a **number** entity and the valve can be moved to any position.
However, this **manual position** is reversed shortly thereafter by the device's internal control logic, causing the valve to return to its original position almost immediately. Since the internal control logic of the device can neither be bypassed nor deactivated, manual control of the valve opening degree is not useful. The `LEVEL` parameter is therefore created as a sensor, and thus also supports long-term statistics.

If you need the `LEVEL` parameter as number entity, then this can be done by using the [unignore](https://github.com/danielperna84/custom_homematic#unignore-device-parameters) feature by adding LEVEL to the file.

### Pressing buttons via automation

It is possible to press buttons of devices from Home Assistant. A common usecase is to press a virtual button of your CCU, which on the CCU is configured to perform a specific action. For this you can use the `homematicip_local.set_device_value` action. In YAML-mode the action call to press button `3` on a CCU could look like this:

```yaml
action: homematicip_local.set_device_value
data:
  device_id: abcdefg...
  parameter: PRESS_SHORT
  value: "true"
  value_type: boolean
  channel: 3
```

### Events for Homematic(IP) devices

To receive button-press events for Homematic(IP) devices like WRC2 / WRC6 (wall switch) or SPDR (passage sensor) or the KRC4 (key ring remote control) or HM-PBI-4-FM (radio button interface) you have to several options:

#### Option A:
Use the action [create_central_links](https://github.com/danielperna84/custom_homematic?tab=readme-ov-file#homeassistantcreate_central_links).
A one time execution is required to activate the events.
To deactivate the events the action [remove_central_links](https://github.com/danielperna84/custom_homematic?tab=readme-ov-file#homeassistantremove_central_links) can be used.

#### Option B:
With RaspberryMatic no program is needed for buttons. Events can directly activated/deactivated within ->Settings->Devices. Click the "+" of e.g. a remote control then click directly the "button-channel". Press "activate". There is no direct feedback but a action message should appear.

#### Option C:
Create a program in the CCU:

1. In the menu of your CCU's admin panel go to `Programs and connections` > `Programs & CCU connection`
2. Go to `New` in the footer menu
3. Click the plus icon below `Condition: If...` and press the button `Device selection`
4. Select one of the device's channels you need (1-2 / 1-6 for WRC2 / WRC6 and 2-3 for SPDR)
5. Select short or long key press
6. Repeat Steps 3 - 5 to add all needed channels (the logic AND / OR is irrelevant)
7. Save the program with the `OK` button
8. Trigger the program by pressing the button as configured in step 5. Your device might indicate success via a green LED or similar. When you select the device in `Status and control` > `Devices` on the CCU, the `Last Modified` field should no longer be empty
9. When your channels are working now, you can set the program to "inactive". Don't delete the program!

Hint: To deactivate the event for one channel, remove that channel from the program


## Updating a device firmware

Homematic offers the possibility to update the device firmware. To do this, the firmware file must be uploaded in the CCU. The firmware is then transferred to the devices, which can take several hours or days per device. Update can then be clicked in the CCU and the device will update and reboot.

To simplify this process, this integration offers update entities per device.

Initially, the firmware file must be uploaded via the CCU. A query of available firmware information from eq3 does not take place. All firmware information used is provided by the local CCU.

Since the CCU does not send any events for firmware updates, the current status of firmware updates is requested via regular queries. Since device updates are usually very rare and the transmission takes a long time, the query is only made every **6 hours**.

If devices whose firmware is currently being transferred were discovered via the update, their statuses are then queried **every hour**.

As soon as the firmware has been successfully transferred to the device, it can be updated on the device by clicking on `install`. This information can be delayed up to **1 hour** in HA.

Depending on whether an update command can be transmitted immediately or with a delay, either the updated firmware version is displayed after a short delay, or `in process`/`installing` is displayed again because a command transmission is being waited for. This state is now updated every **5 minutes** until the installation is finished.

If shorter update cycles are desired, these can be triggered by the action `homeassistant.update_device_firmware_data`, but this might have a negative impact on you CCU!

## Frequently asked questions

Q: I can see an entity, but it is unavailable.<br>
A: Possible reason: the entity is deactivated. Go into the entity configuration and activate the entity.

Q: I'm using a button on a remote control as a trigger in an automation, but the automation doesn't fire after the button is pressed.<br>
A: See [Events for Homematic(IP) devices](#events-for-homematicip-devices)

Q: My device is not listed under [Events for Homematic(IP) devices](#events-for-homematicip-devices)<br>
A: I doesn't matter. These are just examples. If you can press it, it is a button and events are emitted.

Q: I have a problem with the integration. What can i do?<br>
A: Before creating an issue, you should review the HA log files for `error` or `warning` entries related to this integration (`homematicip_local`, `hahomematic`) and read the corresponding messages. You can find further information about some messages in this document.

## Examples in YAML


### Sample for set_variable_value
Set boolean variable to true:

```yaml
---
action: homematicip_local.set_variable_value
data:
  entity_id: sesnsor.ccu2
  name: Variablename
  value: "3"
```

### Sample for set_device_value
Manually turn on a switch actor:

```yaml
---
action: homematicip_local.set_device_value
data:
  device_id: abcdefg...
  channel: 1
  parameter: STATE
  value: "true"
  value_type: boolean
```

### Sample 2 for set_device_value
Manually set temperature on thermostat:

```yaml
---
action: homematicip_local.set_device_value
data:
  device_id: abcdefg...
  channel: 4
  parameter: SET_TEMPERATURE
  value: "23.0"
  value_type: double
```

### Sample for set_schedule_profile_weekday
Send a climate profile for a certain weekday to the device:

```yaml
---
action: homematicip_local.set_schedule_profile_weekday
target:
  entity_id: climate.heizkorperthermostat_db
data:
  profile: P3
  weekday: MONDAY
  weekday_data:
    "1":
      ScheduleSlotType.ENDTIME: "05:00"
      ScheduleSlotType.TEMPERATURE: 16
    "2":
      ScheduleSlotType.ENDTIME: "06:00"
      ScheduleSlotType.TEMPERATURE: 17
    "3":
      ScheduleSlotType.ENDTIME: "09:00"
      ScheduleSlotType.TEMPERATURE: 16
    "4":
      ScheduleSlotType.ENDTIME: "15:00"
      ScheduleSlotType.TEMPERATURE: 17
    "5":
      ScheduleSlotType.ENDTIME: "19:00"
      ScheduleSlotType.TEMPERATURE: 16
    "6":
      ScheduleSlotType.ENDTIME: "22:00"
      ScheduleSlotType.TEMPERATURE: 22
    "7":
      ScheduleSlotType.ENDTIME: "24:00"
      ScheduleSlotType.TEMPERATURE: 16
    "8":
      ScheduleSlotType.ENDTIME: "24:00"
      ScheduleSlotType.TEMPERATURE: 16
    "9":
      ScheduleSlotType.ENDTIME: "24:00"
      ScheduleSlotType.TEMPERATURE: 16
    "10":
      ScheduleSlotType.ENDTIME: "24:00"
      ScheduleSlotType.TEMPERATURE: 16
    "11":
      ScheduleSlotType.ENDTIME: "24:00"
      ScheduleSlotType.TEMPERATURE: 16
    "12":
      ScheduleSlotType.ENDTIME: "24:00"
      ScheduleSlotType.TEMPERATURE: 16
    "13":
      ScheduleSlotType.ENDTIME: "24:00"
      ScheduleSlotType.TEMPERATURE: 16
```

### Sample for set_schedule_simple_profile
Send a simple climate profile to the device:

```yaml
---
action: homematicip_local.set_schedule_simple_profile
target:
  entity_id: climate.heizkorperthermostat_db
data:
  base_temperature: 4.5
  profile: P1
  simple_profile_data:
    MONDAY:
      - TEMPERATURE: 17
        STARTTIME: "05:00"
        ENDTIME: "06:00"
      - TEMPERATURE: 22
        STARTTIME: "19:00"
        ENDTIME: "22:00"
      - TEMPERATURE: 17
        STARTTIME: "09:00"
        ENDTIME: "15:00"
    TUESDAY:
      - TEMPERATURE: 17
        STARTTIME: "05:00"
        ENDTIME: "06:00"
      - TEMPERATURE: 22
        STARTTIME: "19:00"
        ENDTIME: "22:00"
      - TEMPERATURE: 17
        STARTTIME: "09:00"
        ENDTIME: "15:00"
```

### Sample for set_schedule_profile_weekday
Send a climate profile for a certain weekday to the device:

```yaml
---
action: homematicip_local.set_schedule_simple_profile_weekday
target:
  entity_id: climate.heizkorperthermostat_db
data:
  profile: P3
  weekday: MONDAY
  base_temperature: 16
  simple_weekday_list:
    - TEMPERATURE: 17
      STARTTIME: "05:00"
      ENDTIME: "06:00"
    - TEMPERATURE: 22
      STARTTIME: "19:00"
      ENDTIME: "22:00"
    - TEMPERATURE: 17
      STARTTIME: "09:00"
      ENDTIME: "15:00"
```

### Sample for put_paramset
Set the week program of a wall thermostat:

```yaml
---
action: homematicip_local.put_paramset
data:
  device_id: abcdefg...
  paramset_key: MASTER
  paramset:
    WEEK_PROGRAM_POINTER: 1
```

### Sample 2 for put_paramset
Set the week program of a wall thermostat with explicit `rx_mode` (BidCos-RF only):

```yaml
---
action: homematicip_local.put_paramset
data:
  device_id: abcdefg...
  paramset_key: MASTER
  rx_mode: WAKEUP
  paramset:
    WEEK_PROGRAM_POINTER: 1
```

BidCos-RF devices have an optional parameter for put_paramset which defines the way the configuration data is sent to the device.

`rx_mode` `BURST`, which is the default value, will wake up every device when submitting the configuration data and hence makes all devices use some battery. It is instant, i.e. the data is sent almost immediately.

`rx_mode` `WAKEUP` will send the configuration data only after a device submitted updated values to CCU, which usually happens every 3 minutes. It will not wake up every device and thus saves devices battery.

## Available Blueprints

The following blueprints can be used to simplify the usage of HomeMatic and HomematicIP device:

- [Support for 2-button Remotes](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local-actions-for-2-button.yaml): Support for two button remote like HmIP-WRC2.
- [Support for 4-button Key Ring Remote Control](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local-actions-for-key_ring_remote_control.yaml): Support for four button remote like HmIP-KRCA.
- [Support for 6-button Remotes](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local-actions-for-6-button.yaml): Support for six button remote like HmIP-WRC6.
- [Support for 8-button Remotes](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local-actions-for-8-button.yaml): Support for eight button remote like HmIP-RC8.
- [Support for persistent notifications for unavailable devices](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local_persistent_notification.yaml): Enable persistent notifications about unavailable devices.
- [Reactivate device by type](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local_reactivate_device_by_type.yaml). Reactivate unavailable devices by device type.
- [Reactivate every device](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local_reactivate_device_full.yaml). Reactivate all unavailable devices. NOT recommended. Usage of `by device type` or `single device` should be preferred.
- [Reactivate single device](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local_reactivate_single_device.yaml) Reactivate a single unavailable device.
- [Show device errors](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/automation/homematicip_local_show_device_error.yaml) Show all error eventy emitted by a device. This is an unfiltered blueprint. More filters should be added to the trigger.

Feel free to contribute:

- [Community blueprints](https://github.com/danielperna84/custom_homematic/blob/devel/blueprints/community)

These blueprints on my own system and share them with you, but I don't want to investigate in blueprints for devices, that I don't own!
Feel free to copy, improve or enhance these blueprints and adopt them to other devices, and if you like create a PR with a new blueprint.

Just copy these files to "your ha-config_dir"/blueprints/automation
