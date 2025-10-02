"""Config flow for Tuya BLE integration."""

from __future__ import annotations

import logging
import pycountry
from typing import Any

import voluptuous as vol
from tuya_iot import AuthType

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    OptionsFlowWithConfigEntry,
)
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.const import (
    CONF_ADDRESS,
    CONF_COUNTRY_CODE,
    CONF_PASSWORD,
    CONF_USERNAME,
)
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowHandler, FlowResult

from .tuya_ble import TuyaBLEDeviceCredentials
from .tuya_ble.const import SERVICE_UUID, SERVICE_UUID_TEMP, MANUFACTURER_DATA_ID
import hashlib
from Crypto.Cipher import AES

from .const import (
    TUYA_COUNTRIES,
    TUYA_SMART_APP,
    SMARTLIFE_APP,
    TUYA_RESPONSE_SUCCESS,
    TUYA_RESPONSE_CODE,
    TUYA_RESPONSE_MSG,
    CONF_ACCESS_ID,
    CONF_ACCESS_SECRET,
    CONF_APP_TYPE,
    CONF_AUTH_TYPE,
    CONF_ENDPOINT,
    DOMAIN,
)
from .devices import TuyaBLEData, get_device_readable_name
from .cloud import HASSTuyaBLEDeviceManager

_LOGGER = logging.getLogger(__name__)


def _extract_uuid_from_advertisement(discovery_info: BluetoothServiceInfoBleak) -> str | None:
    """Extract UUID from BLE advertisement data for fallback matching."""
    try:
        _LOGGER.debug(
            "Attempting to extract UUID from %s, service_data keys: %s, manufacturer_data keys: %s",
            discovery_info.address,
            list(discovery_info.service_data.keys()) if discovery_info.service_data else None,
            list(discovery_info.manufacturer_data.keys()) if discovery_info.manufacturer_data else None,
        )

        # Get product_id from service data - try both UUIDs
        service_data = discovery_info.service_data.get(SERVICE_UUID)
        if not service_data or len(service_data) < 2:
            service_data = discovery_info.service_data.get(SERVICE_UUID_TEMP)
        if not service_data or len(service_data) < 2:
            _LOGGER.debug("No valid service data found for %s", discovery_info.address)
            return None

        # Service data format: first byte is flags, then product_id
        # Type 0x00 = product_id directly, 0x41 = product_id with length prefix
        if service_data[0] == 0x00:
            raw_product_id = service_data[1:]
        elif service_data[0] == 0x41:
            # Format: 0x41 0x00 0x00 length product_id_bytes...
            # Skip first 4 bytes (0x41 0x00 0x00 length)
            if len(service_data) < 5:
                _LOGGER.debug("Service data too short for type 0x41")
                return None
            raw_product_id = service_data[4:]
        else:
            _LOGGER.debug("Service data type is %s, not 0x00 or 0x41 (product_id)", service_data[0])
            return None
        product_id_str = raw_product_id.decode('utf-8')
        _LOGGER.debug("Extracted product_id: %s", product_id_str)

        # Get encrypted UUID from manufacturer data
        # Format: [6 bytes header][16 bytes encrypted UUID]
        manufacturer_data = discovery_info.manufacturer_data.get(MANUFACTURER_DATA_ID)
        if not manufacturer_data or len(manufacturer_data) <= 6:
            _LOGGER.debug("No valid manufacturer data found for %s (length: %s)", discovery_info.address, len(manufacturer_data) if manufacturer_data else 0)
            return None

        raw_uuid = manufacturer_data[6:]  # Extract encrypted UUID starting at byte 6
        _LOGGER.debug("raw_uuid: %s", raw_uuid.hex())

        # UUID must be 16 bytes for AES decryption
        if len(raw_uuid) != 16:
            _LOGGER.debug("UUID data is not 16 bytes (got %d bytes) for %s", len(raw_uuid), discovery_info.address)
            return None

        # Decrypt UUID using product_id as key (MD5 hash used as both key and IV)
        key = hashlib.md5(raw_product_id).digest()
        _LOGGER.debug("MD5 key: %s", key.hex())
        cipher = AES.new(key, AES.MODE_CBC, key)
        decrypted_uuid = cipher.decrypt(raw_uuid)
        _LOGGER.debug("Decrypted bytes: %s", decrypted_uuid.hex())
        uuid = decrypted_uuid.decode("utf-8").rstrip('\x00')

        _LOGGER.debug("Successfully extracted UUID: %s for device %s", uuid, discovery_info.address)
        return uuid
    except Exception as e:
        _LOGGER.warning("Failed to extract UUID from advertisement for %s: %s", discovery_info.address, e, exc_info=True)
        return None


async def _try_login(
    manager: HASSTuyaBLEDeviceManager,
    user_input: dict[str, Any],
    errors: dict[str, str],
    placeholders: dict[str, Any],
) -> dict[str, Any] | None:
    response: dict[Any, Any] | None
    data: dict[str, Any]

    country = [
        country
        for country in TUYA_COUNTRIES
        if country.name == user_input[CONF_COUNTRY_CODE]
    ][0]

    data = {
        CONF_ENDPOINT: country.endpoint,
        CONF_AUTH_TYPE: AuthType.CUSTOM,
        CONF_ACCESS_ID: user_input[CONF_ACCESS_ID],
        CONF_ACCESS_SECRET: user_input[CONF_ACCESS_SECRET],
        CONF_USERNAME: user_input[CONF_USERNAME],
        CONF_PASSWORD: user_input[CONF_PASSWORD],
        CONF_COUNTRY_CODE: country.country_code,
    }

    for app_type in (TUYA_SMART_APP, SMARTLIFE_APP, ""):
        data[CONF_APP_TYPE] = app_type
        if app_type == "":
            data[CONF_AUTH_TYPE] = AuthType.CUSTOM
        else:
            data[CONF_AUTH_TYPE] = AuthType.SMART_HOME

        response = await manager._login(data, True)

        if response.get(TUYA_RESPONSE_SUCCESS, False):
            return data

    errors["base"] = "login_error"
    if response:
        placeholders.update(
            {
                TUYA_RESPONSE_CODE: response.get(TUYA_RESPONSE_CODE),
                TUYA_RESPONSE_MSG: response.get(TUYA_RESPONSE_MSG),
            }
        )

    return None


def _show_login_form(
    flow: FlowHandler,
    user_input: dict[str, Any],
    errors: dict[str, str],
    placeholders: dict[str, Any],
) -> FlowResult:
    """Shows the Tuya IOT platform login form."""
    if user_input is not None and user_input.get(CONF_COUNTRY_CODE) is not None:
        for country in TUYA_COUNTRIES:
            if country.country_code == user_input[CONF_COUNTRY_CODE]:
                user_input[CONF_COUNTRY_CODE] = country.name
                break

    def_country_name: str | None = None
    try:
        def_country = pycountry.countries.get(alpha_2=flow.hass.config.country)
        if def_country:
            def_country_name = def_country.name
    except:
        pass

    return flow.async_show_form(
        step_id="login",
        data_schema=vol.Schema(
            {
                vol.Required(
                    CONF_COUNTRY_CODE,
                    default=user_input.get(CONF_COUNTRY_CODE, def_country_name),
                ): vol.In(
                    # We don't pass a dict {code:name} because country codes can be duplicate.
                    [country.name for country in TUYA_COUNTRIES]
                ),
                vol.Required(
                    CONF_ACCESS_ID, default=user_input.get(CONF_ACCESS_ID, "")
                ): str,
                vol.Required(
                    CONF_ACCESS_SECRET,
                    default=user_input.get(CONF_ACCESS_SECRET, ""),
                ): str,
                vol.Required(
                    CONF_USERNAME, default=user_input.get(CONF_USERNAME, "")
                ): str,
                vol.Required(
                    CONF_PASSWORD, default=user_input.get(CONF_PASSWORD, "")
                ): str,
            }
        ),
        errors=errors,
        description_placeholders=placeholders,
    )


class TuyaBLEOptionsFlow(OptionsFlowWithConfigEntry):
    """Handle a Tuya BLE options flow."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        super().__init__(config_entry)

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        return await self.async_step_login(user_input)

    async def async_step_login(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the Tuya IOT platform login step."""
        errors: dict[str, str] = {}
        placeholders: dict[str, Any] = {}
        credentials: TuyaBLEDeviceCredentials | None = None
        address: str | None = self.config_entry.data.get(CONF_ADDRESS)

        if user_input is not None:
            entry: TuyaBLEData | None = None
            domain_data = self.hass.data.get(DOMAIN)
            if domain_data:
                entry = domain_data.get(self.config_entry.entry_id)
            if entry:
                login_data = await _try_login(
                    entry.manager,
                    user_input,
                    errors,
                    placeholders,
                )
                if login_data:
                    credentials = await entry.manager.get_device_credentials(
                        address, True, True
                    )
                    if credentials:
                        return self.async_create_entry(
                            title=self.config_entry.title,
                            data=entry.manager.data,
                        )

                    errors["base"] = "device_not_registered"

        if user_input is None:
            user_input = {}
            user_input.update(self.config_entry.options)

        return _show_login_form(self, user_input, errors, placeholders)


class TuyaBLEConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Tuya BLE."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        super().__init__()
        self._discovery_info: BluetoothServiceInfoBleak | None = None
        self._discovered_devices: dict[str, BluetoothServiceInfoBleak] = {}
        self._data: dict[str, Any] = {}
        self._manager: HASSTuyaBLEDeviceManager | None = None
        self._get_device_info_error = False

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> FlowResult:
        """Handle the bluetooth discovery step."""
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._discovery_info = discovery_info
        if self._manager is None:
            self._manager = HASSTuyaBLEDeviceManager(self.hass, self._data)
        await self._manager.build_cache()
        self.context["title_placeholders"] = {
            "name": await get_device_readable_name(
                discovery_info,
                self._manager,
            )
        }
        return await self.async_step_login()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the user step."""
        if self._manager is None:
            self._manager = HASSTuyaBLEDeviceManager(self.hass, self._data)
        await self._manager.build_cache()
        return await self.async_step_login()

    async def async_step_login(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the Tuya IOT platform login step."""
        data: dict[str, Any] | None = None
        errors: dict[str, str] = {}
        placeholders: dict[str, Any] = {}

        if user_input is not None:
            data = await _try_login(
                self._manager,
                user_input,
                errors,
                placeholders,
            )
            if data:
                self._data.update(data)
                return await self.async_step_device()

        if user_input is None:
            user_input = {}
            if self._discovery_info:
                await self._manager.get_device_credentials(
                    self._discovery_info.address,
                    False,
                    True,
                )
            if self._data is None or len(self._data) == 0:
                self._manager.get_login_from_cache()
            if self._data is not None and len(self._data) > 0:
                user_input.update(self._data)

        return _show_login_form(self, user_input, errors, placeholders)

    async def async_step_device(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the user step to pick discovered device."""
        errors: dict[str, str] = {}

        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            discovery_info = self._discovered_devices[address]
            local_name = await get_device_readable_name(discovery_info, self._manager)
            await self.async_set_unique_id(
                discovery_info.address, raise_on_progress=False
            )
            self._abort_if_unique_id_configured()
            _LOGGER.debug("Attempting to get credentials for MAC: %s", discovery_info.address)
            credentials = await self._manager.get_device_credentials(
                discovery_info.address, self._get_device_info_error, True
            )

            # If MAC matching fails, try UUID-based matching
            # This handles devices where BLE MAC != cloud factory MAC
            if credentials is None:
                _LOGGER.info("MAC %s not found in cloud, attempting UUID fallback", discovery_info.address)
                uuid = _extract_uuid_from_advertisement(discovery_info)
                if uuid:
                    _LOGGER.info(
                        "MAC %s not found in cloud, trying UUID fallback: %s",
                        discovery_info.address,
                        uuid,
                    )
                    credentials = await self._manager.get_device_credentials_by_uuid(
                        uuid, self._get_device_info_error, True
                    )
                    if credentials:
                        _LOGGER.info("Successfully matched device by UUID: %s", uuid)
                    else:
                        _LOGGER.warning("UUID %s also not found in cloud", uuid)
                else:
                    _LOGGER.warning("Failed to extract UUID from advertisement for %s", discovery_info.address)
            else:
                _LOGGER.debug("Found credentials by MAC: %s", discovery_info.address)

            self._data[CONF_ADDRESS] = discovery_info.address
            if credentials is None:
                self._get_device_info_error = True
                errors["base"] = "device_not_registered"
            else:
                return self.async_create_entry(
                    title=local_name,
                    data={CONF_ADDRESS: discovery_info.address},
                    options=self._data,
                )

        if discovery := self._discovery_info:
            self._discovered_devices[discovery.address] = discovery
        else:
            current_addresses = self._async_current_ids()
            for discovery in async_discovered_service_info(self.hass):
                if (
                    discovery.address in current_addresses
                    or discovery.address in self._discovered_devices
                    or discovery.service_data is None
                    or not SERVICE_UUID in discovery.service_data.keys()
                ):
                    continue
                self._discovered_devices[discovery.address] = discovery

        if not self._discovered_devices:
            return self.async_abort(reason="no_unconfigured_devices")

        def_address: str
        if user_input:
            def_address = user_input.get(CONF_ADDRESS)
        else:
            def_address = list(self._discovered_devices)[0]

        return self.async_show_form(
            step_id="device",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_ADDRESS,
                        default=def_address,
                    ): vol.In(
                        {
                            service_info.address: await get_device_readable_name(
                                service_info,
                                self._manager,
                            )
                            for service_info in self._discovered_devices.values()
                        }
                    ),
                },
            ),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> TuyaBLEOptionsFlow:
        """Get the options flow for this handler."""
        return TuyaBLEOptionsFlow(config_entry)
