"""The Tuya BLE integration."""

from __future__ import annotations

import logging

from dataclasses import dataclass
import json
from typing import Any, Iterable

from homeassistant.const import (
    CONF_ADDRESS,
    CONF_DEVICE_ID,
    CONF_COUNTRY_CODE,
    CONF_PASSWORD,
    CONF_USERNAME,
)

from homeassistant.core import HomeAssistant

from tuya_iot import (
    TuyaOpenAPI,
    AuthType,
)

from .tuya_ble import (
    AbstaractTuyaBLEDeviceManager,
    TuyaBLEDeviceCredentials,
)

from .const import (
    TUYA_DOMAIN,
    CONF_ACCESS_ID,
    CONF_ACCESS_SECRET,
    CONF_APP_TYPE,
    CONF_AUTH_TYPE,
    CONF_ENDPOINT,
    CONF_PRODUCT_MODEL,
    CONF_UUID,
    CONF_LOCAL_KEY,
    CONF_CATEGORY,
    CONF_PRODUCT_ID,
    CONF_DEVICE_NAME,
    CONF_PRODUCT_NAME,
    CONF_FUNCTIONS,
    CONF_STATUS_RANGE,
    DOMAIN,
    TUYA_API_DEVICES_URL,
    TUYA_API_FACTORY_INFO_URL,
    TUYA_API_DEVICE_SPECIFICATION,
    TUYA_FACTORY_INFO_MAC,
    TUYA_RESPONSE_RESULT,
    TUYA_RESPONSE_SUCCESS,
)

_LOGGER = logging.getLogger(__name__)


@dataclass
class TuyaCloudCacheItem:
    """A cache model for API keys/credentials"""

    api: TuyaOpenAPI | None
    login: dict[str, Any]
    credentials: dict[str, dict[str, Any]]


CONF_TUYA_LOGIN_KEYS = [
    CONF_ENDPOINT,
    CONF_ACCESS_ID,
    CONF_ACCESS_SECRET,
    CONF_AUTH_TYPE,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_COUNTRY_CODE,
    CONF_APP_TYPE,
]

CONF_TUYA_DEVICE_KEYS = [
    CONF_UUID,
    CONF_LOCAL_KEY,
    CONF_DEVICE_ID,
    CONF_CATEGORY,
    CONF_PRODUCT_ID,
    CONF_DEVICE_NAME,
    CONF_PRODUCT_NAME,
    CONF_PRODUCT_MODEL,
]

_cache: dict[str, TuyaCloudCacheItem] = {}


class HASSTuyaBLEDeviceManager(AbstaractTuyaBLEDeviceManager):
    """Cloud connected manager of the Tuya BLE devices credentials."""

    def __init__(self, hass: HomeAssistant, data: dict[str, Any]) -> None:
        assert hass is not None
        self._hass = hass
        self._data = data

    @staticmethod
    def _is_login_success(response: dict[Any, Any]) -> bool:
        return bool(response.get(TUYA_RESPONSE_SUCCESS, False))

    @staticmethod
    def _get_cache_key(data: dict[str, Any]) -> str:
        key_dict = {key: data.get(key) for key in CONF_TUYA_LOGIN_KEYS}
        return json.dumps(key_dict)

    @staticmethod
    def _has_login(data: dict[Any, Any]) -> bool:
        for key in CONF_TUYA_LOGIN_KEYS:
            if data.get(key) is None:
                return False
        return True

    @staticmethod
    def _has_credentials(data: dict[Any, Any]) -> bool:
        for key in CONF_TUYA_DEVICE_KEYS:
            if data.get(key) is None:
                return False
        return True

    async def _login(self, data: dict[str, Any], add_to_cache: bool) -> dict[Any, Any]:
        """Login into Tuya cloud using credentials from data dictionary."""
        global _cache

        if len(data) == 0:
            return {}

        api = TuyaOpenAPI(
            endpoint=data.get(CONF_ENDPOINT, ""),
            access_id=data.get(CONF_ACCESS_ID, ""),
            access_secret=data.get(CONF_ACCESS_SECRET, ""),
            auth_type=data.get(CONF_AUTH_TYPE, ""),
        )
        api.set_dev_channel("hass")

        response = await self._hass.async_add_executor_job(
            api.connect,
            data.get(CONF_USERNAME, ""),
            data.get(CONF_PASSWORD, ""),
            data.get(CONF_COUNTRY_CODE, ""),
            data.get(CONF_APP_TYPE, ""),
        )

        if self._is_login_success(response):
            _LOGGER.debug("Successful login for %s", data[CONF_USERNAME])
            if add_to_cache:
                auth_type = data[CONF_AUTH_TYPE]
                if isinstance(auth_type, AuthType):
                    data[CONF_AUTH_TYPE] = auth_type.value
                cache_key = self._get_cache_key(data)
                cache_item = _cache.get(cache_key)
                if cache_item:
                    cache_item.api = api
                    cache_item.login = data
                else:
                    _cache[cache_key] = TuyaCloudCacheItem(api, data, {})

        return response

    def _check_login(self) -> bool:
        cache_key = self._get_cache_key(self._data)
        return _cache.get(cache_key) is not None

    async def login(self, add_to_cache: bool = False) -> dict[Any, Any]:
        return await self._login(self._data, add_to_cache)

    async def _fill_cache_item(self, item: TuyaCloudCacheItem) -> None:
        devices_response = await self._hass.async_add_executor_job(
            item.api.get,
            TUYA_API_DEVICES_URL % (item.api.token_info.uid),
        )
        if devices_response.get(TUYA_RESPONSE_RESULT):
            devices = devices_response.get(TUYA_RESPONSE_RESULT)
            if isinstance(devices, Iterable):
                for device in devices:
                    fi_response = await self._hass.async_add_executor_job(
                        item.api.get,
                        TUYA_API_FACTORY_INFO_URL % (device.get("id")),
                    )

                    fi_response_result = fi_response.get(TUYA_RESPONSE_RESULT)
                    if fi_response_result and len(fi_response_result) > 0:
                        factory_info = fi_response_result[0]
                        if factory_info and (TUYA_FACTORY_INFO_MAC in factory_info):
                            mac = ":".join(
                                factory_info[TUYA_FACTORY_INFO_MAC][i : i + 2]
                                for i in range(0, 12, 2)
                            ).upper()
                            _LOGGER.debug(
                                "Device %s (%s, %s): Factory MAC from cloud = %s",
                                device.get("id"),
                                device.get("name"),
                                device.get("product_id"),
                                mac,
                            )
                            device_id = device.get("id")
                            uuid = device.get("uuid")
                            credentials_data = {
                                CONF_ADDRESS: mac,
                                CONF_UUID: uuid,
                                CONF_LOCAL_KEY: device.get("local_key"),
                                CONF_DEVICE_ID: device_id,
                                CONF_CATEGORY: device.get("category"),
                                CONF_PRODUCT_ID: device.get("product_id"),
                                CONF_DEVICE_NAME: device.get("name"),
                                CONF_PRODUCT_MODEL: device.get("model"),
                                CONF_PRODUCT_NAME: device.get("product_name"),
                            }
                            # Store credentials indexed by MAC (primary)
                            item.credentials[mac] = credentials_data
                            # Also store by UUID for fallback matching when BLE MAC != cloud MAC
                            if uuid:
                                item.credentials[f"uuid:{uuid}"] = credentials_data

                            spec_response = await self._hass.async_add_executor_job(
                                item.api.get,
                                TUYA_API_DEVICE_SPECIFICATION % device.get("id"),
                            )

                            spec_response_result = spec_response.get(
                                TUYA_RESPONSE_RESULT
                            )
                            if spec_response_result:
                                functions = spec_response_result.get("functions")
                                if functions:
                                    item.credentials[mac][CONF_FUNCTIONS] = functions
                                status = spec_response_result.get("status")
                                if status:
                                    item.credentials[mac][CONF_STATUS_RANGE] = status

                            spec_response = await self._hass.async_add_executor_job(
                                item.api.get,
                                TUYA_API_DEVICE_SPECIFICATION % device.get("id"),
                            )

                            spec_response_result = spec_response.get(
                                TUYA_RESPONSE_RESULT
                            )
                            if spec_response_result:
                                functions = spec_response_result.get("functions")
                                if functions:
                                    item.credentials[mac][CONF_FUNCTIONS] = functions
                                status = spec_response_result.get("status")
                                if status:
                                    item.credentials[mac][CONF_STATUS_RANGE] = status

    async def build_cache(self) -> None:
        global _cache
        data = {}
        tuya_config_entries = self._hass.config_entries.async_entries(TUYA_DOMAIN)
        for config_entry in tuya_config_entries:
            data.clear()
            data.update(config_entry.data)
            key = self._get_cache_key(data)
            item = _cache.get(key)
            if item is None or len(item.credentials) == 0:
                if self._is_login_success(await self._login(data, True)):
                    item = _cache.get(key)
                    if item and len(item.credentials) == 0:
                        await self._fill_cache_item(item)

        ble_config_entries = self._hass.config_entries.async_entries(DOMAIN)
        for config_entry in ble_config_entries:
            data.clear()
            data.update(config_entry.options)
            key = self._get_cache_key(data)
            item = _cache.get(key)
            if item is None or len(item.credentials) == 0:
                if self._is_login_success(await self._login(data, True)):
                    item = _cache.get(key)
                    if item and len(item.credentials) == 0:
                        await self._fill_cache_item(item)

    def get_login_from_cache(self) -> None:
        global _cache
        for cache_item in _cache.values():
            self._data.update(cache_item.login)
            break

    async def get_device_credentials_by_uuid(
        self,
        uuid: str,
        force_update: bool = False,
        save_data: bool = False,
    ) -> TuyaBLEDeviceCredentials | None:
        """Get credentials by UUID when MAC doesn't match."""
        global _cache
        result: TuyaBLEDeviceCredentials | None = None

        cache_key: str | None = None
        if self._has_login(self._data):
            cache_key = self._get_cache_key(self._data)
            item = _cache.get(cache_key)

            if item is None or force_update:
                if self._is_login_success(await self.login(True)):
                    item = _cache.get(cache_key)
                    if item:
                        await self._fill_cache_item(item)

            if item:
                credentials = item.credentials.get(f"uuid:{uuid}")
                if credentials:
                    result = TuyaBLEDeviceCredentials(
                        credentials.get(CONF_UUID, ""),
                        credentials.get(CONF_LOCAL_KEY, ""),
                        credentials.get(CONF_DEVICE_ID, ""),
                        credentials.get(CONF_CATEGORY, ""),
                        credentials.get(CONF_PRODUCT_ID, ""),
                        credentials.get(CONF_DEVICE_NAME, ""),
                        credentials.get(CONF_PRODUCT_MODEL, ""),
                        credentials.get(CONF_PRODUCT_NAME, ""),
                        credentials.get(CONF_FUNCTIONS, []),
                        credentials.get(CONF_STATUS_RANGE, []),
                    )
                    _LOGGER.debug("Retrieved by UUID %s: %s", uuid, result)
                    if save_data:
                        if item:
                            self._data.update(item.login)
                        self._data.update(credentials)

        return result

    async def get_device_credentials_by_product_id(
        self,
        product_id: str,
        ble_address: str,
        force_update: bool = False,
        save_data: bool = False,
    ) -> TuyaBLEDeviceCredentials | None:
        """Get credentials by product_id when MAC and UUID don't match.

        This is a last-resort fallback that returns the first unconfigured device
        with the given product_id. Only use when you have exactly one device of
        this product type that needs to be added.
        """
        global _cache
        result: TuyaBLEDeviceCredentials | None = None

        cache_key: str | None = None
        if self._has_login(self._data):
            cache_key = self._get_cache_key(self._data)
            item = _cache.get(cache_key)

            if item is None or force_update:
                if self._is_login_success(await self.login(True)):
                    item = _cache.get(cache_key)
                    if item:
                        await self._fill_cache_item(item)

            if item:
                # Get list of already configured device IDs
                from homeassistant.const import CONF_DEVICE_ID
                configured_device_ids = set()
                ble_entries = self._hass.config_entries.async_entries(DOMAIN)
                for entry in ble_entries:
                    device_id = entry.options.get(CONF_DEVICE_ID)
                    if device_id:
                        configured_device_ids.add(device_id)

                # Find all unconfigured devices with matching product_id
                matching_devices = []
                for cred_key, cred_data in item.credentials.items():
                    if cred_key.startswith("uuid:"):
                        continue  # Skip UUID-indexed entries
                    if cred_data.get(CONF_PRODUCT_ID) == product_id:
                        device_id = cred_data.get(CONF_DEVICE_ID)
                        if device_id not in configured_device_ids:
                            matching_devices.append(cred_data)

                _LOGGER.info("Found %d unconfigured devices with product_id %s", len(matching_devices), product_id)

                # If there's exactly one unconfigured match, use it
                if len(matching_devices) == 1:
                    credentials = matching_devices[0]
                    result = TuyaBLEDeviceCredentials(
                        credentials.get(CONF_UUID, ""),
                        credentials.get(CONF_LOCAL_KEY, ""),
                        credentials.get(CONF_DEVICE_ID, ""),
                        credentials.get(CONF_CATEGORY, ""),
                        credentials.get(CONF_PRODUCT_ID, ""),
                        credentials.get(CONF_DEVICE_NAME, ""),
                        credentials.get(CONF_PRODUCT_MODEL, ""),
                        credentials.get(CONF_PRODUCT_NAME, ""),
                        credentials.get(CONF_FUNCTIONS, []),
                        credentials.get(CONF_STATUS_RANGE, []),
                    )
                    _LOGGER.info("Using single unconfigured device match for product_id %s: %s", product_id, result)
                    if save_data:
                        if item:
                            self._data.update(item.login)
                        # Override the MAC address with the BLE MAC for this entry
                        cred_copy = credentials.copy()
                        cred_copy[CONF_ADDRESS] = ble_address
                        self._data.update(cred_copy)
                elif len(matching_devices) > 1:
                    _LOGGER.warning("Multiple unconfigured devices found with product_id %s, cannot auto-match. Add them one at a time.", product_id)
                else:
                    _LOGGER.warning("No unconfigured devices found with product_id %s", product_id)

        return result

    async def get_device_credentials(
        self,
        address: str,
        force_update: bool = False,
        save_data: bool = False,
    ) -> TuyaBLEDeviceCredentials | None:
        """Get credentials of the Tuya BLE device."""
        global _cache
        item: TuyaCloudCacheItem | None = None
        credentials: dict[str, any] | None = None
        result: TuyaBLEDeviceCredentials | None = None

        if not force_update and self._has_credentials(self._data):
            credentials = self._data.copy()
        else:
            cache_key: str | None = None
            if self._has_login(self._data):
                cache_key = self._get_cache_key(self._data)
            else:
                for key in _cache.keys():
                    if _cache[key].credentials.get(address) is not None:
                        cache_key = key
                        break
            if cache_key:
                item = _cache.get(cache_key)

            if item is None or force_update:
                if self._is_login_success(await self.login(True)):
                    item = _cache.get(cache_key)
                    if item:
                        await self._fill_cache_item(item)

            if item:
                credentials = item.credentials.get(address)

        if credentials:
            result = TuyaBLEDeviceCredentials(
                credentials.get(CONF_UUID, ""),
                credentials.get(CONF_LOCAL_KEY, ""),
                credentials.get(CONF_DEVICE_ID, ""),
                credentials.get(CONF_CATEGORY, ""),
                credentials.get(CONF_PRODUCT_ID, ""),
                credentials.get(CONF_DEVICE_NAME, ""),
                credentials.get(CONF_PRODUCT_MODEL, ""),
                credentials.get(CONF_PRODUCT_NAME, ""),
                credentials.get(CONF_FUNCTIONS, []),
                credentials.get(CONF_STATUS_RANGE, []),
            )
            _LOGGER.debug("Retrieved: %s", result)
            if save_data:
                if item:
                    self._data.update(item.login)
                self._data.update(credentials)

        return result

    @property
    def data(self) -> dict[str, Any]:
        return self._data
