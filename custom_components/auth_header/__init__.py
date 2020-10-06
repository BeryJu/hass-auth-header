import logging
from ipaddress import ip_address
from typing import OrderedDict

import voluptuous as vol
from homeassistant import data_entry_flow
from homeassistant.auth import providers
from homeassistant.components.auth import _create_auth_code_store, indieauth
from homeassistant.components.auth.login_flow import (LoginFlowIndexView,
                                                      LoginFlowResourceView,
                                                      _prepare_result_json)
from homeassistant.components.http.ban import (log_invalid_auth,
                                               process_success_login)
from homeassistant.components.http.data_validator import RequestDataValidator
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import HTTP_BAD_REQUEST, HTTP_NOT_FOUND
from homeassistant.core import HomeAssistant

from . import headers

_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = vol.Schema({"auth_header": vol.Schema({})}, extra=vol.ALLOW_EXTRA)


async def async_setup(hass: HomeAssistant, config):
    """Register custom view which includes request in context"""
    # Because we start after auth, we have access to store_result
    store_result = hass.data["auth"]
    # Remove old LoginFlowResourceView
    for route in hass.http.app.router._resources:
        if route.canonical == "/auth/login_flow":
            _LOGGER.debug("Removed original login_flow route")
            hass.http.app.router._resources.remove(route)
    _LOGGER.debug("Add new login_flow route")
    hass.http.register_view(
        RequestLoginFlowResourceView(hass.auth.login_flow, store_result)
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Inject Auth-Header provider."""
    hass.auth._providers = OrderedDict()
    provider = headers.HeaderAuthProvider(
        hass,
        hass.auth._store,
        {
            "username_header": entry.data.get(
                "username_header", "X-Forwarded-Preferred-Username"
            )
        },
    )
    hass.auth._providers[(provider.type, provider.id)] = provider
    _LOGGER.debug("Injected auth_header provider")
    return True


class RequestLoginFlowResourceView(LoginFlowIndexView):
    @RequestDataValidator(
        vol.Schema(
            {
                vol.Required("client_id"): str,
                vol.Required("handler"): vol.Any(str, list),
                vol.Required("redirect_uri"): str,
                vol.Optional("type", default="authorize"): str,
            }
        )
    )
    @log_invalid_auth
    async def post(self, request, data):
        """Create a new login flow."""
        if not await indieauth.verify_redirect_uri(
            request.app["hass"], data["client_id"], data["redirect_uri"]
        ):
            return self.json_message(
                "invalid client id or redirect uri", HTTP_BAD_REQUEST
            )

        if isinstance(data["handler"], list):
            handler = tuple(data["handler"])
        else:
            handler = data["handler"]

        try:
            result = await self._flow_mgr.async_init(
                handler,
                context={
                    "request": request,
                    "ip_address": ip_address(request.remote),
                    "credential_only": data.get("type") == "link_user",
                },
            )
        except data_entry_flow.UnknownHandler:
            return self.json_message("Invalid handler specified", HTTP_NOT_FOUND)
        except data_entry_flow.UnknownStep:
            return self.json_message("Handler does not support init", HTTP_BAD_REQUEST)

        if result["type"] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY:
            await process_success_login(request)
            result.pop("data")
            result["result"] = self._store_result(data["client_id"], result["result"])
            return self.json(result)

        return self.json(_prepare_result_json(result))
