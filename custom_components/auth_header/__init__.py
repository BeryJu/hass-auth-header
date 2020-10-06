import logging
from ipaddress import ip_address
from typing import OrderedDict

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant import data_entry_flow
from homeassistant.auth import providers
from homeassistant.components.auth import DOMAIN as AUTH_DOMAIN
from homeassistant.components.auth import indieauth
from homeassistant.components.auth.login_flow import (
    LoginFlowIndexView,
    _prepare_result_json,
)
from homeassistant.components.http.ban import log_invalid_auth, process_success_login
from homeassistant.components.http.data_validator import RequestDataValidator
from homeassistant.const import HTTP_BAD_REQUEST, HTTP_NOT_FOUND
from homeassistant.core import HomeAssistant

from . import headers

DOMAIN = "auth_header"
_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Optional(
                    "username_header", default="X-Forwarded-Preferred-Username"
                ): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config):
    """Register custom view which includes request in context"""
    # Because we start after auth, we have access to store_result
    store_result = hass.data[AUTH_DOMAIN]
    # Remove old LoginFlowResourceView
    for route in hass.http.app.router._resources:
        if route.canonical == "/auth/login_flow":
            _LOGGER.debug("Removed original login_flow route")
            hass.http.app.router._resources.remove(route)
    _LOGGER.debug("Add new login_flow route")
    hass.http.register_view(
        RequestLoginFlowResourceView(hass.auth.login_flow, store_result)
    )

    # Inject Auth-Header provider.
    providers = OrderedDict()
    provider = headers.HeaderAuthProvider(
        hass,
        hass.auth._store,
        config[DOMAIN],
    )
    providers[(provider.type, provider.id)] = provider
    providers.update(hass.auth._providers)
    hass.auth._providers = providers
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
