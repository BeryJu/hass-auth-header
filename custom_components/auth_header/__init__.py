import logging
from ipaddress import ip_address
from typing import OrderedDict
from aiohttp.web_request import Request

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant import data_entry_flow
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
                vol.Optional("debug", default=False): cv.boolean,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config):
    """Register custom view which includes request in context"""
    # Because we start after auth, we have access to store_result
    store_result = hass.data[AUTH_DOMAIN]
    # Remove old LoginFlowIndexView
    for route in hass.http.app.router._resources:
        if route.canonical == "/auth/login_flow":
            _LOGGER.debug("Removed original login_flow route")
            hass.http.app.router._resources.remove(route)
    _LOGGER.debug("Add new login_flow route")
    hass.http.register_view(
        RequestLoginFlowIndexView(
            hass.auth.login_flow, store_result, config[DOMAIN]["debug"]
        )
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


def get_actual_ip(request: Request) -> str:
    """Get remote from `request` without considering overrides. This is because
    when behind a reverse proxy, hass overrides the .remote attributes with the X-Forwarded-For
    value. We still need to check the actual remote though, to verify its from a valid proxy."""
    if isinstance(request._transport_peername, (list, tuple)):
        return request._transport_peername[0]
    return request._transport_peername


class RequestLoginFlowIndexView(LoginFlowIndexView):

    debug: bool

    def __init__(self, flow_mgr, store_result, debug=False) -> None:
        super().__init__(flow_mgr, store_result)
        self.debug = debug

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
    async def post(self, request: Request, data):
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
            _LOGGER.debug(request.headers)
            actual_ip = get_actual_ip(request)
            _LOGGER.debug("Got actual IP %s", actual_ip)
            result = await self._flow_mgr.async_init(
                handler,
                context={
                    "request": request,
                    "ip_address": ip_address(actual_ip),
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
