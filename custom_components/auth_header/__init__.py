import logging
from http import HTTPStatus
import os.path
from ipaddress import ip_address
from typing import Any, OrderedDict, TYPE_CHECKING

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from aiohttp.web import Request, Response
from homeassistant import data_entry_flow
from homeassistant.components.auth import DOMAIN as AUTH_DOMAIN
from homeassistant.components.auth import indieauth
from homeassistant.components.auth.login_flow import LoginFlowIndexView
from homeassistant.components.http.ban import log_invalid_auth
from homeassistant.components.http.data_validator import RequestDataValidator
from homeassistant.core import HomeAssistant
from homeassistant.components.frontend import add_extra_js_url

from . import headers

if TYPE_CHECKING:
    from homeassistant.components.http import FastUrlDispatcher
    from aiohttp.web_urldispatcher import UrlDispatcher, AbstractResource

DOMAIN = "auth_header"
_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Optional("username_header", default="X-Forwarded-Preferred-Username"): cv.string,
                vol.Optional("allow_bypass_login", default=True): cv.boolean,
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
    router: "FastUrlDispatcher" | "UrlDispatcher" = hass.http.app.router
    # Remove old LoginFlowIndexView
    # HASS < 2023.8 just has a list of all routes, which we can directly remove from
    for route in router._resources:
        if route.canonical == RequestLoginFlowIndexView.url:
            _LOGGER.debug("Removed original login_flow route (UrlDispatcher) %s", route)
            hass.http.app.router._resources.remove(route)
    # HASS 2023.8+ uses the "FastUrlDispatcher", which also keeps a dict for faster lookups
    if hasattr(router, "_resource_index"):
        resource_index: dict[str, list["AbstractResource"]] = router._resource_index
        routes = resource_index.get(RequestLoginFlowIndexView.url, None)
        if routes:
            for route in routes:
                if route.canonical == RequestLoginFlowIndexView.url:
                    _LOGGER.debug("Removed original login_flow route (FastUrlDispatcher) %s", route)
                    routes.remove(route)
    _LOGGER.debug("Add new login_flow route")
    hass.http.register_view(
        RequestLoginFlowIndexView(
            hass.auth.login_flow, store_result, config[DOMAIN]["debug"]
        )
    )

    # Load script to store tokens in local storage, else we'll re-auth on every browser refresh.
    hass.http.register_static_path(
        "/auth_header/store-token.js",
        os.path.join(os.path.dirname(__file__), 'store-token.js'),
    )
    add_extra_js_url(hass, '/auth_header/store-token.js')

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
    value. We still need to check the actual remote though, to verify its from a valid proxy.
    """
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
    async def post(self, request: Request, data: dict[str, Any]) -> Response:
        """Create a new login flow."""
        client_id: str = data["client_id"]
        redirect_uri: str = data["redirect_uri"]

        if not indieauth.verify_client_id(client_id):
            return self.json_message("Invalid client id", HTTPStatus.BAD_REQUEST)

        handler: tuple[str, ...] | str
        if isinstance(data["handler"], list):
            handler = tuple(data["handler"])
        else:
            handler = data["handler"]

        try:
            _LOGGER.debug(request.headers)
            actual_ip = get_actual_ip(request)
            _LOGGER.debug("Got actual IP %s", actual_ip)
            result = await self._flow_mgr.async_init(
                handler,  # type: ignore[arg-type]
                context={
                    "request": request,
                    "ip_address": ip_address(request.remote),  # type: ignore[arg-type]
                    "conn_ip_address": ip_address(actual_ip),  # type: ignore[arg-type]
                    "credential_only": data.get("type") == "link_user",
                    "redirect_uri": redirect_uri,
                },
            )
        except data_entry_flow.UnknownHandler:
            return self.json_message("Invalid handler specified", HTTPStatus.NOT_FOUND)
        except data_entry_flow.UnknownStep:
            return self.json_message(
                "Handler does not support init", HTTPStatus.BAD_REQUEST
            )

        return await self._async_flow_result_to_response(request, client_id, result)
