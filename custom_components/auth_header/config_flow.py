"""Config flow for AuthHeader integration."""
import logging

import voluptuous as vol
from homeassistant import config_entries, core

_LOGGER = logging.getLogger(__name__)

DATA_SCHEMA = vol.Schema({"header": str})


async def validate_input(hass: core.HomeAssistant, data):
    """Validate the user input allows us to connect.

    Data has the keys from DATA_SCHEMA with values provided by the user.
    """
    # Return some info we want to store in the config entry.
    return {"title": "AuthHeader"}


class DomainConfigFlow(config_entries.ConfigFlow, domain="auth_header"):
    """Handle a config flow for AuthHeader."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_PUSH

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)

                return self.async_create_entry(title=info["title"], data=user_input)
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user", data_schema=DATA_SCHEMA, errors=errors
        )
