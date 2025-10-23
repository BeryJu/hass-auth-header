# ARCHIVED

There are now functioning OIDC plugins for HASS and there will be no more future development on this plugin:

- https://github.com/cavefire/hass-openid
- https://github.com/christiaangoossens/hass-oidc-auth

---

# Header Auth for Home Assistant

This custom component allows you to delegate authentication to a reverse proxy.

This integrations checks the value of a configured header and authenticates based on its value. The value of the header is
checked against usernames AND full names. Users have to be created in Home Assistant by hand.

**Use with caution. If misconfigured, this can lead to a Home Assistant instance that anyone can access**

## Installation

1. Add this repository to [HACS](https://hacs.xyz/).

   [![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=BeryJu&repository=hass-auth-header&category=integration)


2. Update your configuration.yaml file with
    
    ```yaml
    http:
        use_x_forwarded_for: true
        trusted_proxies:
            - 1.2.3.4/32 # This needs to be set to the IP of your reverse proxy
    auth_header:
        # Optionally set this if you're not using authentik proxy or oauth2_proxy
        # username_header: X-Forwarded-Preferred-Username
        # Optionally set this if you don't want to bypass the login prompt
        # allow_bypass_login: false
        # Optionally enable debug mode to see the headers Home-Assistant gets
        # debug: false
    # Optionally, if something is not working right, add this block below to get more information
    logger:
        default: info
        logs:
            custom_components.auth_header: debug
    ```
3. Afterwards, restart Home Assistant.
    
![](./.github/demo.gif)

## CSRF Errors when used with oauth2_proxy or authentik

See https://github.com/goauthentik/authentik/issues/884#issuecomment-851542477

## How it works

On boot, two main things are done when the integration is enabled:

1. The default `LoginFlowIndexView` view is replaced. This view is called when you submit the login form. The replacement for this view, `RequestLoginFlowResourceView`, simply adds the HTTP Request to the context. This context is passed to authentication Providers.

    Normally the Request is not included, as none of the providers require it.

2. The Header Authentication Provider is injected into the providers, *before* the other authentication providers.

    This ensures that Header auth is tried first, and if it fails the user can still use username/password.


## Help! Everything is broken!

If anything goes wrong or Home Assistant fails to load the component correctly, simply remove the `auth_header` block from your configuration file and restart HASS.
