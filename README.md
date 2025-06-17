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
        # Optionally set this if you want to enable Single Logout
        # single_logout_url: https://your.homeassistant.instance/oauth2/sign_out?rd=https%3A%2F%2Fyour.idp.com%2Foauth2%2Flogout
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

3. If the single logout URL is available, we patch `_handleLogout` as soon as the home-assistant element is available

    This redirects the user to the configured SLO url after the stock logic to revoke the access token is executed

## Single Logout Support

The component can patch the stock log out handler to clear the authentication proxy's session and log you out of your IDP if you specify a `single_logout_url`. This is usually a call to your authentication proxy (such as oauth2-proxy) with a rd parameter to redirect the user to your IDP's logout endpoint after. The IDP's logout endpoint needs to be URL-encoded in the configuration. 

```
https://your.homeassistant.instance/oauth2/sign_out?rd=https%3A%2F%2Fyour.idp.com%2Foauth2%2Flogout

https://your.homeassistant.instance/oauth2/sign_out?rd= > your oauth proxy's SLO endpoint
https%3A%2F%2Fyour.idp.com%2Foauth2%2Flogout > your IDP's SLO endpoint URL-encoded
```

You can also configure a front-channel logout URL in your IDP to call the same endpoint to clear the proxy's session however, this does not revoke your currently logged in access token.

## Help! Everything is broken!

If anything goes wrong or Home Assistant fails to load the component correctly, simply remove the `auth_header` block from your configuration file and restart HASS.
