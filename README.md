# Header Auth for Homeassistant

This custom component allows you to delegate authentication to a reverse proxy.

**Use with caution. If misconfigured, this can lead to Homeassistant that anyone can access***

## Installation

Add this repository to [HACS](https://hacs.xyz/) and install over in the Integrations tab. Go to the Integrations Page and enable it. The prompt is the name of the Header to be checked.

## How it works

On boot, two main things are done:

1. The default `LoginFlowIndexView` view is replaced. This view is called when you submit the login form. The replacement for this view, `RequestLoginFlowResourceView`, simply adds the HTTP Request to the context. This context is passed to authentication Providers.

    Normally the Request is not included, as none of the providers require it.

2. If the integration has been enabled, the default Authentication Provider is replaced by an instance of the Header Authentication Provider. It is replaced because if you have multiple authentication providers, you still get a prompt.
