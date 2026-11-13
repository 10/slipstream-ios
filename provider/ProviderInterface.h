// What the CLI (src/tunnel.m) and the provider (provider/AppProxyProvider.m) agree on.
// The proxy URL in the saved configuration's providerConfiguration.
#define SlipstreamProxyURLKey @"proxy_url"
// Messages to the connected provider. Reload switches to the proxy URL that follows and is
// answered with SlipstreamReloaded.
#define SlipstreamReload @"reload\n"
#define SlipstreamReloaded @"reloaded"
// Runs the connection check; the reply is the engine's JSON result.
#define SlipstreamCheck @"check"
