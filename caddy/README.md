# Caddyfile (v2) Hardened

_Note: I do not use Caddy anymore, but this will still generally apply to most with some maybe minor inconsistencies for a while._

# Why Caddy?

- Very, very, simplistic configuartion style.
- Caddy's crypto library is written in Go, a memory safe and high performance language. Its codebase is a lot more fine grained than OpenSSL, and doesn't support unsafe APIs like OpenSSL.
- Reverse proxying is very easy and handles all headers like Remote IP, Host, etc for you without any intervention.
- Caddy itself is also written in Go.
- Caddy has support for TLS1.3, HTTP2, and HTTP3/QUIC without any extra configuration with default enabled OCSP stapling, downgrade protection, and default SSL session cache\*.
- Caddy uses secure TLS ciphers and secure TLS versions by default.
- Caddy can use compression easily.
- Built in support for requesting and automatically requests and enables free TLS certificates from Let's Encrypt, Let's Encrypt staging (such as wildcard certs), or ZeroSSL.
- Caddy is a project developed by ZeroSSL.
- Full integration with Cloudflare and can use Full (Strict) SSL mode with **zero** configuration necessary as it uses a trusted CA for you.
- Caddy has a JSON API interface for scripting configuration and other tasks.
- And modules can be added easily if necessary using the admin interface.

\*_Caddy's TLS/SSL session cache is different than how Nginx does it. It uses tickets and ticket keys instead of caching. Caddy also rotates these ticket keys every few hours by default. SSLLabs will report no session cache, but you have tickets which do the same thing as cache._

# Why _not_ Caddy?
- Their Brotli module is surprisingly _very_ bad. It's been taken out entirely and is currently an experimental module.
- Reverse proxying software through Caddy is considered experimental. Software such as NextCloud do not support it in any way and discourage its usage.
- Caddy is not considered industry standard like Nginx and Apache.
- Caddy has no middleware or any place to configure rate limiting solutions to mitigate DOS attacks like Nginx.
- Simplicity is not always better.

# Global Settings

- `experimental_http3` allows HTTP3/QUIC. It's a very refined and high performance standard now so it's generally safe to use in production now. Utilizes UDP instead of TCP.
- `allow_h2c` allows HTTP2 over TCP and HTTP (cleartext). Allows unupgraded requests to still utilize HTTP2's stream instead of HTTP1.1's request/reply. We will upgrade them of course. Determine if you actually need this as in some cases it can break things.
- `admin off` disables the Caddy admin interface from both the UNIX socket and TCP listening. By default, Caddy opens an admin interface on TCP `localhost`. This can be assisted in abritrary process modification, and Caddy suggests to use the UNIX socket. Since we won't be using the admin interface at all, we can disable it entirely.

- `strict_sni_host` is an extra TLS client authentication feature that ensures the `Host` header of a request matches the value of the ServerName by the client's TLS ClientHello. For some strange reason, Microsoft Edge would crash every time I tried to access my website with it enabled. Give it a try yourself.

# General Settings for all websites

`encode gzip zstd` uses compression. It will prioritize gzip first. zstd will only be used if the client does not support gzip.

Note: TLS/HTTPS compression adds attack surface, especially gzip. Trades some security for performance. See [CRIME](https://wikipedia.org/wiki/CRIME) and [BREACH](https://en.wikipedia.org/wiki/BREACH).

```
@static {
	file
	path *.ico *.css *.js *.gif *.jpg *.jpeg *.png *.svg *.woff *.woff2
}
header @static Cache-Control max-age=31536000
```
Cache all static content for a year.

By default, Caddy requests an ECC certificate and uses secure ciphers, curves, and TLS protocols.

```
header {
	Cache-Control max-age=31536000
	X-XSS-Protection "1; mode=block"
	X-Frame-Options "DENY"
        X-Robots-Tag "none"
        Referrer-Policy no-referrer
        Expect-CT "enforce, max-age=63072000"
        Cross-Origin-Opener-Policy same-origin
        Cross-Origin-Embedder-Policy require-corp
        Cross-Origin-Resource-Policy same-origin
        Content-Security-Policy "default-src 'none'; script-src 'self'; object-src 'self'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; block-all-mixed-content; form-action 'none'"
        X-Content-Security-Policy "default-src 'none'; script-src 'self'; object-src 'self'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; block-all-mixed-content; form-action 'none'"
        X-WebKit-CSP "default-src 'none'; script-src 'self'; object-src 'self'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; block-all-mixed-content; form-action 'none'"
        Permissions-Policy "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), xr-spatial-tracking=(), clipboard-read=(self), clipboard-write=(self), conversion-measurement=(), hid=(), idle-detection=(), serial=(), trust-token-redemption=()"
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        -Server
}
```

The most important part to this config.

- `Cache-Control max-age=31536000` tells the browser to cache this website for 1 year. Note: This partially breaks Element.
- `X-XSS-Protection "1; mode=block"` is a legacy, but still commonly used, header to prevent from XSS (cross-site scripting attacks) attacks. This has been replaced with a strong Content Security Policy.
- `X-Frame-Options "DENY"` is also a legacy, but still commonly used, header to prevent websites from rendering your website in any frames or objects. This has been replaced with `frame-ancestors` in the CSP.
- `Referrer-Policy no-referrer` omits the `Referrer` header entirely to increase privacy.
- `Expect-CT` is a header that enables browsers to enforce checking certificate transparency. This is an obsolete header as if the client's clock is correct, there will be no issues and all certificates support transparency as of 2018.
- `Strict-Transport-Security` is HTTP Strict Transport Security. HSTS by itself is not that useful as it can still be bypassed, unless you preload your website and submit it to the hstspreload.org list to fully protect clients from downgrading and MITM attacks. For the best security, use a 2 year max-age time, includeSubDomains, and preload.
- `-Server` is Caddy's equivalent to `server_tokens off;` in Nginx. It removes the header that tells clients what web server is being used and the version.
- `X-Robots-Tag` set to `none` tells (respecting) search engine spiders and indexers to not index or crawl our website.
- `X-Content-Type-Options` set to `nosniff` prevents the browser from MIME and content sniffing.

`Content-Security-Policy` is a pretty important header as it defines how browsers handle certain resources such as sandboxing them, restricting them, and access control. A strong CSP prevents many kinds of attacks.

Different websites require different CSP's. For a simple HTML and CSS static website with no inline CSS or JavaScript, I use the following:
<br>
`Content-Security-Policy "default-src 'none'; script-src 'self'; object-src 'self'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; block-all-mixed-content; form-action 'none'"`

- `default-src 'none'` sets any undefined policies to 'none' which is disallowing from any source, including the website and same origin itself (the quotes are important for single keywords here).
- `script-src 'self'` only allows running JavaScript from the same origin. If you're using Brotli or any scripts from Cloudflare, you will need to manually whitelist their origins else your console will be spammed with denied errors.
- `object-src 'self'` only allows plugins (object, embed, or applet) from the same origin.
- `style-src 'self'` only allows CSS stylesheets from the same origin.
- `img-src 'self'` only allows images from the same origin.
- `media-src 'self'` only allows multimedia from the same origin.
- `font-src 'self'` only allows fonts from the same origin. This will block loading fonts from external sources like Google Fonts. You will need to whitelist their origins... or download the fonts :)
- `frame-src 'self'` only allows rendering frames and objects from the same origin.
- `connect-src 'self'` only allows connecting to AJAX, Websockets, fetch(), or pinging from the same origin.
- `manifest-src 'self'` only allows loading application manifest sources from the same origin.
- `form-action 'none'` forbids all HTML forms from anywhere.
- `block-all-mixed-content` is a deprecated policy that forbids loading content from HTTP only sources on an HTTPS website.

Note: `X-Content-Security-Policy` and `X-WebKit-CSP` are the same. They are just for browser compatibility such as Safari/WebKit.

Unfortunately, some web applications (e.g. Discord and Element) use unsafe practices such as inline CSS, inline JavaScript, and JavaScript evaluation. These have been found to assist in exploitation, especially `eval`. While there isn't much you can do about this (besides pushing for the developers to use safer alternatives), you may need to allow `unsafe-inline` and `unsafe-eval` for `script-src` and `style-src`. Whitelisting hashes is very tedious and bloats up the headers.

`Permissions-Policy` is a predefined list of permissions the browser must follow. For example, it can be used to forcibly deny access to camera, microphones, geolocation, and hardware like the sensors gyroscope and WebUSB. The browser cannot override these without changing the header on the server.
<br>
`Permissions-Policy "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), xr-spatial-tracking=(), clipboard-read=(self), clipboard-write=(self), conversion-measurement=(), hid=(), idle-detection=(), serial=(), trust-token-redemption=()"`

Blank values `()` are denied and absolutely no exception. `(self)` only allows the same origin. Usually you'll want clipboard access to be set to `(self)` for this.

```
http://, :80 {
        redir https://{host}{uri}

        header {
                -Server
        }
}
```

Upgrade all HTTP requests (and any requests on port 80) to HTTPS and hide the Server header.
