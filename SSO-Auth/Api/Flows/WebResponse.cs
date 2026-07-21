// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Globalization;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>
/// A helper class to return HTML for the client's auth flow.
/// </summary>
internal static class WebResponse
{
    /// <summary>
    /// The shared HTML between all of the responses.
    /// </summary>
    internal static readonly string Base = @"<!DOCTYPE html>
<html lang='en'><head>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<style nonce=""{{NONCE}}"">
  body {
    background: #101010;
    color: #d1cfce;
    font-family: Noto Sans, Noto Sans HK, Noto Sans JP, Noto Sans KR, Noto Sans SC, Noto Sans TC, sans-serif;
  }
  a {
    color: #00a4dc;
  }
  #iframe-main {
    position: absolute;
    width: 0;
    height: 0;
    border: 0;
  }
</style>
</head><body>
<p role='status' aria-live='polite'>Logging in...</p>
<noscript>Please enable Javascript to complete the login</noscript>
<script nonce=""{{NONCE}}"">

function isTv() {
    // This is going to be really difficult to get right
    const userAgent = navigator.userAgent.toLowerCase();

    // The OculusBrowsers userAgent also has the samsungbrowser defined but is not a tv.
    if (userAgent.indexOf('oculusbrowser') !== -1) {
        return false;
    }

    if (userAgent.indexOf('tv') !== -1) {
        return true;
    }

    if (userAgent.indexOf('samsungbrowser') !== -1) {
        return true;
    }

    if (userAgent.indexOf('viera') !== -1) {
        return true;
    }

    return isWeb0s();
}

function isWeb0s() {
    const userAgent = navigator.userAgent.toLowerCase();

    return userAgent.indexOf('netcast') !== -1
        || userAgent.indexOf('web0s') !== -1;
}

// Browser detection derived from jellyfin-web's browser.js. Trimmed (#364) to only what the served
// page reads — getDeviceName() below consumes tizen/web0s/operaTv/xboxOne/ps4/chrome/edgeChromium/
// edge/firefox/opera/safari/ipad/iphone/android — so the mobile/keyboard/iOS-version/webOS-version/
// CSS-animation detections and their flags are dropped. Re-sync this blob (isTv / isWeb0s / uaMatch /
// the browser-flag assembly below) from upstream rather than editing it in place.
const uaMatch = function (ua) {
    ua = ua.toLowerCase();

    const match = /(chrome)[ /]([\w.]+)/.exec(ua)
        || /(edg)[ /]([\w.]+)/.exec(ua)
        || /(edga)[ /]([\w.]+)/.exec(ua)
        || /(edgios)[ /]([\w.]+)/.exec(ua)
        || /(edge)[ /]([\w.]+)/.exec(ua)
        || /(opera)[ /]([\w.]+)/.exec(ua)
        || /(opr)[ /]([\w.]+)/.exec(ua)
        || /(safari)[ /]([\w.]+)/.exec(ua)
        || /(firefox)[ /]([\w.]+)/.exec(ua)
        || ua.indexOf('compatible') < 0 && /(mozilla)(?:.*? rv:([\w.]+)|)/.exec(ua)
        || [];

    const versionMatch = /(version)[ /]([\w.]+)/.exec(ua);

    let platform_match = /(ipad)/.exec(ua)
        || /(iphone)/.exec(ua)
        || /(windows)/.exec(ua)
        || /(android)/.exec(ua)
        || [];

    let browser = match[1] || '';

    if (browser === 'edge') {
        platform_match = [''];
    }

    if (browser === 'opr') {
        browser = 'opera';
    }

    let version;
    if (versionMatch && versionMatch.length > 2) {
        version = versionMatch[2];
    }

    version = version || match[2] || '0';

    let versionMajor = parseInt(version.split('.')[0], 10);

    if (isNaN(versionMajor)) {
        versionMajor = 0;
    }

    return {
        browser: browser,
        version: version,
        platform: platform_match[0] || '',
        versionMajor: versionMajor
    };
};

const userAgent = navigator.userAgent;

const matched = uaMatch(userAgent);
const browser = {};

if (matched.browser) {
    browser[matched.browser] = true;
}

if (matched.platform) {
    browser[matched.platform] = true;
}

browser.edgeChromium = browser.edg || browser.edga || browser.edgios;

if (!browser.chrome && !browser.edgeChromium && !browser.edge && !browser.opera && userAgent.toLowerCase().indexOf('webkit') !== -1) {
    browser.safari = true;
}

browser.osx = userAgent.toLowerCase().indexOf('mac os x') !== -1;

// This is a workaround to detect iPads on iOS 13+ that report as desktop Safari
// This may break in the future if Apple releases a touchscreen Mac
// https://forums.developer.apple.com/thread/119186
if (browser.osx && !browser.iphone && !browser.ipod && !browser.ipad && navigator.maxTouchPoints > 1) {
    browser.ipad = true;
}

if (userAgent.toLowerCase().indexOf('playstation 4') !== -1) {
    browser.ps4 = true;
    browser.tv = true;
}

if (userAgent.toLowerCase().indexOf('xbox') !== -1) {
    browser.xboxOne = true;
    browser.tv = true;
}
browser.tizen = userAgent.toLowerCase().indexOf('tizen') !== -1 || window.tizen != null;
browser.web0s = isWeb0s();
browser.edgeUwp = browser.edge && (userAgent.toLowerCase().indexOf('msapphost') !== -1 || userAgent.toLowerCase().indexOf('webview') !== -1);

if (browser.tizen) {
    // A Tizen UserAgent contains 'Safari' and 'safari' is set by the matched browser, but we only
    // want 'tizen' to be true so getDeviceName reports the Samsung TV, not Safari.
    delete browser.safari;
}

if (browser.edgeUwp) {
    browser.edge = true;
}

browser.tv = isTv();
browser.operaTv = browser.tv && userAgent.toLowerCase().indexOf('opr/') !== -1;

function getDeviceName() {
	var deviceName = '';
    if (!deviceName) {
        if (browser.tizen) {
            deviceName = 'Samsung Smart TV';
        } else if (browser.web0s) {
            deviceName = 'LG Smart TV';
        } else if (browser.operaTv) {
            deviceName = 'Opera TV';
        } else if (browser.xboxOne) {
            deviceName = 'Xbox One';
        } else if (browser.ps4) {
            deviceName = 'Sony PS4';
        } else if (browser.chrome) {
            deviceName = 'Chrome';
        } else if (browser.edgeChromium) {
            deviceName = 'Edge Chromium';
        } else if (browser.edge) {
            deviceName = 'Edge';
        } else if (browser.firefox) {
            deviceName = 'Firefox';
        } else if (browser.opera) {
            deviceName = 'Opera';
        } else if (browser.safari) {
            deviceName = 'Safari';
        } else {
            deviceName = 'Web Browser';
        }

        if (browser.ipad) {
            deviceName += ' iPad';
        } else if (browser.iphone) {
            deviceName += ' iPhone';
        } else if (browser.android) {
            deviceName += ' Android';
        }
    }

    return deviceName;
}

const sleep = (milliseconds) => {
    return new Promise(resolve => setTimeout(resolve, milliseconds))
}

// On a terminal failure the page must not dead-end (#667): offer an obvious way back to the login
// screen. ssoBaseUrl is a JSON-encoded safe constant; the link is built via DOM APIs (never
// innerHTML) and appended once after the status line, which carries role='status' aria-live='polite'
// so its message swap is announced to assistive tech.
function showReturnLink() {
    if (document.getElementById('sso-return-link')) return;
    const link = document.createElement('a');
    link.id = 'sso-return-link';
    link.textContent = 'Return to login';
    link.href = ssoBaseUrl + '/web/index.html';
    document.querySelector('p').insertAdjacentElement('afterend', link);
}

";

    /// <summary>
    /// A generator for the web response that incorporates the data from the server.
    /// </summary>
    /// <param name="data">The opaque value the page posts back to the mint leg: a one-time state token for OpenID and, since #251, a one-time login-outcome token for a SAML login (a base64 assertion only on the SAML linking / pre-#251 deprecation path).</param>
    /// <param name="provider">The name of the provider to callback to.</param>
    /// <param name="baseUrl">The base URL of the Jellyfin installation.</param>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="nonce">The per-response CSP nonce emitted on the inline script and style tags.</param>
    /// <param name="isLinking">Whether or not this request is to link accounts (Rather than authenticate).</param>
    /// <returns>A string with the HTML to serve to the client.</returns>
    public static string Generator(string data, string provider, string baseUrl, string mode, string nonce, bool isLinking = false)
    {
        System.ArgumentNullException.ThrowIfNull(baseUrl);

        // Strip out the protocol (http:// or https://) and convert the domain to Punycode
        var idnMapping = new IdnMapping();
        var protocolSeparatorIndex = baseUrl.IndexOf("//", System.StringComparison.Ordinal);

        // baseUrl is server-derived and normally carries a scheme, so "//" is expected. A missing
        // separator would otherwise silently mis-split (Substring(0, 1) / Substring(1)); fail closed
        // instead of building a corrupt ssoBaseUrl the whole page then posts back to.
        if (protocolSeparatorIndex < 0)
        {
            throw new System.ArgumentException("baseUrl must contain a protocol separator ('//').", nameof(baseUrl));
        }

        var protocol = baseUrl.Substring(0, protocolSeparatorIndex + 2);
        var domain = baseUrl.Substring(protocolSeparatorIndex + 2);
        var punycodeDomain = idnMapping.GetAscii(domain);
        var punycodeBaseUrl = protocol + punycodeDomain;

        // Emit the server-derived values as JSON-encoded JS constants so they cannot break out of
        // the script context, then build every URL from these constants rather than interpolating
        // raw. punycodeBaseUrl derives from the request host, and provider from the route, so both
        // are treated as untrusted here (defense-in-depth); mode is a fixed literal.
        return Base.Replace("{{NONCE}}", nonce, System.StringComparison.Ordinal) + @"
const ssoBaseUrl = " + JsonSerializer.Serialize(punycodeBaseUrl) + @";
const ssoProvider = " + JsonSerializer.Serialize(provider) + @";
const ssoMode = " + JsonSerializer.Serialize(mode) + @";
async function link(request) {
    const jfCredentialsString = localStorage.getItem(""jellyfin_credentials"");

    if (jfCredentialsString == null) return;

    const jfCredentials = JSON.parse(jfCredentialsString);
    const jfUser = jfCredentials['Servers'][0]['UserId'];
    const jfToken = jfCredentials['Servers'][0]['AccessToken'];

    if (jfUser == null) return;
    if (jfToken == null) return;

    const url = ssoBaseUrl + '/sso/' + ssoMode + '/Link/' + encodeURIComponent(ssoProvider) + '/' + jfUser;

    return new Promise(resolve => {
       var xhr = new XMLHttpRequest();
       xhr.open('POST', url, true);
       xhr.setRequestHeader('Content-Type', 'application/json');
       xhr.setRequestHeader('Accept', 'application/json');

       xhr.setRequestHeader(
           'Authorization',
           `MediaBrowser Client=""${request.appName}"",Device=""${request.deviceName}"",DeviceId=""${request.deviceId}"",Version=""${request.appVersion}"",Token=""${jfToken}""`)

       xhr.onload = function(e) {
         resolve(xhr.status);
       };
       xhr.onerror = function (e) {
         console.log(e);
         resolve(undefined);
       };
       xhr.send(JSON.stringify(request));
    })
}

async function main() {
    localStorage.removeItem('jellyfin_credentials');
    document.getElementById('iframe-main').src = ssoBaseUrl + '/web/index.html';

    var data = " + JsonSerializer.Serialize(data) + @";
    while (localStorage.getItem(""_deviceId2"") == null ||
        localStorage.getItem(""jellyfin_credentials"") == null ||
        JSON.parse(localStorage.getItem(""jellyfin_credentials""))['Servers'][0]['Id'] == null) {
        // If localStorage isn't initialized yet, try again.
        await sleep(100);
    }
    var deviceId = localStorage.getItem(""_deviceId2"");
    var appName = ""Jellyfin Web"";
    var appVersion = ""10.8.0"";
    var deviceName = getDeviceName();

    var request = {deviceId, appName, appVersion, deviceName, data};

    if (" + (isLinking ? "true" : "false") + @") {
        // Linking is NOT a login round-trip, so a DEFINITIVE link outcome is terminal here — the page does
        // NOT go on to post to .../Auth (#614). The Link leg one-time-consumes the assertion / state token,
        // so the old unconditional follow-on Auth post could never redeem it: it fail-closed at the mint leg
        // and rendered a misleading 'Login failed. Please try again.' even though the link itself had already
        // succeeded on its own leg.
        //   - A 2xx is a completed link: show success and stop (do not attempt a login).
        //   - A non-2xx is a rejected link (#344): the provider is disabled (#343), the caller is not
        //     allowed, or the request is throttled — surface it and stop, never fall through to a login.
        //   - A missing status (undefined: no stored credentials, or a network error) keeps the prior
        //     behavior of proceeding to the auth leg, since that outcome cannot be told apart from success.
        var linkStatus = await link(request);
        if (linkStatus !== undefined) {
            const linked = linkStatus >= 200 && linkStatus < 300;
            document.querySelector('p').textContent =
                linked
                    ? 'Account linked. You can now log in with SSO.'
                    : linkStatus === 429
                        ? 'Too many attempts. Please wait a moment and try again.'
                        : 'Could not link this account. The provider may be disabled, or linking is not permitted.';
            if (!linked) {
                showReturnLink();
            }
            return;
        }
    }

    var url = ssoBaseUrl + '/sso/' + ssoMode + '/Auth/' + encodeURIComponent(ssoProvider);

    let response = await new Promise(resolve => {
       var xhr = new XMLHttpRequest();
       xhr.open('POST', url, true);
       xhr.setRequestHeader('Content-Type', 'application/json');
       xhr.setRequestHeader('Accept', 'application/json');
       xhr.onload = function(e) {
         resolve({status: xhr.status, body: xhr.response});
       };
       xhr.onerror = function () {
         resolve(undefined);
       };
       xhr.send(JSON.stringify(request));
    })
    var responseJson;
    try {
        responseJson = response && response.status === 200 ? JSON.parse(response.body) : undefined;
    } catch (e) {
        responseJson = undefined;
    }
    if (!responseJson) {
        // A throttled (429) or failed authentication must surface as text instead of leaving the
        // page stuck on 'Logging in...' forever (reloading only adds rate-limit hits).
        document.querySelector('p').textContent =
            response && response.status === 429
                ? 'Too many login attempts. Please wait a moment and try again.'
                : 'Login failed. Please try again.';
        showReturnLink();
        return;
    }
    var userId = 'user-' + responseJson['User']['Id'] + '-' + responseJson['User']['ServerId'];
    responseJson['User']['EnableAutoLogin'] = true;
    localStorage.setItem(userId, JSON.stringify(responseJson['User']));
    var jfCreds = JSON.parse(localStorage.getItem('jellyfin_credentials'));
    jfCreds['Servers'][0]['AccessToken'] = responseJson['AccessToken'];
    jfCreds['Servers'][0]['UserId'] = responseJson['User']['Id'];
    localStorage.setItem('jellyfin_credentials', JSON.stringify(jfCreds));
    localStorage.setItem('enableAutoLogin', 'true');
    window.location.replace(ssoBaseUrl + '/web/index.html');
}

document.addEventListener('DOMContentLoaded', function () {
    main();
});

// https://stackoverflow.com/a/25435165
</script><iframe id='iframe-main' sandbox='allow-same-origin allow-forms allow-scripts' src=''></iframe></body></html>";
    }
}
