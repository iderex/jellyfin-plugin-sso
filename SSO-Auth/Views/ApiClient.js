// Project-maintained code, NOT a vendored copy: it is loosely based on jellyfin-web (the permalinks
// below mark the functions it was adapted from) but carries this plugin's own logic, so edit it here
// directly. The imported jellyfin-apiClient.esm.min.js bundle it depends on IS vendored. See
// CONTRIBUTING.md → Styleguides.
import jellyfinApiclient from "./jellyfin-apiClient.esm.min.js";
window.jellyfinApiclient = jellyfinApiclient;

// https://github.com/jellyfin/jellyfin-web/blob/9067b0e397cc8b38635d661ce86ddd83194f3202/src/scripts/clientUtils.js#L19-L76
export async function serverAddress({ basePath = "/web" }) {
  const apiClient = window.ApiClient;

  if (apiClient) {
    return apiClient.serverAddress();
  }

  const urls = [];

  const getViewUrl = (basePath) => {
    let url;
    const index = window.location.href
      .toLowerCase()
      .lastIndexOf(basePath.toLowerCase());

    if (index != -1) {
      url = window.location.href.substring(0, index);
    } else {
      // Return nothing, let another method handle it
      url = undefined;
    }

    return url;
  };

  if (urls.length === 0) {
    // Otherwise use computed base URL
    let url;

    url = getViewUrl(basePath) ?? getViewUrl("/web") ?? window.location.origin;

    // Don't use bundled app URL (file:) as server URL
    if (url.startsWith("file:")) {
      return;
    }

    urls.push(url);
  }

  console.debug("URL candidates:", urls);

  // Fail closed: only probe candidates on this page's own origin.
  const isSameOrigin = (candidate) => {
    try {
      return new URL(candidate).origin === window.location.origin;
    } catch {
      return false;
    }
  };

  const promises = urls.filter(isSameOrigin).map((url) => {
    return fetch(`${url}/System/Info/Public`)
      .then((resp) => {
        return {
          url: url,
          response: resp,
        };
      })
      .catch(() => undefined);
  });

  return Promise.all(promises)
    .then((responses) => {
      responses = responses.filter((obj) => obj?.response.ok);
      return Promise.all(
        responses.map(async (obj) => {
          return {
            url: obj.url,
            config: await obj.response.json(),
          };
        }),
      );
    })
    .then((configs) => {
      const selection =
        configs.find((obj) => !obj.config.StartupWizardCompleted) || configs[0];
      return selection?.url;
    })
    .catch((error) => {
      console.log(error);
    });
}

// The browser-to-device-name derivation is defined once, in the server-rendered auth-completion
// page (WebResponse.cs). This linking view is not a login client, so it does not re-derive that
// value; it registers under a fixed placeholder identifier. This is kept byte-identical to the
// prior behavior on purpose - deriving a real device name here would change the name SSO-view
// sessions register under, which is a separate, deliberate behavior change.
const deviceName = "DUMMY";

function getDeviceId() {
  return localStorage.getItem("_deviceId2");
}

const sleep = (milliseconds) => {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
};

async function awaitLocalStorage() {
  while (
    localStorage.getItem("_deviceId2") == null ||
    localStorage.getItem("jellyfin_credentials") == null ||
    JSON.parse(localStorage.getItem("jellyfin_credentials"))["Servers"][0][
      "Id"
    ] == null
  ) {
    // If localStorage isn't initialized yet, try again.
    await sleep(100);
  }
}

await awaitLocalStorage();

// Fetch credentials

const credentials = new jellyfinApiclient.Credentials();

const server = await serverAddress({ basePath: "/SSOViews" });
const deviceId = getDeviceId();
const appName = "SSO-Auth";
const appVersion = "0.0.0.9000";
const capabilities = {};

const current_server = credentials
  .credentials()
  .Servers.find((e) => e.LocalAddress == server || e.ManualAddress == server);

const localApiClient = new jellyfinApiclient.ApiClient(
  server,
  appName,
  appVersion,
  deviceName,
  deviceId,
);
localApiClient.setAuthenticationInfo(
  current_server.AccessToken,
  current_server.UserId,
);

const connections = new jellyfinApiclient.ConnectionManager(
  credentials,
  appName,
  appVersion,
  deviceName,
  deviceId,
  capabilities,
);

connections.addApiClient(localApiClient);

window.ApiClient = localApiClient;

export default localApiClient;
