// Provider templates (#726) — the single source of truth for the "Start from a template" pickers.
// Applying a preset writes ONLY into existing marker-classed fields by their id (OpenID: the property
// name; SAML: "saml-" + the property name) and pre-checks ONLY the compatibility toggles a given IdP
// genuinely needs. Presets are plain data so they are trivial to extend and to lock in with a fitness
// test (ProviderPresets_* in ArchitectureConformanceTests): every `fields` key / `toggles` entry must be
// a real config property, no preset may fill a secret, and toggles may only pre-check a known
// compatibility toggle. `fields` values are non-secret placeholders — endpoints use an example host and
// UPPERCASE tokens the admin replaces (realm/tenant/domain), never a hard-coded production host, so they
// never go stale. OidScopes holds the ADDITIONAL scopes only (one per line) — the server always prepends
// "openid profile", so a preset lists just what a provider needs on top (e.g. "email", or "email\ngroups"
// where roles ride a groups scope), never "openid"/"profile" again. Every OpenID preset sets the SAME four
// fields (blank where a provider has none), so switching templates is idempotent — no stale value survives;
// ProviderPresets_OidcPresetsShareTheSameFieldKeySet locks that shared-key-set invariant in.
const OIDC_PRESETS = {
  keycloak: {
    label: "Keycloak",
    note: "Keycloak realm client with the default mappers. Roles come from realm_access.roles (or resource_access.<clientId>.roles for client roles). Replace YOUR_REALM in the endpoint.",
    fields: {
      OidEndpoint:
        "https://keycloak.example.com/realms/YOUR_REALM/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "realm_access.roles",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  authelia: {
    label: "Authelia",
    note: "Authelia OpenID Connect provider. Groups are exposed via the `groups` claim (add the `groups` scope in Authelia). Pushed Authorization Requests are disabled here because some Authelia versions do not support them.",
    fields: {
      OidEndpoint: "https://auth.example.com/.well-known/openid-configuration",
      OidScopes: "email\ngroups",
      RoleClaim: "groups",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: ["DisablePushedAuthorization"],
  },
  authentik: {
    label: "Authentik",
    note: "Authentik OAuth2/OpenID provider application. Groups are exposed via the `groups` claim. Replace YOUR_APP_SLUG in the endpoint with the application slug.",
    fields: {
      OidEndpoint:
        "https://authentik.example.com/application/o/YOUR_APP_SLUG/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "groups",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  entra: {
    label: "Microsoft Entra ID (Azure AD)",
    note: "Entra ID app registration. App roles come from the `roles` claim (assign them under the app registration). Replace YOUR_TENANT_ID in the endpoint.",
    fields: {
      OidEndpoint:
        "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "roles",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  google: {
    label: "Google",
    note: "Google issues no group or role claim, so Roles is left blank — grant access with folder/role mapping or leave it open. Endpoint validation is relaxed because Google's discovery document does not list every endpoint the strict check expects.",
    fields: {
      OidEndpoint:
        "https://accounts.google.com/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "",
      DefaultUsernameClaim: "email",
    },
    toggles: ["DoNotValidateEndpoints"],
  },
  auth0: {
    label: "Auth0",
    note: "Auth0 application. Roles require a custom claim added by an Auth0 Action/Rule under a namespace you choose — set RoleClaim to that namespaced claim (e.g. https://your-app/roles). Replace YOUR_TENANT in the endpoint.",
    fields: {
      OidEndpoint:
        "https://YOUR_TENANT.us.auth0.com/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "",
      DefaultUsernameClaim: "nickname",
    },
    toggles: [],
  },
  okta: {
    label: "Okta",
    note: "Okta OIDC app. Groups come from the `groups` claim (add a groups claim + the `groups` scope in the Okta authorization server). Replace YOUR_DOMAIN in the endpoint.",
    fields: {
      OidEndpoint:
        "https://YOUR_DOMAIN.okta.com/.well-known/openid-configuration",
      OidScopes: "email\ngroups",
      RoleClaim: "groups",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  gitlab: {
    label: "GitLab",
    note: "GitLab as an OpenID provider. Direct group paths come from the `groups_direct` claim. For self-managed GitLab, replace gitlab.com in the endpoint with your host.",
    fields: {
      OidEndpoint: "https://gitlab.com/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "groups_direct",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
  "generic-oidc": {
    label: "Generic OpenID Connect",
    note: "A standards-compliant OpenID provider. Point the endpoint at its discovery document and set the role claim to whatever your IdP issues (often `groups` or `roles`).",
    fields: {
      OidEndpoint: "https://idp.example.com/.well-known/openid-configuration",
      OidScopes: "email",
      RoleClaim: "",
      DefaultUsernameClaim: "preferred_username",
    },
    toggles: [],
  },
};

const SAML_PRESETS = {
  "generic-saml": {
    label: "Generic SAML 2.0",
    note: "A generic SAML 2.0 identity provider. Use the metadata import below to fill the SSO endpoint and signing certificate from your IdP's metadata, then set the SAML Client ID (this service provider's entity id) and review before saving.",
    fields: {
      SamlEndpoint: "https://idp.example.com/sso/saml",
    },
    toggles: [],
  },
};

// The compatibility/insecure toggles a preset is ALLOWED to pre-check. A preset never pre-checks a
// fail-closed HARDENING toggle (RequirePkce, RequireVerifiedEmail*, RequireAcr, SAML ValidateRecipient/
// ValidateInResponseTo/SignAuthnRequests) — enabling those is a deliberate admin decision, and silently
// turning them on could lock out a not-yet-ready IdP. This set is also what applyOidcPreset/applySamlPreset
// clear before applying, so switching templates never leaves a previous preset's toggle checked.
const OIDC_PRESET_MANAGED_TOGGLES = [
  "DisablePushedAuthorization",
  "DoNotValidateEndpoints",
  "DoNotValidateIssuerName",
  "DoNotValidateResponseIssuer",
  "DisableHttps",
  "DoNotLoadProfile",
];
const SAML_PRESET_MANAGED_TOGGLES = ["DoNotValidateAudience"];

const ssoConfigurationPage = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",
  // Toggles that disable an OpenID Connect security defense. An active one is a downgrade the admin must
  // not miss, so loading a provider with any of these expands the "Insecure options" list and its
  // enclosing "Security & hardening" accordion.
  insecureFieldIds: [
    "DisableHttps",
    "DisablePushedAuthorization",
    "DoNotValidateEndpoints",
    "DoNotValidateIssuerName",
    "DoNotValidateResponseIssuer",
  ],
  // The non-insecure settings whose ENABLED state is still a downgrade / attack-surface widening, so they
  // are surfaced the same way as the insecure toggles (card "Review" flag + auto-expand the enclosing
  // accordion). Only AllowExistingAccountLink qualifies: turning it ON lets a first SSO login adopt (take
  // over) a same-named local account. Deliberately EXCLUDES the fail-closed hardening toggles
  // (RequireVerifiedEmailForAdoption, RequireVerifiedEmailForLogin, RequirePkce): those are OFF by default
  // and enabling them makes the provider MORE secure, so flagging or force-surfacing them would be
  // backwards and would cause alert fatigue on well-configured providers. Do not add an OFF-direction
  // surfacing for them either — it would be noisy on the default.
  sensitiveFieldIds: ["AllowExistingAccountLink"],
  loadConfiguration: (page) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        ssoConfigurationPage.populateProviders(page, config.OidConfigs);
        // Refresh the SAML workspace from the same configuration load (#725), so a SAML save/delete/import
        // reloads its provider list exactly as the OpenID one does.
        ssoConfigurationPage.populateSamlProviders(
          page,
          config.SamlConfigs || {},
        );
        // The GLOBAL login-page buttons opt-in (#722) rides the same configuration load. It is a root
        // PluginConfiguration flag, not a provider field, so it has its own save path (saveLoginButtons)
        // and no sso-* marker class.
        page.querySelector("#ManageLoginPageButtons").checked = Boolean(
          config.ManageLoginPageButtons,
        );
      },
    );

    const folder_container = page.querySelector("#EnabledFolders");
    ssoConfigurationPage.populateFolders(folder_container);
    // The SAML editor has its own available-folders checklist; populate it too (#725).
    const saml_folder_container = page.querySelector("#saml-EnabledFolders");
    if (saml_folder_container) {
      ssoConfigurationPage.populateFolders(saml_folder_container);
    }
  },
  populateProviders: (page, providers) => {
    const select = page.querySelector("#selectProvider");

    // Clear providers in case there are out of date ones
    select.querySelectorAll("option").forEach((option) => option.remove());

    // Add providers as options for the (hidden) selector. The selector is retained as the state holder the
    // save path already reads (saveProvider sets its value after a save); the visible affordance is the card
    // list rendered below.
    Object.keys(providers).forEach((provider_name) => {
      select.appendChild(new Option(provider_name, provider_name));
    });

    ssoConfigurationPage.renderProviderCards(page, providers);
  },
  // Render the provider LIST as cards (#365). Built with createElement/textContent (never innerHTML) so a
  // provider name is inert on the page — a name like `<img onerror=...>` cannot inject markup — mirroring
  // _populateFolders and the linking view (#221). Clicking a card loads that provider into the editor.
  renderProviderCards: (page, providers) => {
    const list = page.querySelector("#sso-provider-list");
    const empty = page.querySelector("#sso-provider-empty");
    list.replaceChildren();

    const names = Object.keys(providers);
    empty.hidden = names.length !== 0;

    names.forEach((provider_name) => {
      const provider = providers[provider_name] || {};

      const card = document.createElement("button");
      card.type = "button";
      card.classList.add("sso-provider-card");
      card.dataset.provider = provider_name;
      card.setAttribute("role", "listitem");

      const name = document.createElement("span");
      name.classList.add("sso-provider-card-name");
      name.textContent = provider_name;

      const badge = document.createElement("span");
      badge.classList.add("sso-badge", "sso-badge-type");
      badge.textContent = "OIDC";

      const enabled = Boolean(provider.Enabled);
      const pill = document.createElement("span");
      pill.classList.add(
        "sso-pill",
        enabled ? "sso-pill-enabled" : "sso-pill-disabled",
      );
      pill.textContent = enabled ? "Enabled" : "Disabled";

      card.append(name, badge, pill);

      // Flag a provider that carries an active insecure / sensitive setting, so an admin sees the downgrade
      // in the list without opening the editor (the setting itself lives behind the collapsed
      // "Security & hardening" accordion). Presentation only — the flag reads from the saved config and
      // changes nothing.
      const flagged = ssoConfigurationPage.insecureFieldIds
        .concat(ssoConfigurationPage.sensitiveFieldIds)
        .some((id) => Boolean(provider[id]));
      if (flagged) {
        card.classList.add("sso-provider-card-flagged");
        const warn = document.createElement("span");
        warn.classList.add("sso-badge", "sso-badge-warn");
        warn.textContent = "Review";
        warn.title =
          "This provider has an active insecure or sensitive setting.";
        card.append(warn);
      }

      list.appendChild(card);
    });
  },
  showEditor: (page) => {
    page.querySelector("#sso-editor").hidden = false;
  },
  hideEditor: (page) => {
    page.querySelector("#sso-editor").hidden = true;
  },
  setEditorTitle: (page, title) => {
    page.querySelector("#sso-editor-title").textContent = title;
  },
  // Load a card into the editor and reveal it. resetEditor gives a CLEAN SLATE first (the same way
  // addProvider does) so no field, toggle, or collapse state from the previously loaded provider can bleed
  // into this one — a text/array field the target provider does not set must not keep the previous
  // provider's value, or a later save would silently persist it (e.g. repoint OidEndpoint with no edit).
  // loadProvider then fills the target provider's actual values on top and re-syncs visibility at its tail.
  openProvider: (page, provider_name) => {
    page.querySelector("#selectProvider").value = provider_name;
    ssoConfigurationPage.resetEditor(page);
    ssoConfigurationPage.clearValidationErrors(page);
    ssoConfigurationPage.renderSaveStatus(page, "");
    ssoConfigurationPage.setEditorTitle(page, provider_name);
    ssoConfigurationPage.showEditor(page);
    ssoConfigurationPage.loadProvider(page, provider_name);
    page.querySelector("#sso-editor").scrollIntoView({ block: "start" });
  },
  // Open a blank editor for a NEW provider. Every toggle is reset OFF (fail closed) — the same security
  // posture loadProvider enforces when switching providers, so a stale insecure toggle from a previous
  // edit can never be carried into a new provider and silently saved.
  addProvider: (page) => {
    page.querySelector("#selectProvider").value = "";
    ssoConfigurationPage.resetEditor(page);
    ssoConfigurationPage.clearValidationErrors(page);
    ssoConfigurationPage.renderSaveStatus(page, "");
    ssoConfigurationPage.setEditorTitle(page, "New provider");
    ssoConfigurationPage.syncDependentFields(page);
    ssoConfigurationPage.showEditor(page);
    page.querySelector("#sso-editor").scrollIntoView({ block: "start" });
    page.querySelector("#OidProviderName").focus();
  },
  resetEditor: (page) => {
    const form_elements = ssoConfigurationPage.listArgumentsByType(page);

    page.querySelector("#OidProviderName").value = "";

    form_elements.text_fields.forEach((id) => {
      page.querySelector("#" + id).value = "";
    });
    form_elements.text_list_fields.forEach((id) => {
      page.querySelector("#" + id).value = "";
    });
    form_elements.check_fields.forEach((id) => {
      page.querySelector("#" + id).checked = false;
    });
    form_elements.folder_list_fields.forEach((id) => {
      ssoConfigurationPage.populateEnabledFolders(
        [],
        page.querySelector("#" + id),
      );
    });
    form_elements.role_map_fields.forEach((id) => {
      ssoConfigurationPage.populateRoleMappings(
        [],
        page.querySelector("#" + id),
      );
    });

    // Clean slate for progressive disclosure and collapse state, so a previous provider's expanded danger
    // zone / accordion state cannot bleed into the next provider. Collapse the "Insecure options" list,
    // return every editor accordion to its authored default (data-expanded), then re-sync the
    // reveal-on-toggle groups now that every controlling toggle is off. loadProvider (openProvider) and the
    // explicit syncDependentFields (addProvider) re-expand only what the loaded/new provider actually needs.
    ssoConfigurationPage.setInsecureOptionsExpanded(page, false);
    ssoConfigurationPage.resetEditorSections(page);
    ssoConfigurationPage.syncDependentFields(page);
    // Clear the computed redirect URI back to its placeholder for the fresh/blank editor (#724).
    ssoConfigurationPage.updateRedirectUri(page);
    // Reset the template picker + its note so opening/adding a provider never shows a stale template (#726).
    const oidPreset = page.querySelector("#OidPreset");
    if (oidPreset) {
      oidPreset.value = "";
    }
    ssoConfigurationPage.renderPresetNote(page, "OidPreset-note", "");
  },
  // Return every accordion section INSIDE the editor to its authored default collapse state (the sections
  // with data-expanded="true" open, the rest — including "Security & hardening" — collapsed). Scoped to
  // #sso-editor so the page-level About / Export collapses are untouched.
  resetEditorSections: (page) => {
    const editor = page.querySelector("#sso-editor");
    if (!editor) {
      return;
    }
    editor.querySelectorAll('[is="emby-collapse"]').forEach((section) => {
      ssoConfigurationPage.setCollapseExpanded(
        section,
        section.getAttribute("data-expanded") === "true",
      );
    });
  },
  // Drive an emby-collapse to a definite expanded/collapsed state. The host component tracks its open state
  // as the boolean `expanded` PROPERTY on its `.collapseContent` element and flips it by a click of the
  // generated `.emby-collapsible-button` (its own click handler runs the slide + hide-class toggle). We read
  // that property and click only when it differs from the target, so this is idempotent — clicking an
  // already-open section would wrongly collapse it. Null-guarded so it degrades to a no-op (rather than
  // throwing) if the section has not been upgraded yet or the host markup changes.
  setCollapseExpanded: (section, expanded) => {
    const button = section.querySelector(".emby-collapsible-button");
    const content = section.querySelector(".collapseContent");
    if (!button || !content) {
      return;
    }
    if (Boolean(content.expanded) !== expanded) {
      button.click();
    }
  },
  setSectionExpanded: (page, sectionId, expanded) => {
    const section = page.querySelector("#" + sectionId);
    if (!section) {
      return;
    }
    ssoConfigurationPage.setCollapseExpanded(section, expanded);
  },
  // Keep reveal-on-toggle groups in sync with their controlling checkbox. Presentation ONLY: it toggles the
  // `hidden` attribute on wrapper elements and never mutates a field's value or `.checked`, so every marked
  // field stays in the DOM and serializable (the hide-not-remove invariant, #365). The save path enumerates
  // the fields with querySelectorAll regardless of whether their group is hidden.
  setDependent: (page, checkboxId, groupId, revealWhenChecked) => {
    const checkbox = page.querySelector("#" + checkboxId);
    const group = page.querySelector("#" + groupId);
    if (!checkbox || !group) {
      return;
    }
    const reveal = revealWhenChecked ? checkbox.checked : !checkbox.checked;
    group.hidden = !reveal;
    checkbox.setAttribute("aria-expanded", String(reveal));
  },
  syncDependentFields: (page) => {
    // EnabledFolders is only meaningful when NOT all folders are enabled.
    ssoConfigurationPage.setDependent(
      page,
      "EnableAllFolders",
      "EnabledFolders-group",
      false,
    );
    ssoConfigurationPage.setDependent(
      page,
      "EnableFolderRoles",
      "FolderRoleMapping-group",
      true,
    );
    ssoConfigurationPage.setDependent(
      page,
      "EnableLiveTvRoles",
      "LiveTvRoles-group",
      true,
    );

    // Surface active insecure / sensitive settings so an admin cannot miss that a security defense is
    // disabled or an account-adoption path is widened. The "Security & hardening" accordion is collapsed by
    // default, and the insecure toggles are additionally behind a "Show insecure options" list, so a
    // downgrade on a loaded provider would otherwise be invisible behind two collapsed layers. Expand BOTH
    // the enclosing accordion section AND, for the insecure subset, the inner list. Expand-only — it never
    // AUTO-HIDES a set option; resetEditor returns the section to its default when switching to a provider
    // that has none.
    const isChecked = (id) => {
      const el = page.querySelector("#" + id);
      return Boolean(el && el.checked);
    };
    const anyInsecure = ssoConfigurationPage.insecureFieldIds.some(isChecked);
    const anySensitive =
      anyInsecure || ssoConfigurationPage.sensitiveFieldIds.some(isChecked);
    if (anyInsecure) {
      ssoConfigurationPage.setInsecureOptionsExpanded(page, true);
    }
    if (anySensitive) {
      ssoConfigurationPage.setSectionExpanded(
        page,
        "sso-security-section",
        true,
      );
    }
  },
  setInsecureOptionsExpanded: (page, expanded) => {
    const button = page.querySelector("#ShowInsecureOptions");
    const options = page.querySelector("#sso-insecure-options");
    if (!button || !options) {
      return;
    }
    options.hidden = !expanded;
    button.setAttribute("aria-expanded", String(expanded));
    button.querySelector("span").textContent = expanded
      ? "Hide insecure options"
      : "Show insecure options";
  },
  // On-blur inline validation (#365). These are pre-emptive WARNINGS that mirror the server's fail-closed
  // checks, surfaced beside the field before the round-trip; they never block the save (the server remains
  // the authority), so a false positive cannot lock an admin out of saving.
  clearValidationErrors: (page) => {
    [
      "OidProviderName",
      "OidEndpoint",
      "OidClientId",
      "RoleClaim",
      "OidScopes",
      "BaseUrlOverride",
    ].forEach((id) => ssoConfigurationPage.setFieldError(page, id, ""));
  },
  setFieldError: (page, id, message) => {
    const field = page.querySelector("#" + id);
    const box = page.querySelector("#" + id + "-error");
    if (!box || !field) {
      return;
    }
    if (message) {
      box.textContent = message;
      box.hidden = false;
      field.setAttribute("aria-invalid", "true");
    } else {
      box.textContent = "";
      box.hidden = true;
      field.removeAttribute("aria-invalid");
    }
  },
  validateRequired: (page, id, label) => {
    const value = page.querySelector("#" + id).value.trim();
    ssoConfigurationPage.setFieldError(
      page,
      id,
      value ? "" : label + " is required.",
    );
  },
  validateEndpoint: (page) => {
    const value = page.querySelector("#OidEndpoint").value.trim();
    if (!value) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        "OpenID Endpoint is required.",
      );
      return;
    }
    let url;
    try {
      url = new URL(value);
    } catch (e) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        "Enter an absolute URL, e.g. https://id.example.com",
      );
      return;
    }
    if (url.protocol === "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        "Uses http:// — discovery would be unencrypted. Prefer an https:// endpoint.",
      );
      return;
    }
    if (url.protocol !== "https:") {
      ssoConfigurationPage.setFieldError(
        page,
        "OidEndpoint",
        "Use an https:// URL for the OpenID endpoint.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "OidEndpoint", "");
  },
  validateBaseUrl: (page) => {
    const value = page.querySelector("#BaseUrlOverride").value.trim();
    if (!value) {
      // Optional field: blank is valid (the redirect URI then derives from the request host).
      ssoConfigurationPage.setFieldError(page, "BaseUrlOverride", "");
      return;
    }
    let url;
    try {
      url = new URL(value);
    } catch (e) {
      ssoConfigurationPage.setFieldError(
        page,
        "BaseUrlOverride",
        "Enter a full origin such as https://jellyfin.example.com (scheme + host only).",
      );
      return;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "BaseUrlOverride",
        "Enter a full origin such as https://jellyfin.example.com",
      );
      return;
    }
    // Full origin only — no path, query or fragment (this is the base URL, not the redirect URI).
    if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
      ssoConfigurationPage.setFieldError(
        page,
        "BaseUrlOverride",
        "Enter the base URL only (no path) — e.g. https://jellyfin.example.com, not the /sso/... redirect URI.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "BaseUrlOverride", "");
  },
  validateProviderName: (page) => {
    const value = page.querySelector("#OidProviderName").value;
    if (!value.trim()) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidProviderName",
        "A provider name is required.",
      );
      return;
    }
    // Mirror the server's fail-closed name checks (#336/#360) so they surface before the round-trip.
    // Control characters are detected by code point (not a regex escape) to keep this source ASCII-only.
    const hasControlChar = [...value].some((ch) => {
      const code = ch.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    });
    if (hasControlChar) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidProviderName",
        "Remove control characters (such as a tab or newline, often introduced by copy-paste) from the name.",
      );
      return;
    }
    // The backslash and the URI-reserved characters the server rejects.
    const reserved = ["\\", "/", "?", "#", "%"];
    if (reserved.some((c) => value.includes(c))) {
      ssoConfigurationPage.setFieldError(
        page,
        "OidProviderName",
        "Remove backslash and URI-reserved characters (\\ / ? # %) from the name.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "OidProviderName", "");
  },
  renderSaveStatus: (page, message, ok) => {
    const box = page.querySelector("#sso-save-status");
    if (!box) {
      return;
    }
    box.textContent = message || "";
    box.classList.remove("sso-status-ok", "sso-status-fail");
    if (message) {
      box.classList.add(ok ? "sso-status-ok" : "sso-status-fail");
    }
  },
  populateEnabledFolders: (folder_list, container) => {
    container.querySelectorAll(".folder-checkbox").forEach((e) => {
      e.checked = folder_list.includes(e.dataset.id);
    });
  },
  serializeEnabledFolders: (container) => {
    return [...container.querySelectorAll(".folder-checkbox")]
      .filter((e) => e.checked)
      .map((e) => {
        return e.dataset.id;
      });
  },
  populateFolders: (container) => {
    return ApiClient.getJSON(
      ApiClient.getUrl("Library/MediaFolders", {
        IsHidden: false,
      }),
    ).then((folders) => {
      ssoConfigurationPage._populateFolders(container, folders);
    });
  },
  /*
  container: html element
  folders.Items: array of objects, with .Id & .Name
  */
  _populateFolders: (container, folders) => {
    container
      .querySelectorAll(".emby-checkbox-label")
      .forEach((e) => e.remove());

    const checkboxes = folders.Items.map((folder) => {
      // The library folder Name/Id come from the Jellyfin core API; build the row with
      // createElement/textContent (never innerHTML) so a folder named e.g. `<img onerror=...>`
      // stays inert on the config page (#221). Mirrors linking.js populateExistingLinks.
      const out = document.createElement("label");
      // Tag the row with the class the re-render cleanup (querySelectorAll above) removes, so a
      // second populate deterministically clears the old rows instead of relying on the
      // emby-checkbox upgrade to add it — otherwise folder IDs could be duplicated on re-populate.
      out.classList.add("emby-checkbox-label");

      // createElement's `is` option upgrades the customized built-in; the attribute is set as well
      // so CSS attribute selectors and the web-components polyfill see it.
      const checkbox = document.createElement("input", { is: "emby-checkbox" });
      checkbox.setAttribute("is", "emby-checkbox");
      checkbox.classList.add("folder-checkbox", "chkFolder");
      checkbox.type = "checkbox";
      checkbox.dataset.id = folder.Id;

      const label = document.createElement("span");
      label.textContent = folder.Name;

      out.append(checkbox, label);

      return out;
    });

    checkboxes.forEach((e) => {
      container.appendChild(e);
    });
  },

  populateRoleMappings: (folder_role_mappings, container) => {
    container
      .querySelectorAll(".sso-role-mapping-container")
      .forEach((e) => e.remove());

    const mapping_elements = folder_role_mappings.map((mapping) => {
      const elem = document.createElement("div");

      elem.classList.add("sso-role-mapping-container");
      elem.innerHTML = `
      <label
        class="inputLabel inputLabelUnfocused sso-role-mapping-input-label"
      >Role:</label>
      <div class="listItem">
        <input
          is="emby-input"
          required=""
          type="text"
          class="listItemBody sso-role-mapping-name"
        />
        <button
          type="button"
          is="paper-icon-button-light"
          class="listItemButton sso-remove-role-mapping"
        >
          <span class="material-icons remove_circle" aria-hidden="true"></span>
        </button>
      </div>
      <div
        class="checkboxList paperList sso-folder-list"
      ></div>
      `;

      const checklist = elem.querySelector(".sso-folder-list");
      const enabled_folders = mapping["Folders"];

      ssoConfigurationPage
        .populateFolders(checklist)
        .then(() =>
          ssoConfigurationPage.populateEnabledFolders(
            enabled_folders,
            checklist,
          ),
        );

      elem.querySelector(".sso-role-mapping-name").value = mapping["Role"];
      elem
        .querySelector(".sso-remove-role-mapping")
        .addEventListener(
          "click",
          ssoConfigurationPage.handleRoleMappingRemove,
        );

      return elem;
    });

    mapping_elements.forEach((e) => container.appendChild(e));
  },
  serializeRoleMappings: (container) => {
    const out = [];
    [...container.querySelectorAll(".sso-role-mapping-container")].forEach(
      (elem) => {
        const role = elem.querySelector(".sso-role-mapping-name").value;
        const checklist = elem.querySelector(".sso-folder-list");

        out.push({
          Role: role,
          Folders: ssoConfigurationPage.serializeEnabledFolders(checklist),
        });
      },
    );

    return out;
  },
  handleRoleMappingRemove: (evt) => {
    const targeted_mapping = evt.target.closest(".sso-role-mapping-container");
    targeted_mapping.remove();
  },
  // The provider form's save contract, made explicit (#365): every input in #sso-new-oidc-provider
  // that should persist carries an sso-* class AND an id spelled EXACTLY like the OidConfig property it
  // writes to (saveProvider does current_config[element.id] = value). A field with the wrong id, a
  // missing sso-* class, or placed outside this form renders fine but silently never saves — and the
  // server drops unknown JSON members too. The ArchitectureConformanceTests
  // ProviderFormFieldIds_MatchOidConfigProperties test locks this in: it fails the build if any
  // sso-*-classed field id is not a real OidConfig property.
  listArgumentsByType: (page) => {
    const toggle_class = ".sso-toggle";
    const text_class = ".sso-text";
    const text_list_class = ".sso-line-list";

    const folder_list_fields = ["EnabledFolders"];
    const role_map_fields = ["FolderRoleMapping"];

    const oidc_form = page.querySelector("#sso-new-oidc-provider");

    const text_fields = [...oidc_form.querySelectorAll(text_class)].map(
      (e) => e.id,
    );

    const text_list_fields = [
      ...oidc_form.querySelectorAll(text_list_class),
    ].map((e) => e.id);

    const check_fields = [...oidc_form.querySelectorAll(toggle_class)].map(
      (e) => e.id,
    );

    const output = {
      text_list_fields,
      text_fields,
      check_fields,
      folder_list_fields,
      role_map_fields,
    };

    return output;
  },
  fillTextList: (text_list, element) => {
    // text_list is an array of strings
    // element is an input element
    const val = text_list.join("\r\n");
    element.value = val;
  },
  parseTextList: (element) => {
    // Return the parsed text list
    const out = element.value
      .split("\n")
      .map((e) => e.trim())
      .filter(Boolean);
    return out;
  },
  loadProvider: (page, provider_name) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        const provider = config.OidConfigs[provider_name] || {};

        const form_elements = ssoConfigurationPage.listArgumentsByType(page);

        page.querySelector("#OidProviderName").value = provider_name;

        form_elements.text_fields.forEach((id) => {
          if (provider[id]) page.querySelector("#" + id).value = provider[id];
        });

        form_elements.text_list_fields.forEach((id) => {
          if (provider[id])
            ssoConfigurationPage.fillTextList(
              provider[id],
              page.querySelector("#" + id),
            );
        });

        form_elements.folder_list_fields.forEach((id) => {
          if (provider[id]) {
            ssoConfigurationPage.populateEnabledFolders(
              provider[id],
              page.querySelector(`#${id}`),
            );
          }
        });

        form_elements.check_fields.forEach((id) => {
          // Always set the checkbox from the loaded provider so switching providers
          // resets stale toggles. Setting it only when truthy left a previous
          // provider's checked box in place, which a later save could silently
          // persist as true — a security downgrade for toggles like
          // DoNotValidateEndpoints / DisableHttps.
          page.querySelector("#" + id).checked = Boolean(provider[id]);
        });

        form_elements.role_map_fields.forEach((id) => {
          const elem = page.querySelector(`#${id}`);
          if (provider[id])
            ssoConfigurationPage.populateRoleMappings(provider[id], elem);
        });

        // Reflect the loaded toggles in the reveal-on-toggle groups (hide-not-remove) and surface any
        // active insecure option. Runs after the check_fields above are set from the loaded provider, so a
        // hidden-but-checked box is never left behind for the next save.
        ssoConfigurationPage.syncDependentFields(page);
        // Reflect the loaded provider's name + base-URL override in the computed redirect URI (#724).
        ssoConfigurationPage.updateRedirectUri(page);
      },
    );
  },
  // Computes the exact redirect_uri the login uses, so the admin can register it verbatim at the IdP (#724).
  // Mirrors the server-side build (OidcRedirectUriBuilder): the canonical base — the Base URL Override when
  // set, else this server's address — plus the fixed /sso/OID/redirect/<provider> path. The provider name is
  // appended raw (names are validated to exclude URI-reserved characters, #336), matching the server, which
  // appends the route-decoded name without re-encoding so the string equals the login's byte-for-byte.
  computeRedirectUri: (page, providerName) => {
    const override = page.querySelector("#BaseUrlOverride").value.trim();
    const raw = override || ApiClient.serverAddress() || "";
    let base;
    try {
      // Mirror the server's CanonicalBaseUrl (System.Uri.GetLeftPart(UriPartial.Path)) so the shown value
      // equals what the login sends: `origin` lowercases scheme + host AND elides the default port
      // (443/80) — exactly as System.Uri does — while pathname keeps any sub-path; query/fragment are
      // dropped and the trailing slash trimmed. A raw string strip alone would show a non-canonical override
      // (e.g. `https://X.COM:443`) that the login then normalizes away, causing a redirect_uri mismatch.
      const u = new URL(raw);
      base = u.origin + u.pathname.replace(/\/+$/, "");
    } catch (e) {
      // Not a parseable absolute URL yet (admin mid-typing, or a bare host): best-effort fall back to the
      // raw value with only trailing slashes stripped so the field still shows something.
      base = raw.replace(/\/+$/, "");
    }
    return base + "/sso/OID/redirect/" + providerName;
  },
  // Live-updates the read-only redirect-URI field; empty (placeholder) until a provider name is entered. Sets
  // .value only (never innerHTML, #221). Called on name/override input, on load, on reset, and at init.
  updateRedirectUri: (page) => {
    const field = page.querySelector("#OidRedirectUri");
    if (!field) {
      return;
    }
    const name = page.querySelector("#OidProviderName").value.trim();
    field.value = name
      ? ssoConfigurationPage.computeRedirectUri(page, name)
      : "";
    field.placeholder = name
      ? ""
      : "Enter a provider name above to see the redirect URI";
    // A name/override change invalidates any previous "copied" confirmation.
    const status = page.querySelector("#OidRedirectUri-copied");
    if (status) {
      status.textContent = "";
    }
  },
  copyRedirectUri: (page) => {
    const field = page.querySelector("#OidRedirectUri");
    const status = page.querySelector("#OidRedirectUri-copied");
    const value = field && field.value;
    if (!value) {
      return;
    }
    const announce = (message) => {
      if (status) {
        status.textContent = message;
      }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        () => announce("Redirect URI copied to the clipboard."),
        () => announce("Copy failed — select the field and copy it manually."),
      );
      return;
    }
    // Fallback for a non-secure context without the async Clipboard API.
    field.removeAttribute("readonly");
    field.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    field.setAttribute("readonly", "");
    announce(
      ok
        ? "Redirect URI copied to the clipboard."
        : "Copy failed — select the field and copy it manually.",
    );
  },
  deleteProvider: (page, provider_name) => {
    if (
      !window.confirm(
        `Are you sure you want to delete the provider ${provider_name}?`,
      )
    ) {
      return;
    }
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        if (!config.OidConfigs.hasOwnProperty(provider_name)) {
          return;
        }

        delete config.OidConfigs[provider_name];
        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            // The deleted provider is gone from the list; close its now-stale editor.
            ssoConfigurationPage.hideEditor(page);

            Dashboard.alert("Provider removed");
          },
          // Report a genuine save failure rather than swallowing it. The delete
          // re-posts the whole configuration, so the server can now reject it for
          // a reason unrelated to this delete — e.g. a different provider whose
          // reserved-character name became "new" because it was removed from the
          // live config in the meantime (#336). Without this the PUT would reject
          // silently and the provider would appear undeleted with no explanation.
          function () {
            Dashboard.alert({
              title: "Delete failed",
              message:
                "Could not remove the provider. The saved configuration was rejected by the server; reload the page and try again.",
            });
          },
        );
      },
    );
  },
  // Save the GLOBAL login-page buttons opt-in (#722). ManageLoginPageButtons is a root
  // PluginConfiguration flag, so this fetches the live configuration, changes ONLY this flag, and
  // re-posts the whole document — the provider dictionaries and every other root setting ride along
  // unchanged, exactly as the provider save/delete paths do. The server reacts to the saved
  // configuration itself (LoginButtonManager listens for the configuration change), so no extra
  // endpoint call is needed: on save the managed block is injected/refreshed, or — with the flag
  // off — only the managed region is removed and the admin's own branding is preserved.
  saveLoginButtons: (page) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        config.ManageLoginPageButtons = page.querySelector(
          "#ManageLoginPageButtons",
        ).checked;

        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            Dashboard.alert("Settings saved.");
          },
          // Report a genuine save failure rather than swallowing it: this PUT re-posts the whole
          // configuration, so the server can reject it for a reason unrelated to this toggle (#336).
          function () {
            Dashboard.alert({
              title: "Save failed",
              message:
                "Could not save the login-page button setting. The saved configuration was rejected by the server; reload the page and try again.",
            });
          },
        );
      },
    );
  },
  saveProvider: (page, provider_name) => {
    return new Promise((resolve, reject) => {
      const form_elements = ssoConfigurationPage.listArgumentsByType(page);

      ApiClient.getPluginConfiguration(
        ssoConfigurationPage.pluginUniqueId,
      ).then((config) => {
        let current_config = {};
        if (config.OidConfigs.hasOwnProperty(provider_name)) {
          current_config = config.OidConfigs[provider_name];
        }

        form_elements.text_fields.forEach((id) => {
          current_config[id] = page.querySelector("#" + id).value || null;
        });

        form_elements.check_fields.forEach((id) => {
          current_config[id] = page.querySelector("#" + id).checked;
        });

        form_elements.text_list_fields.forEach((id) => {
          current_config[id] = ssoConfigurationPage.parseTextList(
            page.querySelector("#" + id),
          );
        });

        form_elements.folder_list_fields.forEach((id) => {
          const elem = page.querySelector(`#${id}`);
          current_config[id] =
            ssoConfigurationPage.serializeEnabledFolders(elem);
        });

        form_elements.role_map_fields.forEach((id) => {
          const elem = page.querySelector(`#${id}`);
          current_config[id] = ssoConfigurationPage.serializeRoleMappings(elem);
        });

        config.OidConfigs[provider_name] = current_config;

        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            ssoConfigurationPage.loadProvider(page, provider_name);

            page.querySelector("#selectProvider").value = provider_name;
            Dashboard.alert("Settings saved.");
            resolve();
          },
          // Rejection handler attached directly to the save call, so it reports only a genuine save
          // failure and not an error thrown by the post-save UI work above. The server can refuse a
          // save for more than one reason (a malformed Base URL Override, #139; a provider name with
          // URI-reserved or control characters, #336/#360), so the message names both checks instead of
          // blaming one.
          function () {
            Dashboard.alert({
              title: "Save failed",
              message:
                "Could not save the provider. Check that the provider name has no control characters (such as a tab or newline, often introduced by copy-paste), no backslash, and none of the URI-reserved characters such as / ? # %, and that the Base URL Override is a full URL such as https://jellyfin.example.com (or blank).",
            });
            reject(new Error("Provider save failed"));
          },
        );
      });
    });
  },
  // Test-connection (#163). Calls the elevation-gated OID/Test endpoint for the SAVED provider and renders
  // the result. The endpoint reads the stored config server-side, fetches the discovery document over the
  // login's hardened path, and returns only non-secret facts (issuer, endpoints, JWKS reachability) — the
  // client secret is never sent back. Everything is rendered with createElement/textContent (never
  // innerHTML) so a reflected issuer/endpoint string cannot inject markup, matching linking.js and
  // _populateFolders (#221).
  testProvider: (page, provider_name) => {
    const container = page.querySelector("#TestResult");
    if (!provider_name) {
      ssoConfigurationPage.renderTestMessage(
        container,
        "Enter a provider name and save it first, then test.",
      );
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTestMessage(container, "Testing…");

    return ApiClient.getJSON(
      ApiClient.getUrl("sso/OID/Test/" + encodeURIComponent(provider_name)),
    ).then(
      (result) => ssoConfigurationPage.renderTestResult(container, result),
      // A rejection is a transport/authorization failure or an unconfigured provider (404). Keep the
      // message generic and actionable — it never reflects a server-side secret.
      () =>
        ssoConfigurationPage.renderTestMessage(
          container,
          "Could not run the test. Make sure the provider is saved and that you are signed in as an administrator, then try again.",
        ),
    );
  },
  renderTestMessage: (container, message) => {
    container.replaceChildren();
    const line = document.createElement("p");
    line.classList.add("fieldDescription");
    line.textContent = message;
    container.appendChild(line);
  },
  renderTestResult: (container, result) => {
    container.replaceChildren();

    const heading = document.createElement("p");
    heading.classList.add("fieldDescription");
    // Boolean coercion, not string interpolation: the label is fixed text, so no server value reaches the DOM here.
    heading.textContent =
      (result && result.Ok ? "✅ " : "⚠ ") +
      (result && result.Message ? result.Message : "No result returned.");
    container.appendChild(heading);

    const details =
      result && Array.isArray(result.Details) ? result.Details : [];
    if (details.length === 0) {
      return;
    }

    const list = document.createElement("ul");
    details.forEach((detail) => {
      const item = document.createElement("li");
      // textContent so an issuer/endpoint value echoed by the provider stays inert on the page.
      item.textContent = String(detail);
      list.appendChild(item);
    });
    container.appendChild(list);
  },
  // Config export (#161). Fetches the redacted export document from the elevation-gated endpoint (the
  // server withholds every secret and account-link map) and saves it as a JSON file via a Blob download —
  // never navigation, so the admin's auth header is sent and no secret is placed in a URL. The filename is
  // fixed text; nothing from the document reaches the DOM as markup.
  exportConfig: (page) => {
    const container = page.querySelector("#ConfigTransferResult");
    ssoConfigurationPage.renderTransferMessage(container, "Exporting…");

    return ApiClient.getJSON(ApiClient.getUrl("sso/Config/Export")).then(
      (document_json) => {
        const blob = new Blob([JSON.stringify(document_json, null, 2)], {
          type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const anchor = window.document.createElement("a");
        anchor.href = url;
        anchor.download = "sso-config-export.json";
        window.document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
        ssoConfigurationPage.renderTransferMessage(
          container,
          "Exported. Provider secrets and account links are redacted from the file.",
        );
      },
      () =>
        ssoConfigurationPage.renderTransferMessage(
          container,
          "Could not export the configuration. Make sure you are signed in as an administrator, then try again.",
        ),
    );
  },
  // Config import (#161). Reads the chosen file as text, parses it locally (a parse error is reported, never
  // applied), and POSTs it to the elevation-gated import endpoint. The server validates and merges it
  // fail-closed, keeping each unchanged provider's stored secret and links (an OpenID provider whose
  // endpoint/client id the import changes has its links/secret cleared — the #186 repoint safety measure).
  // On success the provider list is reloaded so the merged providers appear; the admin re-enters secrets.
  importConfig: (page, file) => {
    const container = page.querySelector("#ConfigTransferResult");
    if (!file) {
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTransferMessage(container, "Importing…");
    return file
      .text()
      .then((text) => {
        let document_json;
        try {
          document_json = JSON.parse(text);
        } catch (e) {
          throw new Error("not-json");
        }

        return ApiClient.fetch({
          type: "POST",
          url: ApiClient.getUrl("sso/Config/Import"),
          data: JSON.stringify(document_json),
          contentType: "application/json",
        });
      })
      .then(() => {
        ssoConfigurationPage.loadConfiguration(page);
        ssoConfigurationPage.renderTransferMessage(
          container,
          "Imported. Re-enter each provider's secret and save it — secrets are never included in an export.",
        );
      })
      .catch((e) => {
        // A local parse failure and a server rejection (an invalid or unsupported document, an expired
        // session) are both fail-closed here: the message is generic and never reflects a server value.
        const message =
          e && e.message === "not-json"
            ? "That file is not valid JSON. Choose a configuration file exported from this plugin."
            : "Could not import the configuration. The file was rejected by the server, or you are not signed in as an administrator.";
        ssoConfigurationPage.renderTransferMessage(container, message);
      });
  },
  renderTransferMessage: (container, message) => {
    container.replaceChildren();
    const line = window.document.createElement("p");
    line.classList.add("fieldDescription");
    line.textContent = message;
    container.appendChild(line);
  },
  addTextAreaStyle: (view) => {
    const style = document.createElement("link");
    style.rel = "stylesheet";
    style.href =
      ApiClient.getUrl("web/configurationpage") + "?name=SSO-Auth.css";
    view.appendChild(style);
  },

  // ---- Provider templates (#726) ----
  // Fill a preset picker's options from its catalog (createElement/textContent — the labels are our own
  // fixed strings, but building them inertly keeps the one-DOM-construction idiom). The leading blank
  // "Choose a template" option authored in the HTML is preserved.
  populatePresetPicker: (page, selectId, presets) => {
    const select = page.querySelector("#" + selectId);
    if (!select) {
      return;
    }
    Object.keys(presets).forEach((key) => {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = presets[key].label;
      select.appendChild(option);
    });
  },
  renderPresetNote: (page, noteId, message) => {
    const box = page.querySelector("#" + noteId);
    if (box) {
      box.textContent = message || "";
    }
  },
  // Apply an OpenID preset onto the editor. Writes ONLY into existing marker-classed fields by their id
  // (every field key is a real OidConfig property, pinned by ProviderPresets_ReferenceOnlyRealOidcProperties)
  // and pre-checks ONLY the listed compatibility toggles. It first clears every preset-managed toggle so
  // switching templates cannot leave a previous preset's toggle checked, never touches the secret, and
  // never saves. syncDependentFields then surfaces any pre-enabled insecure toggle in the auto-expanded
  // danger zone. The provider name and client secret the admin may have typed are left untouched.
  applyOidcPreset: (page, key) => {
    OIDC_PRESET_MANAGED_TOGGLES.forEach((prop) => {
      const el = page.querySelector("#" + prop);
      if (el) {
        el.checked = false;
      }
    });

    const preset = OIDC_PRESETS[key];
    if (!preset) {
      // The blank "choose a template" option: clear the note and re-sync (so a just-cleared toggle
      // collapses its danger-zone surfacing) without altering the admin's fields.
      ssoConfigurationPage.renderPresetNote(page, "OidPreset-note", "");
      ssoConfigurationPage.syncDependentFields(page);
      return;
    }

    Object.keys(preset.fields).forEach((prop) => {
      const el = page.querySelector("#" + prop);
      if (el) {
        el.value = preset.fields[prop];
      }
    });
    preset.toggles.forEach((prop) => {
      const el = page.querySelector("#" + prop);
      if (el) {
        el.checked = true;
      }
    });

    ssoConfigurationPage.syncDependentFields(page);
    ssoConfigurationPage.updateRedirectUri(page);
    ssoConfigurationPage.renderPresetNote(page, "OidPreset-note", preset.note);
  },
  // The SAML counterpart. Field ids are "saml-" + the SamlConfig property; toggles likewise. Same
  // clear-then-apply discipline, and syncSamlDependentFields surfaces a pre-enabled insecure toggle.
  applySamlPreset: (page, key) => {
    SAML_PRESET_MANAGED_TOGGLES.forEach((prop) => {
      const el = page.querySelector("#saml-" + prop);
      if (el) {
        el.checked = false;
      }
    });

    const preset = SAML_PRESETS[key];
    if (!preset) {
      ssoConfigurationPage.renderPresetNote(page, "saml-Preset-note", "");
      ssoConfigurationPage.syncSamlDependentFields(page);
      return;
    }

    Object.keys(preset.fields).forEach((prop) => {
      const el = page.querySelector("#saml-" + prop);
      if (el) {
        el.value = preset.fields[prop];
      }
    });
    preset.toggles.forEach((prop) => {
      const el = page.querySelector("#saml-" + prop);
      if (el) {
        el.checked = true;
      }
    });

    ssoConfigurationPage.syncSamlDependentFields(page);
    ssoConfigurationPage.updateSamlUrls(page);
    ssoConfigurationPage.renderPresetNote(
      page,
      "saml-Preset-note",
      preset.note,
    );
  },

  // ============================================================================
  // SAML provider workspace (#725)
  // ----------------------------------------------------------------------------
  // A lifecycle parallel to the OpenID one above, kept entirely separate so the OpenID workspace and its
  // JS are untouched (there is no JS runtime test harness — the adversarial review is the primary
  // verification, so isolation is the cheapest correctness guarantee). Every SAML persisting field id is
  // its SamlConfig property spelled with a "saml-" PREFIX (ids must be unique across the whole document,
  // and the OpenID fields already own the unprefixed spellings); the property is the id minus that prefix,
  // computed by samlPropOf. ProviderFormFieldIds_MatchSamlConfigProperties fails the build if any
  // saml-*-marked field id (after stripping the prefix) is not a real SamlConfig property, so a field that
  // would silently never save cannot land. The generic element-argument helpers above (setFieldError,
  // populateFolders / populateEnabledFolders / serializeEnabledFolders, populateRoleMappings /
  // serializeRoleMappings, fillTextList / parseTextList, setCollapseExpanded, setDependent,
  // setSectionExpanded, renderTestMessage / renderTestResult) are protocol-agnostic and reused as-is.
  // ============================================================================

  // Toggles/settings whose ENABLED state is a security downgrade the admin must not miss (mirrors
  // insecureFieldIds/sensitiveFieldIds for OpenID). DoNotValidateAudience disables the AudienceRestriction
  // check; AllowExistingAccountLink widens account adoption. Property names (no prefix): the flag is read
  // from the saved config (provider[prop]) and, when checking the live checkbox, queried as "#saml-"+prop.
  // ProvisionNewUsersDisabled is deliberately NOT flagged — it is a fail-closed hardening toggle (ON is
  // MORE secure), so surfacing it would be backwards and cause alert fatigue, exactly as for OpenID.
  samlInsecureFieldIds: ["DoNotValidateAudience"],
  samlSensitiveFieldIds: ["AllowExistingAccountLink"],
  samlPropOf: (id) => id.slice("saml-".length),
  populateSamlProviders: (page, providers) => {
    const select = page.querySelector("#saml-selectProvider");
    select.querySelectorAll("option").forEach((option) => option.remove());
    Object.keys(providers).forEach((provider_name) => {
      select.appendChild(new Option(provider_name, provider_name));
    });
    ssoConfigurationPage.renderSamlProviderCards(page, providers);
  },
  // SAML provider cards — same inert createElement/textContent construction as renderProviderCards (#221):
  // a provider name is never interpolated as markup, so a hostile name stays inert on the page.
  renderSamlProviderCards: (page, providers) => {
    const list = page.querySelector("#saml-provider-list");
    const empty = page.querySelector("#saml-provider-empty");
    list.replaceChildren();

    const names = Object.keys(providers);
    empty.hidden = names.length !== 0;

    names.forEach((provider_name) => {
      const provider = providers[provider_name] || {};

      const card = document.createElement("button");
      card.type = "button";
      card.classList.add("sso-provider-card");
      card.dataset.provider = provider_name;
      card.setAttribute("role", "listitem");

      const name = document.createElement("span");
      name.classList.add("sso-provider-card-name");
      name.textContent = provider_name;

      const badge = document.createElement("span");
      badge.classList.add("sso-badge", "sso-badge-type");
      badge.textContent = "SAML";

      const enabled = Boolean(provider.Enabled);
      const pill = document.createElement("span");
      pill.classList.add(
        "sso-pill",
        enabled ? "sso-pill-enabled" : "sso-pill-disabled",
      );
      pill.textContent = enabled ? "Enabled" : "Disabled";

      card.append(name, badge, pill);

      const flagged = ssoConfigurationPage.samlInsecureFieldIds
        .concat(ssoConfigurationPage.samlSensitiveFieldIds)
        .some((id) => Boolean(provider[id]));
      if (flagged) {
        card.classList.add("sso-provider-card-flagged");
        const warn = document.createElement("span");
        warn.classList.add("sso-badge", "sso-badge-warn");
        warn.textContent = "Review";
        warn.title =
          "This provider has an active insecure or sensitive setting.";
        card.append(warn);
      }

      list.appendChild(card);
    });
  },
  showSamlEditor: (page) => {
    page.querySelector("#saml-editor").hidden = false;
  },
  hideSamlEditor: (page) => {
    page.querySelector("#saml-editor").hidden = true;
  },
  setSamlEditorTitle: (page, title) => {
    page.querySelector("#saml-editor-title").textContent = title;
  },
  // Load a SAML card into the editor. resetSamlEditor gives a clean slate FIRST (same discipline as
  // openProvider) so no field, toggle, or collapse state from the previously loaded provider bleeds into
  // this one and gets silently re-saved.
  openSamlProvider: (page, provider_name) => {
    page.querySelector("#saml-selectProvider").value = provider_name;
    ssoConfigurationPage.resetSamlEditor(page);
    ssoConfigurationPage.clearSamlValidationErrors(page);
    ssoConfigurationPage.renderSamlSaveStatus(page, "");
    ssoConfigurationPage.setSamlEditorTitle(page, provider_name);
    ssoConfigurationPage.showSamlEditor(page);
    ssoConfigurationPage.loadSamlProvider(page, provider_name);
    page.querySelector("#saml-editor").scrollIntoView({ block: "start" });
  },
  addSamlProvider: (page) => {
    page.querySelector("#saml-selectProvider").value = "";
    ssoConfigurationPage.resetSamlEditor(page);
    ssoConfigurationPage.clearSamlValidationErrors(page);
    ssoConfigurationPage.renderSamlSaveStatus(page, "");
    ssoConfigurationPage.setSamlEditorTitle(page, "New provider");
    ssoConfigurationPage.syncSamlDependentFields(page);
    ssoConfigurationPage.showSamlEditor(page);
    page.querySelector("#saml-editor").scrollIntoView({ block: "start" });
    page.querySelector("#saml-provider-name").focus();
  },
  resetSamlEditor: (page) => {
    const form_elements = ssoConfigurationPage.listSamlArgumentsByType(page);

    page.querySelector("#saml-provider-name").value = "";

    form_elements.text_fields.forEach((id) => {
      page.querySelector("#" + id).value = "";
    });
    form_elements.text_list_fields.forEach((id) => {
      page.querySelector("#" + id).value = "";
    });
    form_elements.check_fields.forEach((id) => {
      page.querySelector("#" + id).checked = false;
    });
    form_elements.folder_list_fields.forEach((id) => {
      ssoConfigurationPage.populateEnabledFolders(
        [],
        page.querySelector("#" + id),
      );
    });
    form_elements.role_map_fields.forEach((id) => {
      ssoConfigurationPage.populateRoleMappings(
        [],
        page.querySelector("#" + id),
      );
    });

    ssoConfigurationPage.setSamlInsecureOptionsExpanded(page, false);
    ssoConfigurationPage.resetSamlEditorSections(page);
    ssoConfigurationPage.syncSamlDependentFields(page);
    ssoConfigurationPage.updateSamlUrls(page);
    // Reset the template picker + its note so opening/adding a provider never shows a stale template (#726).
    const samlPreset = page.querySelector("#saml-Preset");
    if (samlPreset) {
      samlPreset.value = "";
    }
    ssoConfigurationPage.renderPresetNote(page, "saml-Preset-note", "");
  },
  // Return every accordion INSIDE the SAML editor to its authored default; scoped to #saml-editor so the
  // OpenID editor and the page-level collapses are untouched.
  resetSamlEditorSections: (page) => {
    const editor = page.querySelector("#saml-editor");
    if (!editor) {
      return;
    }
    editor.querySelectorAll('[is="emby-collapse"]').forEach((section) => {
      ssoConfigurationPage.setCollapseExpanded(
        section,
        section.getAttribute("data-expanded") === "true",
      );
    });
  },
  syncSamlDependentFields: (page) => {
    ssoConfigurationPage.setDependent(
      page,
      "saml-EnableAllFolders",
      "saml-EnabledFolders-group",
      false,
    );
    ssoConfigurationPage.setDependent(
      page,
      "saml-EnableFolderRoles",
      "saml-FolderRoleMapping-group",
      true,
    );
    ssoConfigurationPage.setDependent(
      page,
      "saml-EnableLiveTvRoles",
      "saml-LiveTvRoles-group",
      true,
    );

    // Surface active insecure / sensitive settings behind the collapsed "Security & hardening" accordion
    // (and, for the insecure subset, its inner list) — expand-only, exactly like syncDependentFields.
    const isChecked = (id) => {
      const el = page.querySelector("#saml-" + id);
      return Boolean(el && el.checked);
    };
    const anyInsecure =
      ssoConfigurationPage.samlInsecureFieldIds.some(isChecked);
    const anySensitive =
      anyInsecure || ssoConfigurationPage.samlSensitiveFieldIds.some(isChecked);
    if (anyInsecure) {
      ssoConfigurationPage.setSamlInsecureOptionsExpanded(page, true);
    }
    if (anySensitive) {
      ssoConfigurationPage.setSectionExpanded(
        page,
        "saml-security-section",
        true,
      );
    }
  },
  setSamlInsecureOptionsExpanded: (page, expanded) => {
    const button = page.querySelector("#saml-ShowInsecureOptions");
    const options = page.querySelector("#saml-insecure-options");
    if (!button || !options) {
      return;
    }
    options.hidden = !expanded;
    button.setAttribute("aria-expanded", String(expanded));
    button.querySelector("span").textContent = expanded
      ? "Hide insecure options"
      : "Show insecure options";
  },
  // The SAML save contract, made explicit (mirrors listArgumentsByType): every input in
  // #sso-new-saml-provider that persists carries an sso-* marker class AND a "saml-"+property id. The
  // folder-list and role-map ids are the two that are not plain inputs, listed explicitly like the OpenID
  // side. saveSamlProvider/loadSamlProvider map id->property with samlPropOf.
  listSamlArgumentsByType: (page) => {
    const folder_list_fields = ["saml-EnabledFolders"];
    const role_map_fields = ["saml-FolderRoleMapping"];

    const form = page.querySelector("#sso-new-saml-provider");

    const text_fields = [...form.querySelectorAll(".sso-text")].map(
      (e) => e.id,
    );
    const text_list_fields = [...form.querySelectorAll(".sso-line-list")].map(
      (e) => e.id,
    );
    const check_fields = [...form.querySelectorAll(".sso-toggle")].map(
      (e) => e.id,
    );

    return {
      text_list_fields,
      text_fields,
      check_fields,
      folder_list_fields,
      role_map_fields,
    };
  },
  loadSamlProvider: (page, provider_name) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        const provider = (config.SamlConfigs || {})[provider_name] || {};

        const form_elements =
          ssoConfigurationPage.listSamlArgumentsByType(page);

        page.querySelector("#saml-provider-name").value = provider_name;

        form_elements.text_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          // The write-only signing keys (SamlSigningKeyPfx / SamlRolloverSigningKeyPfx) are serialized back
          // as null by the server (WriteOnlySecretConverter), so provider[prop] is falsy and the field stays
          // blank — its "leave blank to keep" placeholder governs, exactly like the OpenID OidSecret.
          if (provider[prop]) {
            page.querySelector("#" + id).value = provider[prop];
          }
        });

        form_elements.text_list_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          if (provider[prop]) {
            ssoConfigurationPage.fillTextList(
              provider[prop],
              page.querySelector("#" + id),
            );
          }
        });

        form_elements.folder_list_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          if (provider[prop]) {
            ssoConfigurationPage.populateEnabledFolders(
              provider[prop],
              page.querySelector("#" + id),
            );
          }
        });

        form_elements.check_fields.forEach((id) => {
          // Always set from the loaded provider (not only when truthy) so a stale insecure toggle from a
          // previously loaded provider is never left checked to be silently re-saved — the exact reason the
          // OpenID loadProvider sets Boolean(provider[id]) unconditionally.
          const prop = ssoConfigurationPage.samlPropOf(id);
          page.querySelector("#" + id).checked = Boolean(provider[prop]);
        });

        form_elements.role_map_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          const elem = page.querySelector("#" + id);
          if (provider[prop]) {
            ssoConfigurationPage.populateRoleMappings(provider[prop], elem);
          }
        });

        ssoConfigurationPage.syncSamlDependentFields(page);
        ssoConfigurationPage.updateSamlUrls(page);
      },
    );
  },
  // Canonical external base for the computed SAML URLs (mirrors the inline logic in computeRedirectUri,
  // #724): the Base URL Override when set, else this server's address, normalized the way the server's
  // CanonicalBaseUrl (System.Uri.GetLeftPart) is — origin lowercases scheme+host and elides the default
  // port, pathname keeps any sub-path, and the trailing slash is trimmed. When the override is blank the
  // shown URL reflects the browser's server address; the scheme/port overrides are a legacy mechanism the
  // Base URL Override supersedes (its callout steers the admin there).
  samlCanonicalBase: (page) => {
    const override = page.querySelector("#saml-BaseUrlOverride").value.trim();
    const raw = override || ApiClient.serverAddress() || "";
    try {
      const u = new URL(raw);
      return u.origin + u.pathname.replace(/\/+$/, "");
    } catch (e) {
      return raw.replace(/\/+$/, "");
    }
  },
  // Live-update the read-only ACS + SP-metadata URLs (#725/#569). The IdP POSTs to the new-path ACS
  // spelling the SP metadata advertises at index 0 (SamlAcsUrlBuilder.AcsUrl newPath=true => "post"); the
  // metadata document is served at /sso/SAML/metadata/<provider>. The provider name is appended raw, as the
  // server does (names exclude URI-reserved characters, #336). Sets .value only, never innerHTML (#221).
  updateSamlUrls: (page) => {
    const acs = page.querySelector("#saml-AcsUrl");
    const metadata = page.querySelector("#saml-MetadataUrl");
    const name = page.querySelector("#saml-provider-name").value.trim();
    const base = ssoConfigurationPage.samlCanonicalBase(page);

    if (acs) {
      acs.value = name ? base + "/sso/SAML/post/" + name : "";
      acs.placeholder = name
        ? ""
        : "Enter a provider name above to see the ACS URL";
    }
    if (metadata) {
      metadata.value = name ? base + "/sso/SAML/metadata/" + name : "";
      metadata.placeholder = name
        ? ""
        : "Enter a provider name above to see the metadata URL";
    }
    const status = page.querySelector("#saml-url-copied");
    if (status) {
      status.textContent = "";
    }
  },
  // Copy a read-only computed SAML URL to the clipboard, with the same secure-context/execCommand fallback
  // and inert status announcement as copyRedirectUri (#724). fieldId/label identify which URL was copied.
  copySamlUrl: (page, fieldId, label) => {
    const field = page.querySelector("#" + fieldId);
    const status = page.querySelector("#saml-url-copied");
    const value = field && field.value;
    if (!value) {
      return;
    }
    const announce = (message) => {
      if (status) {
        status.textContent = message;
      }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        () => announce(label + " copied to the clipboard."),
        () => announce("Copy failed — select the field and copy it manually."),
      );
      return;
    }
    field.removeAttribute("readonly");
    field.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    field.setAttribute("readonly", "");
    announce(
      ok
        ? label + " copied to the clipboard."
        : "Copy failed — select the field and copy it manually.",
    );
  },
  // Import IdP metadata (#735) from a URL (fetched server-side through the SSRF-hardened outbound client) or
  // pasted XML, and pre-fill the endpoint + signing certificate(s) for the admin to review and save. The
  // server returns the parsed values; NOTHING is applied server-side by this call. The IdP EntityId is
  // shown for reference only — it is NOT the SP SamlClientId, which the admin chooses.
  importSamlMetadata: (page, source) => {
    const status = page.querySelector("#saml-metadata-status");
    const url =
      source === "url"
        ? page.querySelector("#saml-metadata-url").value.trim()
        : "";
    const xml =
      source === "xml"
        ? page.querySelector("#saml-metadata-xml").value.trim()
        : "";
    if (!url && !xml) {
      ssoConfigurationPage.renderTransferMessage(
        status,
        source === "url"
          ? "Enter a metadata URL first."
          : "Paste the metadata XML first.",
      );
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTransferMessage(status, "Importing metadata…");
    return ApiClient.fetch({
      type: "POST",
      url: ApiClient.getUrl("sso/SAML/ImportMetadata"),
      data: JSON.stringify({ Url: url || null, Xml: xml || null }),
      contentType: "application/json",
      dataType: "json",
    }).then(
      (result) => {
        if (result && result.Endpoint) {
          page.querySelector("#saml-SamlEndpoint").value = result.Endpoint;
        }
        if (result && result.PrimaryCertificate) {
          page.querySelector("#saml-SamlCertificate").value =
            result.PrimaryCertificate;
        }
        if (result && result.SecondaryCertificate) {
          page.querySelector("#saml-SamlSecondaryCertificate").value =
            result.SecondaryCertificate;
        }
        // The endpoint/certificate are now filled; re-run their on-blur validation so a bad imported value
        // surfaces immediately rather than only on the next focus change.
        ssoConfigurationPage.validateSamlEndpoint(page);
        ssoConfigurationPage.validateSamlCertificate(
          page,
          "saml-SamlCertificate",
          "IdP Signing Certificate",
        );
        // EntityId is reference-only: shown as inert text, never written into a field.
        const entity = result && result.EntityId ? result.EntityId : "";
        ssoConfigurationPage.renderTransferMessage(
          status,
          entity
            ? "Imported the endpoint and certificate. The provider's entity id is " +
                entity +
                " (reference only — set the SAML Client ID yourself). Review the fields and Save."
            : "Imported the endpoint and certificate. Review the fields and Save.",
        );
      },
      () =>
        ssoConfigurationPage.renderTransferMessage(
          status,
          "Could not import the metadata. Check the URL or XML, make sure you are signed in as an administrator, and that the address is reachable and not a private/loopback host.",
        ),
    );
  },
  clearSamlValidationErrors: (page) => {
    [
      "saml-provider-name",
      "saml-SamlEndpoint",
      "saml-SamlClientId",
      "saml-SamlCertificate",
      "saml-SamlSecondaryCertificate",
      "saml-BaseUrlOverride",
    ].forEach((id) => ssoConfigurationPage.setFieldError(page, id, ""));
  },
  renderSamlSaveStatus: (page, message, ok) => {
    const box = page.querySelector("#saml-save-status");
    if (!box) {
      return;
    }
    box.textContent = message || "";
    box.classList.remove("sso-status-ok", "sso-status-fail");
    if (message) {
      box.classList.add(ok ? "sso-status-ok" : "sso-status-fail");
    }
  },
  // Mirror the server's fail-closed provider-name checks (#336/#360) before the round-trip, keeping the
  // source ASCII-only (control chars detected by code point, not a regex escape) as validateProviderName does.
  validateSamlProviderName: (page) => {
    const value = page.querySelector("#saml-provider-name").value;
    if (!value.trim()) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-provider-name",
        "A provider name is required.",
      );
      return;
    }
    const hasControlChar = [...value].some((ch) => {
      const code = ch.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    });
    if (hasControlChar) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-provider-name",
        "Remove control characters (such as a tab or newline, often introduced by copy-paste) from the name.",
      );
      return;
    }
    const reserved = ["\\", "/", "?", "#", "%"];
    if (reserved.some((c) => value.includes(c))) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-provider-name",
        "Remove backslash and URI-reserved characters (\\ / ? # %) from the name.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "saml-provider-name", "");
  },
  validateSamlRequired: (page, id, label) => {
    const value = page.querySelector("#" + id).value.trim();
    ssoConfigurationPage.setFieldError(
      page,
      id,
      value ? "" : label + " is required.",
    );
  },
  validateSamlEndpoint: (page) => {
    const value = page.querySelector("#saml-SamlEndpoint").value.trim();
    if (!value) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        "SAML SSO Endpoint is required.",
      );
      return;
    }
    let url;
    try {
      url = new URL(value);
    } catch (e) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        "Enter an absolute URL, e.g. https://idp.example.com/sso",
      );
      return;
    }
    if (url.protocol === "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        "Uses http:// — the redirect would be unencrypted. Prefer an https:// endpoint.",
      );
      return;
    }
    if (url.protocol !== "https:") {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-SamlEndpoint",
        "Use an https:// URL for the SAML endpoint.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "saml-SamlEndpoint", "");
  },
  validateSamlBaseUrl: (page) => {
    const value = page.querySelector("#saml-BaseUrlOverride").value.trim();
    if (!value) {
      ssoConfigurationPage.setFieldError(page, "saml-BaseUrlOverride", "");
      return;
    }
    let url;
    try {
      url = new URL(value);
    } catch (e) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-BaseUrlOverride",
        "Enter a full origin such as https://jellyfin.example.com (scheme + host only).",
      );
      return;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-BaseUrlOverride",
        "Enter a full origin such as https://jellyfin.example.com",
      );
      return;
    }
    if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
      ssoConfigurationPage.setFieldError(
        page,
        "saml-BaseUrlOverride",
        "Enter the base URL only (no path) — e.g. https://jellyfin.example.com, not the /sso/... ACS URL.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, "saml-BaseUrlOverride", "");
  },
  // Pre-emptive certificate shape check (WARNING only, never blocks the save — the server stays the
  // authority, so a false positive cannot lock an admin out). Accepts an empty optional field, a PEM block,
  // or a bare Base64 body; only an obviously malformed value (non-Base64 characters once PEM armor and
  // whitespace are stripped) is flagged. label/id let it serve both the primary and secondary certificate.
  validateSamlCertificate: (page, id, label) => {
    const raw = page.querySelector("#" + id).value.trim();
    if (!raw) {
      // Optional (the secondary) or required-checked elsewhere (the primary) — an empty value is not a
      // SHAPE error here; requiredness for the primary is enforced by the server on save.
      ssoConfigurationPage.setFieldError(page, id, "");
      return;
    }
    const body = raw
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s+/g, "");
    if (!body || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
      ssoConfigurationPage.setFieldError(
        page,
        id,
        label +
          " is not valid Base64 — paste the certificate body (the text between the PEM BEGIN/END lines) or the whole PEM block.",
      );
      return;
    }
    ssoConfigurationPage.setFieldError(page, id, "");
  },
  deleteSamlProvider: (page, provider_name) => {
    if (
      !window.confirm(
        `Are you sure you want to delete the provider ${provider_name}?`,
      )
    ) {
      return;
    }
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        if (
          !config.SamlConfigs ||
          !config.SamlConfigs.hasOwnProperty(provider_name)
        ) {
          return;
        }

        delete config.SamlConfigs[provider_name];
        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            ssoConfigurationPage.hideSamlEditor(page);
            Dashboard.alert("Provider removed");
          },
          function () {
            Dashboard.alert({
              title: "Delete failed",
              message:
                "Could not remove the provider. The saved configuration was rejected by the server; reload the page and try again.",
            });
          },
        );
      },
    );
  },
  saveSamlProvider: (page, provider_name) => {
    return new Promise((resolve, reject) => {
      const form_elements = ssoConfigurationPage.listSamlArgumentsByType(page);

      ApiClient.getPluginConfiguration(
        ssoConfigurationPage.pluginUniqueId,
      ).then((config) => {
        if (!config.SamlConfigs) {
          config.SamlConfigs = {};
        }
        let current_config = {};
        if (config.SamlConfigs.hasOwnProperty(provider_name)) {
          current_config = config.SamlConfigs[provider_name];
        }

        form_elements.text_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          current_config[prop] = page.querySelector("#" + id).value || null;
        });

        form_elements.check_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          current_config[prop] = page.querySelector("#" + id).checked;
        });

        form_elements.text_list_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          current_config[prop] = ssoConfigurationPage.parseTextList(
            page.querySelector("#" + id),
          );
        });

        form_elements.folder_list_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          const elem = page.querySelector("#" + id);
          current_config[prop] =
            ssoConfigurationPage.serializeEnabledFolders(elem);
        });

        form_elements.role_map_fields.forEach((id) => {
          const prop = ssoConfigurationPage.samlPropOf(id);
          const elem = page.querySelector("#" + id);
          current_config[prop] =
            ssoConfigurationPage.serializeRoleMappings(elem);
        });

        config.SamlConfigs[provider_name] = current_config;

        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(
          function (result) {
            Dashboard.processPluginConfigurationUpdateResult(result);
            ssoConfigurationPage.loadConfiguration(page);
            ssoConfigurationPage.loadSamlProvider(page, provider_name);

            page.querySelector("#saml-selectProvider").value = provider_name;
            Dashboard.alert("Settings saved.");
            resolve();
          },
          function () {
            Dashboard.alert({
              title: "Save failed",
              message:
                "Could not save the provider. Check that the provider name has no control characters (such as a tab or newline, often introduced by copy-paste), no backslash, and none of the URI-reserved characters such as / ? # %, and that the Base URL Override is a full URL such as https://jellyfin.example.com (or blank).",
            });
            reject(new Error("Provider save failed"));
          },
        );
      });
    });
  },
  // Test-connection for a SAVED SAML provider (#163). Calls the elevation-gated SAML/Test endpoint, which
  // parses the stored IdP signing certificate server-side and returns only its non-secret facts (never the
  // SP signing key). Reuses the OpenID renderTestResult/renderTestMessage (same Ok/Message/Details shape).
  testSamlProvider: (page, provider_name) => {
    const container = page.querySelector("#saml-TestResult");
    if (!provider_name) {
      ssoConfigurationPage.renderTestMessage(
        container,
        "Enter a provider name and save it first, then test.",
      );
      return Promise.resolve();
    }

    ssoConfigurationPage.renderTestMessage(container, "Testing…");

    return ApiClient.getJSON(
      ApiClient.getUrl("sso/SAML/Test/" + encodeURIComponent(provider_name)),
    ).then(
      (result) => ssoConfigurationPage.renderTestResult(container, result),
      () =>
        ssoConfigurationPage.renderTestMessage(
          container,
          "Could not run the test. Make sure the provider is saved and that you are signed in as an administrator, then try again.",
        ),
    );
  },
};

export default function initSsoConfigurationPage(view) {
  ssoConfigurationPage.addTextAreaStyle(view);
  ssoConfigurationPage.loadConfiguration(view);

  view.querySelector("#SaveProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#OidProviderName").value;

    // The save alerts the admin on failure via Dashboard.alert; also surface the outcome inline in the
    // editor header. Handling the rejection here keeps a failed save from becoming an unhandled promise
    // rejection (the rejection still exists so callers can distinguish failure from success).
    ssoConfigurationPage.saveProvider(view, target_provider).then(
      () => {
        ssoConfigurationPage.renderSaveStatus(view, "Settings saved.", true);
        ssoConfigurationPage.setEditorTitle(view, target_provider);
      },
      () =>
        ssoConfigurationPage.renderSaveStatus(
          view,
          "Save failed — see the details in the alert.",
          false,
        ),
    );

    e.preventDefault();
    return false;
  });

  view.querySelector("#TestProvider").addEventListener("click", (e) => {
    // Test the provider named in the editor (the one just saved), not a load selector.
    const target_provider = view.querySelector("#OidProviderName").value;

    ssoConfigurationPage.testProvider(view, target_provider);

    e.preventDefault();
    return false;
  });

  // The provider LIST replaces the old select -> Load button: a click on a card loads that provider into
  // the editor. Event delegation, because the cards are re-rendered on every configuration reload.
  view.querySelector("#sso-provider-list").addEventListener("click", (e) => {
    const card = e.target.closest(".sso-provider-card");
    if (!card) {
      return;
    }
    ssoConfigurationPage.openProvider(view, card.dataset.provider);
  });

  view.querySelector("#AddProvider").addEventListener("click", (e) => {
    ssoConfigurationPage.addProvider(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#AddProviderEmpty").addEventListener("click", (e) => {
    ssoConfigurationPage.addProvider(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#DeleteProvider").addEventListener("click", (e) => {
    // Delete the provider currently loaded in the editor (its name is the editor's name field).
    const target_provider = view.querySelector("#OidProviderName").value;

    if (target_provider) {
      ssoConfigurationPage.deleteProvider(view, target_provider);
    } else {
      // A never-saved new provider: nothing to delete server-side, just discard the editor.
      ssoConfigurationPage.hideEditor(view);
    }

    e.preventDefault();
    return false;
  });

  view.querySelector("#AddRoleMapping").addEventListener("click", (e) => {
    const container = view.querySelector("#FolderRoleMapping");
    const current_mappings =
      ssoConfigurationPage.serializeRoleMappings(container);
    current_mappings.push({ Role: "", Folders: [] });
    ssoConfigurationPage.populateRoleMappings(current_mappings, container);
  });

  // The insecure-options expander keeps the dangerous toggles in the DOM (hidden), never detached, so they
  // still serialize; it only flips the `hidden` attribute and the aria-expanded state.
  view.querySelector("#ShowInsecureOptions").addEventListener("click", (e) => {
    const collapsed = view.querySelector("#sso-insecure-options").hidden;
    ssoConfigurationPage.setInsecureOptionsExpanded(view, collapsed);
    e.preventDefault();
    return false;
  });

  // Reveal-on-toggle dependent groups react to their controlling checkbox. syncDependentFields only toggles
  // visibility (hide-not-remove) and never mutates a value, so nothing can be dropped from a later save.
  ["EnableAllFolders", "EnableFolderRoles", "EnableLiveTvRoles"].forEach(
    (id) => {
      view
        .querySelector("#" + id)
        .addEventListener("change", () =>
          ssoConfigurationPage.syncDependentFields(view),
        );
    },
  );

  // On-blur inline validation (not per-keystroke) pre-empts the generic round-trip save error.
  view
    .querySelector("#OidProviderName")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateProviderName(view),
    );
  view
    .querySelector("#OidEndpoint")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateEndpoint(view),
    );
  view
    .querySelector("#OidClientId")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateRequired(
        view,
        "OidClientId",
        "OpenID Client ID",
      ),
    );
  view
    .querySelector("#RoleClaim")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateRequired(view, "RoleClaim", "Role Claim"),
    );
  view
    .querySelector("#OidScopes")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateRequired(
        view,
        "OidScopes",
        "Additional Scopes",
      ),
    );
  view
    .querySelector("#BaseUrlOverride")
    .addEventListener("blur", () => ssoConfigurationPage.validateBaseUrl(view));

  // Live-update the computed redirect URI (#724) as the provider name or the base-URL override changes, so
  // the value shown always matches what the login will send. `input` (per-keystroke) not `blur`, since the
  // field is purely informational — reflecting immediately is the point.
  ["OidProviderName", "BaseUrlOverride"].forEach((id) => {
    view
      .querySelector("#" + id)
      .addEventListener("input", () =>
        ssoConfigurationPage.updateRedirectUri(view),
      );
  });

  view.querySelector("#CopyRedirectUri").addEventListener("click", (e) => {
    ssoConfigurationPage.copyRedirectUri(view);
    e.preventDefault();
    return false;
  });

  // Populate the redirect URI once at init (the blank editor shows its placeholder until a name is typed).
  ssoConfigurationPage.updateRedirectUri(view);

  view.querySelector("#SaveLoginButtons").addEventListener("click", (e) => {
    ssoConfigurationPage.saveLoginButtons(view);
    e.preventDefault();
    return false;
  });

  view.querySelector("#ExportConfig").addEventListener("click", (e) => {
    ssoConfigurationPage.exportConfig(view);
    e.preventDefault();
    return false;
  });

  // The visible Import button drives the hidden file input; selecting a file runs the import.
  view.querySelector("#ImportConfig").addEventListener("click", (e) => {
    view.querySelector("#ImportConfigFile").click();
    e.preventDefault();
    return false;
  });

  view.querySelector("#ImportConfigFile").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    // Clear the input so choosing the same file again re-triggers change.
    e.target.value = "";
    ssoConfigurationPage.importConfig(view, file);
  });

  view.querySelector("#sso-self-service-link").href =
    ApiClient.getUrl("/SSOViews/linking");

  // ---- SAML workspace bindings (#725) — the exact parallel of the OpenID bindings above ----
  view.querySelector("#saml-SaveProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#saml-provider-name").value;

    ssoConfigurationPage.saveSamlProvider(view, target_provider).then(
      () => {
        ssoConfigurationPage.renderSamlSaveStatus(
          view,
          "Settings saved.",
          true,
        );
        ssoConfigurationPage.setSamlEditorTitle(view, target_provider);
      },
      () =>
        ssoConfigurationPage.renderSamlSaveStatus(
          view,
          "Save failed — see the details in the alert.",
          false,
        ),
    );

    e.preventDefault();
    return false;
  });

  view.querySelector("#saml-TestProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#saml-provider-name").value;
    ssoConfigurationPage.testSamlProvider(view, target_provider);
    e.preventDefault();
    return false;
  });

  view.querySelector("#saml-provider-list").addEventListener("click", (e) => {
    const card = e.target.closest(".sso-provider-card");
    if (!card) {
      return;
    }
    ssoConfigurationPage.openSamlProvider(view, card.dataset.provider);
  });

  view.querySelector("#saml-AddProvider").addEventListener("click", (e) => {
    ssoConfigurationPage.addSamlProvider(view);
    e.preventDefault();
    return false;
  });

  view
    .querySelector("#saml-AddProviderEmpty")
    .addEventListener("click", (e) => {
      ssoConfigurationPage.addSamlProvider(view);
      e.preventDefault();
      return false;
    });

  view.querySelector("#saml-DeleteProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#saml-provider-name").value;
    if (target_provider) {
      ssoConfigurationPage.deleteSamlProvider(view, target_provider);
    } else {
      ssoConfigurationPage.hideSamlEditor(view);
    }
    e.preventDefault();
    return false;
  });

  view.querySelector("#saml-AddRoleMapping").addEventListener("click", (e) => {
    const container = view.querySelector("#saml-FolderRoleMapping");
    const current_mappings =
      ssoConfigurationPage.serializeRoleMappings(container);
    current_mappings.push({ Role: "", Folders: [] });
    ssoConfigurationPage.populateRoleMappings(current_mappings, container);
    e.preventDefault();
    return false;
  });

  view
    .querySelector("#saml-ShowInsecureOptions")
    .addEventListener("click", (e) => {
      const collapsed = view.querySelector("#saml-insecure-options").hidden;
      ssoConfigurationPage.setSamlInsecureOptionsExpanded(view, collapsed);
      e.preventDefault();
      return false;
    });

  [
    "saml-EnableAllFolders",
    "saml-EnableFolderRoles",
    "saml-EnableLiveTvRoles",
  ].forEach((id) => {
    view
      .querySelector("#" + id)
      .addEventListener("change", () =>
        ssoConfigurationPage.syncSamlDependentFields(view),
      );
  });

  view
    .querySelector("#saml-provider-name")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlProviderName(view),
    );
  view
    .querySelector("#saml-SamlEndpoint")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlEndpoint(view),
    );
  view
    .querySelector("#saml-SamlClientId")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlRequired(
        view,
        "saml-SamlClientId",
        "SAML Client ID",
      ),
    );
  view
    .querySelector("#saml-SamlCertificate")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlCertificate(
        view,
        "saml-SamlCertificate",
        "IdP Signing Certificate",
      ),
    );
  view
    .querySelector("#saml-SamlSecondaryCertificate")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlCertificate(
        view,
        "saml-SamlSecondaryCertificate",
        "Secondary IdP Signing Certificate",
      ),
    );
  view
    .querySelector("#saml-BaseUrlOverride")
    .addEventListener("blur", () =>
      ssoConfigurationPage.validateSamlBaseUrl(view),
    );

  // Live-update the computed ACS + SP-metadata URLs as the provider name or base-URL override changes.
  ["saml-provider-name", "saml-BaseUrlOverride"].forEach((id) => {
    view
      .querySelector("#" + id)
      .addEventListener("input", () =>
        ssoConfigurationPage.updateSamlUrls(view),
      );
  });

  view.querySelector("#saml-CopyAcsUrl").addEventListener("click", (e) => {
    ssoConfigurationPage.copySamlUrl(view, "saml-AcsUrl", "ACS URL");
    e.preventDefault();
    return false;
  });
  view.querySelector("#saml-CopyMetadataUrl").addEventListener("click", (e) => {
    ssoConfigurationPage.copySamlUrl(view, "saml-MetadataUrl", "Metadata URL");
    e.preventDefault();
    return false;
  });

  view
    .querySelector("#saml-ImportMetadataUrl")
    .addEventListener("click", (e) => {
      ssoConfigurationPage.importSamlMetadata(view, "url");
      e.preventDefault();
      return false;
    });
  view
    .querySelector("#saml-ImportMetadataXml")
    .addEventListener("click", (e) => {
      ssoConfigurationPage.importSamlMetadata(view, "xml");
      e.preventDefault();
      return false;
    });

  // Populate the computed URLs once at init (blank editor shows the placeholders until a name is typed).
  ssoConfigurationPage.updateSamlUrls(view);

  // ---- Provider template pickers (#726) ----
  ssoConfigurationPage.populatePresetPicker(view, "OidPreset", OIDC_PRESETS);
  ssoConfigurationPage.populatePresetPicker(view, "saml-Preset", SAML_PRESETS);
  view.querySelector("#OidPreset").addEventListener("change", (e) => {
    ssoConfigurationPage.applyOidcPreset(view, e.target.value);
  });
  view.querySelector("#saml-Preset").addEventListener("change", (e) => {
    ssoConfigurationPage.applySamlPreset(view, e.target.value);
  });
}
