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
      },
    );

    const folder_container = page.querySelector("#EnabledFolders");
    ssoConfigurationPage.populateFolders(folder_container);
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
}
