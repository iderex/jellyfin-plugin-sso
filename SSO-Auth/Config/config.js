const ssoConfigurationPage = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",
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
    // Clear providers in case there are out of date ones
    page
      .querySelector("#selectProvider")
      .querySelectorAll("option")
      .forEach((option) => {
        option.remove();
      });

    // Add providers as options for the selector

    Object.keys(providers).forEach((provider_name) => {
      const choice = new Option(provider_name, provider_name);

      page.querySelector("#selectProvider").appendChild(choice);
    });
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
      },
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

    // The save already alerts the admin on failure; swallow the rejection here so a failed save is not
    // an unhandled promise rejection (the rejection exists so callers can distinguish failure from success).
    ssoConfigurationPage.saveProvider(view, target_provider).catch(() => {});

    e.preventDefault();
    return false;
  });

  view.querySelector("#TestProvider").addEventListener("click", (e) => {
    // Test the provider named in the add/update form (the one just saved), not the load selector.
    const target_provider = view.querySelector("#OidProviderName").value;

    ssoConfigurationPage.testProvider(view, target_provider);

    e.preventDefault();
    return false;
  });

  view.querySelector("#LoadProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#selectProvider").value;

    ssoConfigurationPage.loadProvider(view, target_provider);

    e.preventDefault();
    return false;
  });

  view.querySelector("#DeleteProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#selectProvider").value;

    ssoConfigurationPage.deleteProvider(view, target_provider);

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
