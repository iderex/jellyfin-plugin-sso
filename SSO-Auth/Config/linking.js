const ssoConfigLinking = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",
  loadProviders: (view) => {
    ["oid", "saml"].forEach((provider_mode) => {
      const container = view.querySelector(
        `#sso-provider-list-${provider_mode}`,
      );
      container.innerHTML = "";

      fetch(
        new Request(
          ApiClient.getUrl(`sso/${provider_mode.toUpperCase()}/GetNames`),
        ),
      ).then((resp) => {
        resp.json().then((config_names) => {
          ssoConfigLinking.loadProviderList(
            container,
            config_names,
            provider_mode,
          );
        });
      });
    });
  },
  loadProviderList: (container, providers, provider_mode) => {
    // The server only offers enabled providers for new links (#344), so every name here gets an
    // add button. A link the user still holds to a since-disabled provider is rendered separately
    // below, from the links feed, so it stays visible and removable.
    providers.forEach((provider_name) => {
      ssoConfigLinking.appendProviderContainer(
        container,
        provider_name,
        provider_mode,
        true,
      );
    });

    const currentUserId = ApiClient.getCurrentUserId();

    if (currentUserId) {
      ApiClient.fetch(
        {
          type: "GET",
          url: ApiClient.getUrl(`sso/${provider_mode}/links/${currentUserId}`),
        },
        true,
      ).then((resp) => {
        resp.json().then((provider_map) => {
          Object.keys(provider_map).forEach((provider_name) => {
            let existing_links = container.querySelector(
              `.sso-provider-existing-links-container[data-provider="${CSS.escape(provider_name)}"]`,
            );

            // No container means the provider is not offered for new links because it is disabled
            // (it is absent from the enabled-only GetNames list, #344). The server still returns
            // such links and still lets the user delete them (LinksByUser / TryRemoveLink pass
            // requireEnabled:false — disabling then cleaning up is the intended workflow), so render
            // a container without an add button, marked disabled, rather than dropping it and
            // throwing on a null container. A disabled provider the user holds no link to (empty
            // list, nothing to remove) is skipped.
            if (!existing_links) {
              if (provider_map[provider_name].length === 0) {
                return;
              }
              existing_links = ssoConfigLinking.appendProviderContainer(
                container,
                provider_name,
                provider_mode,
                false,
              );
            }

            ssoConfigLinking.populateExistingLinks(
              existing_links,
              provider_mode,
              provider_name,
              provider_map[provider_name],
            );
          });
        });
      });
    }
  },

  // Builds one provider row (title, optional add button, existing-links container) and appends it,
  // returning the existing-links container so the caller can populate it. When offerLink is false the
  // provider is disabled: no add button is drawn (it cannot accept a new link) and the title is marked,
  // but any link the user already holds stays listed and removable.
  appendProviderContainer: (
    container,
    provider_name,
    provider_mode,
    offerLink,
  ) => {
    // Provider and canonical names are identity-provider/admin-controlled: build the DOM with
    // createElement/textContent (never innerHTML), and feed them into selectors and URLs only
    // through CSS.escape / encodeURIComponent, never raw.
    const provider_config = document.createElement("div");
    provider_config.classList.add("sso-provider-links-container");
    provider_config.dataset.id = provider_name;

    const title = document.createElement("label");
    title.classList.add(
      "inputLabel",
      "inputLabelUnfocused",
      "sso-provider-link-title",
    );
    title.textContent = provider_name;

    const existing_links = document.createElement("div");
    existing_links.classList.add("sso-provider-existing-links-container");
    existing_links.dataset.provider = provider_name;

    if (offerLink) {
      const add_provider = document.createElement("a");
      add_provider.classList.add(
        "fab",
        "emby-button",
        "sso-provider-add-link",
        "sso-provider",
      );
      const add_icon = document.createElement("span");
      add_icon.classList.add("material-icons", "add");
      add_icon.setAttribute("aria-hidden", "true");
      add_provider.appendChild(add_icon);
      add_provider.href = ApiClient.getUrl(
        `/SSO/${provider_mode}/p/${encodeURIComponent(provider_name)}?isLinking=true`,
      );
      provider_config.append(title, add_provider, existing_links);
    } else {
      const disabled_note = document.createElement("span");
      disabled_note.classList.add("sso-provider-disabled-note");
      disabled_note.textContent = " (disabled)";
      title.appendChild(disabled_note);
      provider_config.append(title, existing_links);
    }

    container.appendChild(provider_config);
    return existing_links;
  },

  populateExistingLinks: (
    container,
    provider_mode,
    provider_name,
    canonical_names,
  ) => {
    container
      .querySelectorAll(".sso-provider-link-checkbox-wrapper")
      .forEach((e) => e.remove());

    const checkboxes = canonical_names.map((canonical_name) => {
      const out = document.createElement("label");
      out.classList.add(
        "sso-provider-link-checkbox-wrapper",
        "checkbox-wrapper",
      );

      // The canonical name is identity-provider-controlled - assigning it via dataset/textContent
      // (never innerHTML) keeps a hostile linked-account name inert on this page.
      // createElement's `is` option upgrades the customized built-in; the attribute is set as well
      // so CSS attribute selectors and the web-components polyfill see it.
      const checkbox = document.createElement("input", {
        is: "emby-checkbox",
      });
      checkbox.setAttribute("is", "emby-checkbox");
      checkbox.classList.add("sso-link-checkbox");
      checkbox.type = "checkbox";
      checkbox.dataset.id = canonical_name;
      checkbox.dataset.mode = provider_mode;
      checkbox.dataset.provider = provider_name;

      const checkbox_label = document.createElement("span");
      checkbox_label.classList.add("checkbox-label");
      checkbox_label.textContent = canonical_name;

      out.append(checkbox, checkbox_label);
      return out;
    });

    checkboxes.forEach((e) => {
      container.appendChild(e);
    });
  },

  handleDeleteButtonPressed: (evt, view) => {
    if (evt.target.disabled) return;

    const currentUserId = ApiClient.getCurrentUserId();
    if (!currentUserId) return;

    const delete_requests = [...view.querySelectorAll(".sso-link-checkbox")]
      .filter((checkbox_link) => {
        const canonical_name = checkbox_link.dataset.id;
        const provider_name = checkbox_link.dataset.provider;
        const provider_mode = checkbox_link.dataset.mode;

        if (![canonical_name, provider_name, provider_mode].every(Boolean)) {
          return false;
        }

        if (!checkbox_link.checked) {
          return false;
        }

        return true;
      })
      .map((checked_link) => {
        const canonical_name = checked_link.dataset.id;
        const provider_name = checked_link.dataset.provider;
        const provider_mode = checked_link.dataset.mode;

        // Encode the provider/canonical segments so an identity-provider-controlled name with a
        // slash or other reserved character cannot inject extra path segments. A name that is
        // exactly "." or ".." can still be collapsed by a path normalizer, but that only 404s
        // (the route targets the caller's own links); "." is left unencoded because encoding it
        // would break the common dotted username/email behind a strict reverse proxy.
        return ApiClient.fetch({
          type: "DELETE",
          url: ApiClient.getUrl(
            `sso/${provider_mode}/link/${encodeURIComponent(provider_name)}/${currentUserId}/${encodeURIComponent(canonical_name)}`,
          ),
        });
      });

    Promise.all(delete_requests).then((values) => {
      window.location.reload();
    });
  },
};

export default function initLinkingView(view) {
  ssoConfigLinking.loadProviders(view);

  view.querySelector("#enable-delete").addEventListener("change", (e) => {
    view.querySelector("#btn-delete-selected-links").disabled =
      !e.target.checked;
  });

  view
    .querySelector("#btn-delete-selected-links")
    .addEventListener("click", (e) =>
      ssoConfigLinking.handleDeleteButtonPressed(e, view),
    );
}
