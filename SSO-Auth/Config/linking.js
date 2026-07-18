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
      )
        // The global fetch resolves even on a non-2xx status, so gate on resp.ok before reading the body:
        // a swallowed rejection would otherwise leave the section silently empty instead of telling the
        // user something failed (#344).
        .then((resp) => {
          if (!resp.ok) {
            throw new Error("provider list request failed");
          }
          return resp.json();
        })
        .then((config_names) => {
          ssoConfigLinking.loadProviderList(
            container,
            config_names,
            provider_mode,
          );
        })
        .catch(() => ssoConfigLinking.showError());
    });
  },

  // A single generic banner for any failed request on this page — it never carries a status code or
  // server message, so a rejection cannot leak an internal detail into the admin UI (#344).
  showError: () => {
    const banner = document.querySelector("#sso-linking-error");
    if (banner) {
      banner.hidden = false;
    }
  },
  // Builds one provider row (title + optional add button + an empty existing-links container) and
  // appends it, returning that container. The add button is offered only for a provider on the
  // enabled add-list (#344): a disabled provider must not start a NEW link (the challenge/link twins
  // reject it, #343), but a row without the button still lets its already-created links be removed —
  // the deliberate disable-then-clean-up workflow (#380). Provider names are identity-provider/
  // admin-controlled: the DOM is built with createElement/textContent (never innerHTML) and names reach
  // selectors/URLs only through CSS.escape / encodeURIComponent, never raw.
  createProviderRow: (
    container,
    provider_name,
    provider_mode,
    withAddButton,
  ) => {
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
    provider_config.appendChild(title);

    if (withAddButton) {
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
      provider_config.appendChild(add_provider);
    }

    const existing_links = document.createElement("div");
    existing_links.classList.add("sso-provider-existing-links-container");
    existing_links.dataset.provider = provider_name;
    provider_config.appendChild(existing_links);

    container.appendChild(provider_config);
    return existing_links;
  },

  loadProviderList: (container, providers, provider_mode) => {
    providers.forEach((provider_name) => {
      ssoConfigLinking.createProviderRow(
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
      )
        .then((resp) => resp.json())
        .then((provider_map) => {
          Object.keys(provider_map).forEach((provider_name) => {
            const canonical_names = provider_map[provider_name];
            let provider_container = container.querySelector(
              `.sso-provider-existing-links-container[data-provider="${CSS.escape(provider_name)}"]`,
            );
            if (!provider_container) {
              // The links endpoint reports every provider, including disabled ones the enabled-only
              // add-list omitted (#344). Surface a disabled provider only when the user actually has
              // links to remove — otherwise skip it, so a disabled provider is neither offered nor
              // clutters the page — and render it without an add button (#380).
              if (!canonical_names || canonical_names.length === 0) {
                return;
              }
              provider_container = ssoConfigLinking.createProviderRow(
                container,
                provider_name,
                provider_mode,
                false,
              );
            }
            ssoConfigLinking.populateExistingLinks(
              provider_container,
              provider_mode,
              provider_name,
              canonical_names,
            );
          });
        })
        // ApiClient.fetch rejects on a non-2xx status, so a failed existing-links load surfaces the same
        // generic banner rather than silently omitting the user's current links (#344).
        .catch(() => ssoConfigLinking.showError());
    }
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

    Promise.all(delete_requests)
      .then(() => {
        window.location.reload();
      })
      // A rejected unlink used to reload the page anyway, presenting a failure as success; show the
      // generic banner instead so the stale links stay visible and the user knows nothing changed (#344).
      .catch(() => ssoConfigLinking.showError());
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
