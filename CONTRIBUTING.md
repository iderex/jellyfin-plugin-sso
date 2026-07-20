<!-- omit in toc -->

# Contributing to Jellyfin SSO Plugin

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued. See the [Table of Contents](#table-of-contents) for different ways to help and details about how this project handles them. Please make sure to read the relevant section before making your contribution. It will make it a lot easier for us maintainers and smooth out the experience for all involved. The community looks forward to your contributions. 🎉

> And if you like the project, but just don't have time to contribute, that's fine. There are other easy ways to support the project and show your appreciation, which we would also be very happy about:
>
> - Star the project
> - Tweet about it
> - Refer this project in your project's readme
> - Mention the project at local meetups and tell your friends/colleagues

<!-- omit in toc -->

## Table of Contents

- [I Have a Question](#i-have-a-question)
- [I Want To Contribute](#i-want-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Improving The Documentation](#improving-the-documentation)
- [Styleguides](#styleguides)
  - [Commit Messages](#commit-messages)
- [Join The Project Team](#join-the-project-team)

> Project governance — who holds access, how decisions are made, and the continuity model — is documented in [GOVERNANCE.md](GOVERNANCE.md).

## I Have a Question

> If you want to ask a question, we assume that you have read the available [Documentation](https://github.com/iderex/jellyfin-plugin-sso/blob/main/README.md).

Before you ask a question, it is best to search for existing [Issues](https://github.com/iderex/jellyfin-plugin-sso/issues) that might help you. In case you have found a suitable issue and still need clarification, you can write your question in this issue. It is also advisable to search the internet for answers first.

If you then still feel the need to ask a question and need clarification, we recommend the following:

- Open an [Issue](https://github.com/iderex/jellyfin-plugin-sso/issues/new).
- Provide as much context as you can about what you're running into.
- Provide the relevant versions: your .NET SDK version, the Jellyfin server version, and the SSO provider type (OpenID Connect or SAML, and which identity provider).

We will then take care of the issue as soon as possible.

<!--
You might want to create a separate issue tag for questions and include it in this description. People should then tag their issues accordingly.

Depending on how large the project is, you may want to outsource the questioning, e.g. to Stack Overflow or Gitter. You may add additional contact and information possibilities:
- IRC
- Slack
- Gitter
- Stack Overflow tag
- Blog
- FAQ
- Roadmap
- E-Mail List
- Forum
-->

## I Want To Contribute

> ### Legal Notice <!-- omit in toc -->
>
> When contributing to this project, you must agree that you have authored 100% of the content, that you have the necessary rights to the content and that the content you contribute may be provided under the project license.

### Reporting Bugs

<!-- omit in toc -->

#### Before Submitting a Bug Report

A good bug report shouldn't leave others needing to chase you up for more information. Therefore, we ask you to investigate carefully, collect information and describe the issue in detail in your report. Please complete the following steps in advance to help us fix any potential bug as fast as possible.

- Make sure that you are using the latest version.
- Determine if your bug is really a bug and not an error on your side e.g. using incompatible environment components/versions (Make sure that you have read the [documentation](https://github.com/iderex/jellyfin-plugin-sso/blob/main/README.md). If you are looking for support, you might want to check [this section](#i-have-a-question)).
- To see if other users have experienced (and potentially already solved) the same issue you are having, check if there is not already a bug report existing for your bug or error in the [bug tracker](https://github.com/iderex/jellyfin-plugin-sso/issues?q=label%3Abug).
- Also make sure to search the internet (including Stack Overflow) to see if users outside of the GitHub community have discussed the issue.
- Collect information about the bug:
  - Stack trace (Traceback)
  - OS, Platform and Version (Windows, Linux, macOS, x86, ARM)
  - Version of the interpreter, compiler, SDK, runtime environment, package manager, depending on what seems relevant.
  - Possibly your input and the output
  - Can you reliably reproduce the issue? And can you also reproduce it with older versions?

<!-- omit in toc -->

#### How Do I Submit a Good Bug Report?

> You must never report an exploitable vulnerability, or any bug report that includes sensitive information, to the issue tracker or elsewhere in public. See [SECURITY.md](SECURITY.md) — report those privately through GitHub's vulnerability-reporting form instead.

We use GitHub issues to track bugs and errors. If you run into an issue with the project:

- Open an [Issue](https://github.com/iderex/jellyfin-plugin-sso/issues/new). (Since we can't be sure at this point whether it is a bug or not, we ask you not to talk about a bug yet and not to label the issue.)
- Explain the behavior you would expect and the actual behavior.
- Please provide as much context as possible and describe the _reproduction steps_ that someone else can follow to recreate the issue on their own. This usually includes your code. For good bug reports you should isolate the problem and create a reduced test case.
- Provide the information you collected in the previous section.

Once it's filed:

- The project team will label the issue accordingly.
- A team member will try to reproduce the issue with your provided steps. If there are no reproduction steps or no obvious way to reproduce the issue, the team will ask you for those steps and mark the issue as `needs-repro`. Bugs with the `needs-repro` tag will not be addressed until they are reproduced.
- If the team is able to reproduce the issue, it will be marked `needs-fix`, as well as possibly other tags (such as `critical`), and the issue will be left to be [implemented by someone](#your-first-code-contribution).

<!-- You might want to create an issue template for bugs and errors that can be used as a guide and that defines the structure of the information to be included. If you do so, reference it here in the description. -->

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Jellyfin SSO Plugin, **including completely new features and minor improvements to existing functionality**. Following these guidelines will help maintainers and the community to understand your suggestion and find related suggestions.

<!-- omit in toc -->

#### Before Submitting an Enhancement

- Make sure that you are using the latest version.
- Read the [documentation](https://github.com/iderex/jellyfin-plugin-sso/blob/main/README.md) carefully and find out if the functionality is already covered, maybe by an individual configuration.
- Perform a [search](https://github.com/iderex/jellyfin-plugin-sso/issues) to see if the enhancement has already been suggested. If it has, add a comment to the existing issue instead of opening a new one.
- Find out whether your idea fits with the scope and aims of the project. It's up to you to make a strong case to convince the project's developers of the merits of this feature. Keep in mind that we want features that will be useful to the majority of our users and not just a small subset. If you're just targeting a minority of users, consider writing an add-on/plugin library.

<!-- omit in toc -->

#### How Do I Submit a Good Enhancement Suggestion?

Enhancement suggestions are tracked as [GitHub issues](https://github.com/iderex/jellyfin-plugin-sso/issues).

- Use a **clear and descriptive title** for the issue to identify the suggestion.
- Provide a **step-by-step description of the suggested enhancement** in as many details as possible.
- **Describe the current behavior** and **explain which behavior you expected to see instead** and why. At this point you can also tell which alternatives do not work for you.
- You may want to **include screenshots and animated GIFs** which help you demonstrate the steps or point out the part which the suggestion is related to. You can use [this tool](https://www.cockos.com/licecap/) to record GIFs on macOS and Windows, and [this tool](https://github.com/colinkeenan/silentcast) or [this tool](https://github.com/GNOME/byzanz) on Linux. <!-- this should only be included if the project has a GUI -->
- **Explain why this enhancement would be useful** to most Jellyfin SSO Plugin users. You may also want to point out the other projects that solved it better and which could serve as inspiration.

<!-- You might want to create an issue template for enhancement suggestions that can be used as a guide and that defines the structure of the information to be included. If you do so, reference it here in the description. -->

### Your First Code Contribution

The project is built with .NET 9, targeting Jellyfin 10.11. Download [the .NET 9 SDK](https://dotnet.microsoft.com/en-us/download).

Any code editor or IDE with .NET support will work out of the box with this program.

(Some) editors:

- [VSCode](https://code.visualstudio.com/docs/languages/dotnet)
- [N/Vim](https://github.com/OmniSharp/Omnisharp-vim)

**Getting oriented.** Before diving into the `SSOController` and the SAML/OpenID helpers, read the [Login Flow](https://github.com/iderex/jellyfin-plugin-sso/wiki/Login-Flow) and [Architecture](https://github.com/iderex/jellyfin-plugin-sso/wiki/Architecture) wiki pages — together they walk an OpenID and a SAML sign-in from challenge to session and map the module layout, so you can place a change onto the flow instead of reverse-engineering it.

**Building and testing.** CI runs these on every pull request and they must pass:

```sh
dotnet restore                               # once on a fresh clone; the --no-restore flags below assume it
dotnet build --no-restore --warnaserror      # warnings are errors, exactly as in CI
dotnet test --no-build --verbosity normal    # the xUnit project SSO-Auth.Tests must stay green
npx prettier --check "**/*.{js,html,md,css,scss}"   # for any .js/.html/.md/.css change
```

CI restores in a separate step, so its build/test use `--no-restore`/`--no-build`; on a fresh local clone run `dotnet restore` once first (or drop `--no-restore` on the first build) or the build fails before any package is fetched.

**Developing the admin UI.** The settings page and the account-linking page are **embedded resources**, not files served from disk: `configPage.html`, `config.js`, and the `linking.*` assets are compiled into `SSO-Auth.dll` (see the `<EmbeddedResource>` entries in `SSO-Auth.csproj`). So the edit loop is **rebuild → redeploy the DLL → restart Jellyfin**: `dotnet publish -c Release`, copy the output into your Jellyfin `config/plugins/sso/`, and restart the server; there is no live reload. Jellyfin's logs (the plugin logs through them) live under the server's `config/log/` directory. One gotcha while iterating: the `/SSOViews` assets are served with an ETag derived from the assembly `FileVersion`, so a browser will `304`-serve the **previous** build of `linking.js`/`linking.css` until the version changes — disable the browser cache (DevTools → Network → "Disable cache") during a UI edit session, or you will be testing stale assets.

**Branching and pull requests.** `main` is the released line and is PR-only. Branch every change — even a one-liner — off `main` for fixes and security work, or off the feature branch for features, using a short kebab-case name with a `fix/`, `harden/`, `feature/`, `chore/`, or `refactor/` prefix. Reference the issue your change addresses (`Closes #N`) and fill in the [pull request template](.github/pull_request_template.md).

This is a security-sensitive login path: before opening a pull request, understand and own every line you propose, and be ready to explain what it does and why. The merge gate is internal-only (CI, the adversarial review, and my own sign-off); [Review Gate](https://github.com/iderex/jellyfin-plugin-sso/wiki/Review-Gate) maps how those controls cover each class of issue an automated PR reviewer would catch.

### Improving The Documentation

We are always open to better docs! The main place documentation could be improved is the [provider setup](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup) documentation. This file keeps track of configurations that are known to work with common SSO providers.

## Styleguides

### Commit Messages

Short, imperative subject line (`Add SAML replay cache`, not `feat: add ...`); explain the _why_ in the body. **Every commit subject ends with its issue reference(s) in brackets** — `Add SAML replay cache [#123]`, multiple issues as `[#123][#456]` — so the link survives `git blame`/`bisect`/`log`, which show only the subject. GitHub's auto-close keywords (`Closes #N`) additionally go in the body when the commit resolves the issue. The PR-hygiene gate enforces the bracketed subject reference per commit (bots and merge commits exempt).

### C#

We format all C# code according to the .NET formatter. Build with `dotnet build --no-restore --warnaserror` (the same command CI runs, so warnings fail the build) and fix anything it reports, and keep `dotnet test` green.

The architecture, comment/documentation, and object-oriented rules a change is held to live in one canonical place — the [Coding Standards](https://github.com/iderex/jellyfin-plugin-sso/wiki/Coding-Standards) wiki page. This guide does not restate them; read that page before a non-trivial change. They are enforced by the conformance fitness functions in `SSO-Auth.Tests/ArchitectureConformanceTests.cs` and the adversarial review gate.

### HTML/CSS/JS/Markdown

We use [Prettier](https://prettier.io) to format these files. Run `npx prettier --write "**/*.{js,html,md,css,scss}"` before committing, and `npx prettier --check "**/*.{js,html,md,css,scss}"` to confirm — CI enforces the check (only `*.min.js` is exempt).

Not every file under `SSO-Auth/Web` is project code. Check the provenance header before editing: `emby-restyle.css` and the minified `jellyfin-apiClient.esm.min.js` are **vendored** from jellyfin-web — update them by re-copying from upstream, not by editing in place — whereas `ApiClient.js` is **project-maintained** code (loosely based on the linked upstream) that carries our own security logic and is edited here directly.

### Keeping the docs in step

When a code change makes any **README section or wiki page** wrong or incomplete — a changed behaviour, a moved type the [Architecture](https://github.com/iderex/jellyfin-plugin-sso/wiki/Architecture) page names, a new or renamed config option, an altered login flow — the documentation follow-up must not be lost. Either **update the docs in the same pull request**, or **open a `documentation`-labelled issue on the current-release milestone** so it ships before the next release. The PR checklist has a box for this. (The wiki has no pull-request flow — wiki edits are pushed directly to its repository — but the _tracking_ still lives as an issue in the main repository.)

<!-- omit in toc -->

## Attribution

This guide is based on the **contributing-gen**. [Make your own](https://github.com/bttger/contributing-gen)!
