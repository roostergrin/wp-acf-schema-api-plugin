=== ACF Schema API ===
Contributors: rgops
Tags: acf, rest-api, schema, headless, automation
Requires at least: 6.0
Tested up to: 6.5
Requires PHP: 7.4
Stable tag: 1.5.9
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Expose secure REST endpoints to pull and push ACF schema JSON for headless automation workflows.

== Description ==

ACF Schema API adds authenticated WordPress REST endpoints for ACF schema automation:

* `POST /wp-json/acf-schema/v1/pull`
* `POST /wp-json/acf-schema/v1/push`
* `GET /wp-json/acf-automation/v1/bootstrap/status`
* `POST /wp-json/acf-automation/v1/bootstrap/claim`
* `POST /wp-json/acf-automation/v1/bootstrap/rotate`
* `GET/POST /wp-json/acf-automation/v1/content/{resource_type}/{resource_id}`

The plugin is designed for teams managing ACF schema as code, with dry-run support, hash checking, strict validation, and optional signed push hardening.

== Installation ==

1. Upload the plugin zip in WordPress admin under Plugins > Add New > Upload Plugin.
2. Activate the plugin.
3. Ensure ACF is installed and active.
4. Create an application password for an administrator account (or use plugin secret bootstrap auth).
5. Test the pull endpoint before using push.

== Frequently Asked Questions ==

= Does this plugin require Advanced Custom Fields? =

Yes. The endpoints operate on ACF field groups and expect ACF to be active.

= Can I test changes safely? =

Yes. Use `dry_run: true` on push requests to validate payloads before writing.

= How do I prevent overwriting concurrent changes? =

Use `expected_hash` from a recent pull response in every push request.

== Changelog ==

= 1.5.9 =

* Push apply now suppresses known legacy `save_post` CodePipeline build callbacks by default, reducing accidental build triggers during schema deploy.
* Added `suppress_legacy_build_hooks` push request flag (default `true`) and related suppression filters.

= 1.5.8 =

* Production release for schema pull/push, bootstrap, and content APIs.
