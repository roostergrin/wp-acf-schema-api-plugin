# ACF Schema API Plugin

Adds REST endpoints for ACF schema pull/push.

## Endpoints
- `POST /wp-json/acf-schema/v1/pull`
- `POST /wp-json/acf-schema/v1/push`

Both endpoints require an authenticated user with capability `manage_options` by default.

## Install
1. Build or download `acf-schema-api.zip`.
2. Upload it in WordPress under Plugins > Add Plugin > Upload Plugin, or unpack it to `wp-content/plugins/acf-schema-api/`.
3. Activate plugin in WordPress admin.
4. Ensure ACF is installed and active.
5. Use an Application Password for an admin-capable user.

## Build a zip

Build a deployable WordPress plugin zip locally:

```bash
./scripts/build-zip.sh
```

The script validates that the plugin header `Version` matches `readme.txt` `Stable tag` before packaging.

This writes:
- `dist/acf-schema-api-<version>.zip`
- `dist/acf-schema-api.zip`

The zip expands to `acf-schema-api/`, so it can be uploaded directly in WordPress or unpacked into `wp-content/plugins/acf-schema-api/`.

## GitHub automation

GitHub Actions rebuilds the zip on every push with `.github/workflows/build-zip.yml`.

- Every push uploads fresh zip files as a workflow artifact.
- Every git tag publishes the zip files to the corresponding GitHub release.

This is the reliable way to keep the zip up to date. Committing built zip files into git is possible, but it creates noisy binary diffs and usually ages badly.

### Plesk shell note
If `wp` fails with `/usr/bin/env: 'php': No such file or directory`, run WP-CLI with a PHP path prefix:

```bash
PATH=/opt/plesk/php/8.2/bin:$PATH wp --path='/var/www/vhosts/example.com/site' plugin activate acf-schema-api
```

## Pull schema
Returns `schema_hash`, `group_count`, and optionally `field_groups`.

```bash
curl --user "wp_user:app_password" \
  -X POST "https://example.com/wp-json/acf-schema/v1/pull" \
  -H "Content-Type: application/json" \
  -d '{"include_groups": true}'
```

## Push schema (dry-run)
`field_groups` must be an array of ACF group JSON objects.
`expected_hash` is optional but recommended for optimistic locking.
`allow_field_key_changes` defaults to `false`.
`delete_missing_groups` defaults to `false` (when `true`, deletes groups not present in payload from JSON and ACF DB).
`suppress_legacy_build_hooks` defaults to `true` (temporarily suppresses legacy `save_post` pipeline hooks during DB import/delete apply).

```bash
curl --user "wp_user:app_password" \
  -X POST "https://example.com/wp-json/acf-schema/v1/push" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_hash": "CURRENT_HASH_FROM_PULL",
    "dry_run": true,
    "allow_field_key_changes": false,
    "delete_missing_groups": false,
    "suppress_legacy_build_hooks": true,
    "field_groups": [
      {
        "key": "group_abc123",
        "title": "Example",
        "fields": []
      }
    ]
  }'
```

## Push schema (apply)

```bash
curl --user "wp_user:app_password" \
  -X POST "https://example.com/wp-json/acf-schema/v1/push" \
  -H "Content-Type: application/json" \
  -d @schema-payload.json
```

Where `schema-payload.json` contains:

```json
{
  "expected_hash": "CURRENT_HASH_FROM_PULL",
  "dry_run": false,
  "allow_field_key_changes": false,
  "delete_missing_groups": false,
  "suppress_legacy_build_hooks": true,
  "field_groups": [
    {
      "key": "group_abc123",
      "title": "Example",
      "fields": []
    }
  ]
}
```

## Safety notes
- Writes only to `wp-content/acf-json` by default.
- Pull/push hash state now follows effective ACF schema resolution:
  - from `acf_get_setting('load_json')` JSON files, preferring the newest duplicate group by `modified` (then file mtime)
  - then DB-only field groups not present in JSON
- Strict JSON mode is enabled by default (`acf_schema_api_strict_json_only`).
- The WordPress `Settings > AI Automation` page now shows DB-only field groups and can export them to JSON.
- Optional auto-heal: enable auto-export from `Settings > AI Automation`, or override it with `acf_schema_api_auto_export_db_only_groups`, to export DB-only groups automatically during pull/push before strict mode fails.
- Push requests rely on authenticated WordPress users with the required capability by default.
- Signed push headers are optional and can be re-enabled with `acf_schema_api_require_signed_push`.
- During push apply, legacy `save_post` build triggers from old themes (for example callbacks from `functions/run-build.php`) are suppressed by default so schema deploy does not auto-run frontend build pipelines.
- Validates group keys as `group_*`.
- Validates nested field keys as `field_*`.
- Fails on duplicate sibling field names at any nesting level.
- Fails on field-key set changes for existing groups unless `allow_field_key_changes=true`.
- Can delete groups not present in payload only when `delete_missing_groups=true` (JSON files and matching DB field groups).
- Use `expected_hash` on every push to avoid overwriting concurrent changes.

## Optional signed push hardening
If you want an extra shared-secret layer on top of WordPress auth, enable the filter and set a server-side secret in `wp-config.php`:

```php
add_filter('acf_schema_api_require_signed_push', '__return_true');
define('ACF_SCHEMA_API_HMAC_SECRET', 'replace-with-long-random-secret');
```

Signed headers required for `POST /acf-schema/v1/push`:
- `X-ACF-Schema-Timestamp` (unix epoch seconds)
- `X-ACF-Schema-Nonce` (random token, single-use)
- `X-ACF-Schema-Signature` (`hex(hmac_sha256(canonical, secret))`)

Canonical string:
`METHOD + "\n" + ROUTE + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + sha256(raw_body)`

Route for push:
`/acf-schema/v1/push`

## Optional filters
- `acf_schema_api_required_capability` (default `manage_options`)
- `acf_schema_api_json_dir` (default `WP_CONTENT_DIR . '/acf-json'`)
- `acf_schema_api_auto_export_db_only_groups` (default `false`)
- `acf_schema_api_require_signed_push` (default `false`)
- `acf_schema_api_suppress_legacy_build_hooks` (default `true`)
- `acf_schema_api_match_legacy_build_callback` (default matcher targets known legacy CodePipeline callbacks)

## Local test script
Use `test-schema-api.sh` for pull + push dry-run verification.

```bash
export WP_API_USER='admin-user'
export WP_API_APP_PASSWORD='app password here'
./test-schema-api.sh --base-url https://example.com
```

If the site is configured to require signed push requests, also set:

```bash
export ACF_SCHEMA_API_HMAC_SECRET='your-shared-hmac-secret'
```

Add `--apply` only after dry-run is verified.

The script now writes both:
- pretty JSON (`*.json`) for readability
- raw JSON (`*.raw.json`) for exact API payload auditing
