# ACF Schema API Plugin

Adds secure REST endpoints for ACF schema pull/push.

## Endpoints
- `POST /wp-json/acf-schema/v1/pull`
- `POST /wp-json/acf-schema/v1/push`

Both endpoints require an authenticated user with capability `manage_options` by default.

## Install
1. Copy folder `wp-acf-schema-api-plugin` into:
`wp-content/plugins/acf-schema-api`
2. Activate plugin in WordPress admin.
3. Ensure ACF is installed and active.
4. Use an Application Password for an admin-capable user.

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

```bash
curl --user "wp_user:app_password" \
  -X POST "https://example.com/wp-json/acf-schema/v1/push" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_hash": "CURRENT_HASH_FROM_PULL",
    "dry_run": true,
    "allow_field_key_changes": false,
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
  - first from `acf_get_setting('load_json')` JSON files (path order precedence)
  - then DB-only field groups not present in JSON
- Strict JSON mode is enabled by default (`acf_schema_api_strict_json_only`).
- Push requests require signed headers by default (`acf_schema_api_require_signed_push`).
- Validates group keys as `group_*`.
- Validates nested field keys as `field_*`.
- Fails on duplicate sibling field names at any nesting level.
- Fails on field-key set changes for existing groups unless `allow_field_key_changes=true`.
- Does not delete groups that are not present in payload.
- Use `expected_hash` on every push to avoid overwriting concurrent changes.

## Configure HMAC secret for signed push
Set a server-side secret in `wp-config.php`:

```php
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

## Local test script
Use `test-schema-api.sh` for pull + push dry-run verification.

```bash
export WP_API_USER='admin-user'
export WP_API_APP_PASSWORD='app password here'
export ACF_SCHEMA_API_HMAC_SECRET='your-shared-hmac-secret'
./test-schema-api.sh --base-url https://example.com
```

Add `--apply` only after dry-run is verified.

The script now writes both:
- pretty JSON (`*.json`) for readability
- raw JSON (`*.raw.json`) for exact API payload auditing
