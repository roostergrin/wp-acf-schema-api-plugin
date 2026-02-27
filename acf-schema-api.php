<?php
/**
 * Plugin Name: ACF Schema API
 * Description: Secure REST endpoints to pull and push ACF schema JSON (field groups) with dry-run and hash lock support.
 * Version: 1.3.2
 * Author: RG Ops
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('RG_ACF_Schema_API')) {
    final class RG_ACF_Schema_API
    {
        const ROUTE_NAMESPACE = 'acf-schema/v1';
        const NONCE_TRANSIENT_PREFIX = 'acf_schema_api_nonce_';

        public static function init()
        {
            add_action('rest_api_init', array(__CLASS__, 'register_routes'));
        }

        public static function register_routes()
        {
            register_rest_route(
                self::ROUTE_NAMESPACE,
                '/pull',
                array(
                    'methods' => WP_REST_Server::CREATABLE,
                    'callback' => array(__CLASS__, 'handle_pull'),
                    'permission_callback' => array(__CLASS__, 'permission_check'),
                    'args' => array(
                        'include_groups' => array(
                            'type' => 'boolean',
                            'required' => false,
                            'default' => true,
                        ),
                    ),
                )
            );

            register_rest_route(
                self::ROUTE_NAMESPACE,
                '/push',
                array(
                    'methods' => WP_REST_Server::CREATABLE,
                    'callback' => array(__CLASS__, 'handle_push'),
                    'permission_callback' => array(__CLASS__, 'permission_check'),
                    'args' => array(
                        'field_groups' => array(
                            'type' => 'array',
                            'required' => true,
                        ),
                        'expected_hash' => array(
                            'type' => 'string',
                            'required' => false,
                        ),
                        'dry_run' => array(
                            'type' => 'boolean',
                            'required' => false,
                            'default' => true,
                        ),
                        'allow_field_key_changes' => array(
                            'type' => 'boolean',
                            'required' => false,
                            'default' => false,
                        ),
                    ),
                )
            );
        }

        public static function permission_check(WP_REST_Request $request)
        {
            $cap = apply_filters('acf_schema_api_required_capability', 'manage_options');
            if (is_user_logged_in() && current_user_can($cap)) {
                return true;
            }

            return new WP_Error(
                'acf_schema_api_forbidden',
                sprintf('Authentication required with capability: %s', esc_html($cap)),
                array('status' => 403)
            );
        }

        public static function handle_pull(WP_REST_Request $request)
        {
            $json_dir = self::get_json_dir();
            if (is_wp_error($json_dir)) {
                return $json_dir;
            }

            $state = self::load_effective_groups($json_dir);
            if (is_wp_error($state)) {
                return $state;
            }

            $groups_for_hash = $state['groups'];

            $response = array(
                'generated_at' => gmdate('c'),
                'schema_hash' => self::compute_schema_hash($groups_for_hash),
                'group_count' => count($groups_for_hash),
                'source_counts' => $state['source_counts'],
            );

            if ($request->get_param('include_groups')) {
                $response['field_groups'] = array_values($groups_for_hash);
            }

            if (!empty($state['warnings'])) {
                $response['warnings'] = $state['warnings'];
            }

            return rest_ensure_response($response);
        }

        public static function handle_push(WP_REST_Request $request)
        {
            $signature_check = self::verify_signed_push_request($request);
            if (is_wp_error($signature_check)) {
                return $signature_check;
            }

            $json_dir = self::get_json_dir();
            if (is_wp_error($json_dir)) {
                return $json_dir;
            }

            $state = self::load_effective_groups($json_dir);
            if (is_wp_error($state)) {
                return $state;
            }

            $current_groups = $state['groups'];

            $current_hash = self::compute_schema_hash($current_groups);
            $expected_hash = trim((string) $request->get_param('expected_hash'));
            if ($expected_hash !== '' && !hash_equals($expected_hash, $current_hash)) {
                return new WP_Error(
                    'acf_schema_api_hash_mismatch',
                    'expected_hash does not match current schema hash.',
                    array(
                        'status' => 409,
                        'current_hash' => $current_hash,
                    )
                );
            }

            $incoming_groups = $request->get_param('field_groups');
            if (!is_array($incoming_groups) || empty($incoming_groups)) {
                return new WP_Error(
                    'acf_schema_api_bad_request',
                    'field_groups must be a non-empty array.',
                    array('status' => 400)
                );
            }

            $validated = self::validate_incoming_groups($incoming_groups);
            if (is_wp_error($validated)) {
                return $validated;
            }

            $incoming_map = $validated;
            $allow_field_key_changes = (bool) $request->get_param('allow_field_key_changes');

            $duplicate_errors = self::validate_no_duplicate_sibling_field_names($incoming_map);
            if (!empty($duplicate_errors)) {
                return new WP_Error(
                    'acf_schema_api_duplicate_field_names',
                    'Duplicate sibling field names detected.',
                    array(
                        'status' => 400,
                        'errors' => $duplicate_errors,
                    )
                );
            }

            if (!$allow_field_key_changes) {
                $field_key_errors = self::validate_field_key_stability($current_groups, $incoming_map);
                if (!empty($field_key_errors)) {
                    return new WP_Error(
                        'acf_schema_api_field_key_change_blocked',
                        'Field key changes are blocked by default. Set allow_field_key_changes=true only when intentionally changing keys.',
                        array(
                            'status' => 400,
                            'errors' => $field_key_errors,
                        )
                    );
                }
            }

            $incoming_hash = self::compute_schema_hash($incoming_map);
            $plan = self::build_change_plan($current_groups, $incoming_map);
            $dry_run = (bool) $request->get_param('dry_run');

            $result = array(
                'current_hash' => $current_hash,
                'incoming_hash' => $incoming_hash,
                'dry_run' => $dry_run,
                'allow_field_key_changes' => $allow_field_key_changes,
                'plan' => $plan,
                'source_counts' => $state['source_counts'],
                'signature_verified' => true,
            );

            if (!empty($state['warnings'])) {
                $result['warnings'] = $state['warnings'];
            }

            if ($dry_run) {
                return rest_ensure_response($result);
            }

            if (!is_dir($json_dir)) {
                return new WP_Error(
                    'acf_schema_api_missing_dir',
                    'ACF JSON directory does not exist.',
                    array('status' => 500)
                );
            }

            if (!is_writable($json_dir)) {
                return new WP_Error(
                    'acf_schema_api_not_writable',
                    'ACF JSON directory is not writable.',
                    array('status' => 500)
                );
            }

            $write_errors = array();
            foreach (array_merge($plan['create'], $plan['update']) as $group_key) {
                $group = $incoming_map[$group_key];
                $filename = sanitize_file_name($group_key . '.json');
                $target_file = trailingslashit($json_dir) . $filename;

                $encoded = wp_json_encode($group, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                if (!is_string($encoded)) {
                    $write_errors[] = sprintf('Failed to encode JSON for %s.', $group_key);
                    continue;
                }

                $tmp_file = sprintf(
                    '%s.tmp-%s',
                    $target_file,
                    function_exists('wp_generate_uuid4') ? wp_generate_uuid4() : uniqid('', true)
                );

                $written = @file_put_contents($tmp_file, $encoded . PHP_EOL, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                if ($written === false) {
                    $write_errors[] = sprintf('Failed writing temporary file for %s.', $group_key);
                    continue;
                }

                if (!@rename($tmp_file, $target_file)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                    @unlink($tmp_file); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                    $write_errors[] = sprintf('Failed replacing target file for %s.', $group_key);
                    continue;
                }
            }

            if (!empty($write_errors)) {
                return new WP_Error(
                    'acf_schema_api_write_failed',
                    'One or more schema files failed to write.',
                    array(
                        'status' => 500,
                        'errors' => $write_errors,
                    )
                );
            }

            if (self::should_import_groups_to_db()) {
                $import_report = self::maybe_import_groups_to_db($incoming_map, $plan);
            } else {
                $import_report = array(
                    'attempted' => 0,
                    'imported' => 0,
                    'skipped' => count($plan['create']) + count($plan['update']),
                    'errors' => array(),
                    'mode' => 'skipped',
                    'reason' => 'DB import disabled by default. Enable with acf_schema_api_import_to_db filter.',
                );
            }
            $refreshed = self::load_effective_groups($json_dir);
            if (is_wp_error($refreshed)) {
                return $refreshed;
            }

            $result['applied'] = true;
            $result['schema_hash_after'] = self::compute_schema_hash($refreshed['groups']);
            $result['import_report'] = $import_report;
            $result['source_counts_after'] = $refreshed['source_counts'];
            if (!empty($refreshed['warnings'])) {
                $result['warnings_after'] = $refreshed['warnings'];
            }

            try {
                do_action('acf_schema_api_after_push', $result, $incoming_map, $plan);
            } catch (Throwable $e) {
                $result['after_push_hook_error'] = $e->getMessage();
            }

            return rest_ensure_response($result);
        }

        private static function get_json_dir()
        {
            $default_dir = WP_CONTENT_DIR . '/acf-json';
            if (function_exists('acf_get_setting')) {
                $configured = acf_get_setting('save_json');
                if (is_array($configured)) {
                    $configured = reset($configured);
                }
                if (is_string($configured) && $configured !== '') {
                    $default_dir = $configured;
                }
            }
            $json_dir = (string) apply_filters('acf_schema_api_json_dir', $default_dir);
            $json_dir = rtrim($json_dir, '/');

            if ($json_dir === '') {
                return new WP_Error(
                    'acf_schema_api_bad_config',
                    'Resolved JSON directory is empty.',
                    array('status' => 500)
                );
            }

            $content_real = realpath(WP_CONTENT_DIR);
            $target_real = realpath($json_dir);

            if ($target_real === false) {
                // Directory may not exist yet; validate logical path prefix as a fallback.
                $normalized_content = wp_normalize_path(WP_CONTENT_DIR);
                $normalized_target = wp_normalize_path($json_dir);
                if (strpos($normalized_target, $normalized_content) !== 0) {
                    return new WP_Error(
                        'acf_schema_api_invalid_dir',
                        'JSON directory must be under wp-content.',
                        array('status' => 500)
                    );
                }

                return $json_dir;
            }

            if ($content_real !== false) {
                $content_real = wp_normalize_path($content_real);
                $target_real = wp_normalize_path($target_real);
                if (strpos($target_real, $content_real) !== 0) {
                    return new WP_Error(
                        'acf_schema_api_invalid_dir',
                        'JSON directory must be under wp-content.',
                        array('status' => 500)
                    );
                }
            }

            return $target_real;
        }

        private static function load_effective_groups($json_dir)
        {
            $json_state = self::load_groups_from_load_json_paths($json_dir);
            if (is_wp_error($json_state)) {
                return $json_state;
            }

            $db_state = self::load_db_only_groups(array_keys($json_state['groups']));
            if (is_wp_error($db_state)) {
                return $db_state;
            }

            if (self::is_strict_json_only() && !empty($db_state['groups'])) {
                $db_only_keys = array_keys($db_state['groups']);
                sort($db_only_keys);
                return new WP_Error(
                    'acf_schema_api_strict_json_violation',
                    'Strict JSON mode is enabled and DB-only field groups were detected. Export these groups to JSON before pull/push.',
                    array(
                        'status' => 409,
                        'db_only_count' => count($db_only_keys),
                        'db_only_group_keys' => $db_only_keys,
                    )
                );
            }

            $groups = $json_state['groups'];
            foreach ($db_state['groups'] as $group_key => $group) {
                $groups[$group_key] = $group;
            }
            ksort($groups);

            return array(
                'groups' => $groups,
                'source_counts' => array(
                    'json' => count($json_state['groups']),
                    'db_only' => count($db_state['groups']),
                    'total' => count($groups),
                ),
                'warnings' => array_merge($json_state['warnings'], $db_state['warnings']),
            );
        }

        private static function load_groups_from_load_json_paths($save_json_dir)
        {
            $groups = array();
            $warnings = array();
            $group_meta = array();
            $load_paths = self::get_load_json_paths($save_json_dir);

            foreach ($load_paths as $load_path) {
                if (!is_dir($load_path)) {
                    continue;
                }

                $files = glob(trailingslashit($load_path) . 'group_*.json');
                if ($files === false) {
                    $warnings[] = sprintf('Unable to scan JSON files in path: %s', $load_path);
                    continue;
                }
                sort($files);

                foreach ($files as $file_path) {
                    $raw = @file_get_contents($file_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                    if (!is_string($raw)) {
                        $warnings[] = sprintf('Unreadable JSON file skipped: %s', $file_path);
                        continue;
                    }

                    $decoded = json_decode($raw, true);
                    if (!is_array($decoded)) {
                        $warnings[] = sprintf('Invalid JSON file skipped: %s', $file_path);
                        continue;
                    }

                    $group_key = isset($decoded['key']) ? (string) $decoded['key'] : '';
                    if (!self::is_valid_group_key($group_key)) {
                        $warnings[] = sprintf('Invalid group key in JSON file skipped: %s', $file_path);
                        continue;
                    }

                    $candidate_meta = self::build_group_source_meta($decoded, $file_path);
                    if (!isset($groups[$group_key])) {
                        $groups[$group_key] = $decoded;
                        $group_meta[$group_key] = $candidate_meta;
                        continue;
                    }

                    $current_meta = $group_meta[$group_key];
                    if (self::is_group_source_newer($candidate_meta, $current_meta)) {
                        $warnings[] = sprintf(
                            'Duplicate group key %s found in JSON paths; replacing older source with newer source (%s -> %s).',
                            $group_key,
                            $current_meta['source'],
                            $candidate_meta['source']
                        );
                        $groups[$group_key] = $decoded;
                        $group_meta[$group_key] = $candidate_meta;
                    }
                }
            }

            return array(
                'groups' => $groups,
                'warnings' => $warnings,
            );
        }

        private static function build_group_source_meta($group, $source_path = '')
        {
            $source_mtime = 0;
            if (is_string($source_path) && $source_path !== '') {
                $mtime = @filemtime($source_path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                if (is_int($mtime) || (is_string($mtime) && preg_match('/^[0-9]+$/', $mtime))) {
                    $source_mtime = (int) $mtime;
                }
            }

            return array(
                'modified' => self::extract_group_modified_timestamp($group),
                'file_mtime' => $source_mtime,
                'source' => (string) $source_path,
            );
        }

        private static function extract_group_modified_timestamp($group)
        {
            if (!is_array($group) || !array_key_exists('modified', $group)) {
                return 0;
            }

            $raw = $group['modified'];
            if (is_int($raw) || is_float($raw)) {
                return (int) $raw;
            }
            if (is_string($raw) && preg_match('/^-?[0-9]+$/', $raw)) {
                return (int) $raw;
            }

            return 0;
        }

        private static function is_group_source_newer($candidate_meta, $current_meta)
        {
            $candidate_modified = isset($candidate_meta['modified']) ? (int) $candidate_meta['modified'] : 0;
            $current_modified = isset($current_meta['modified']) ? (int) $current_meta['modified'] : 0;
            if ($candidate_modified !== $current_modified) {
                return $candidate_modified > $current_modified;
            }

            $candidate_mtime = isset($candidate_meta['file_mtime']) ? (int) $candidate_meta['file_mtime'] : 0;
            $current_mtime = isset($current_meta['file_mtime']) ? (int) $current_meta['file_mtime'] : 0;
            if ($candidate_mtime !== $current_mtime) {
                return $candidate_mtime > $current_mtime;
            }

            return false;
        }

        private static function get_load_json_paths($save_json_dir)
        {
            $paths = array();

            if (function_exists('acf_get_setting')) {
                $load_json = acf_get_setting('load_json');
                if (is_array($load_json)) {
                    foreach ($load_json as $path) {
                        if (is_string($path) && trim($path) !== '') {
                            $paths[] = rtrim($path, '/');
                        }
                    }
                }
            }

            if (is_string($save_json_dir) && $save_json_dir !== '') {
                $paths[] = rtrim($save_json_dir, '/');
            }

            $unique = array();
            $seen = array();
            foreach ($paths as $path) {
                $normalized = wp_normalize_path($path);
                if (isset($seen[$normalized])) {
                    continue;
                }
                $seen[$normalized] = true;
                $unique[] = $path;
            }

            return $unique;
        }

        private static function is_strict_json_only()
        {
            return (bool) apply_filters('acf_schema_api_strict_json_only', true);
        }

        private static function should_require_signed_push()
        {
            return (bool) apply_filters('acf_schema_api_require_signed_push', true);
        }

        private static function should_import_groups_to_db()
        {
            return (bool) apply_filters('acf_schema_api_import_to_db', false);
        }

        private static function resolve_hmac_secret()
        {
            $secret = '';

            if (defined('ACF_SCHEMA_API_HMAC_SECRET') && is_string(ACF_SCHEMA_API_HMAC_SECRET)) {
                $secret = trim((string) ACF_SCHEMA_API_HMAC_SECRET);
            }

            if ($secret === '') {
                $env = getenv('ACF_SCHEMA_API_HMAC_SECRET');
                if (is_string($env)) {
                    $secret = trim($env);
                }
            }

            $secret = (string) apply_filters('acf_schema_api_hmac_secret', $secret);
            return trim($secret);
        }

        private static function verify_signed_push_request(WP_REST_Request $request)
        {
            if (!self::should_require_signed_push()) {
                return true;
            }

            $secret = self::resolve_hmac_secret();
            if ($secret === '') {
                return new WP_Error(
                    'acf_schema_api_signature_unconfigured',
                    'Signed push is required but no HMAC secret is configured.',
                    array('status' => 500)
                );
            }

            $timestamp_raw = trim((string) $request->get_header('x-acf-schema-timestamp'));
            $nonce = trim((string) $request->get_header('x-acf-schema-nonce'));
            $signature = strtolower(trim((string) $request->get_header('x-acf-schema-signature')));

            if ($timestamp_raw === '' || $nonce === '' || $signature === '') {
                return new WP_Error(
                    'acf_schema_api_missing_signature_headers',
                    'Missing required signed push headers.',
                    array('status' => 401)
                );
            }

            if (!preg_match('/^[0-9]{10,}$/', $timestamp_raw)) {
                return new WP_Error(
                    'acf_schema_api_bad_timestamp',
                    'Invalid timestamp header format.',
                    array('status' => 401)
                );
            }
            if (!preg_match('/^[A-Za-z0-9._-]{16,128}$/', $nonce)) {
                return new WP_Error(
                    'acf_schema_api_bad_nonce',
                    'Invalid nonce header format.',
                    array('status' => 401)
                );
            }
            if (!preg_match('/^[a-f0-9]{64}$/', $signature)) {
                return new WP_Error(
                    'acf_schema_api_bad_signature',
                    'Invalid signature header format.',
                    array('status' => 401)
                );
            }

            $timestamp = (int) $timestamp_raw;
            $max_skew = (int) apply_filters('acf_schema_api_signature_max_skew', 300);
            if ($max_skew < 30) {
                $max_skew = 30;
            }
            if (abs(time() - $timestamp) > $max_skew) {
                return new WP_Error(
                    'acf_schema_api_signature_expired',
                    'Signed request timestamp is outside allowed window.',
                    array('status' => 401)
                );
            }

            $nonce_key = self::NONCE_TRANSIENT_PREFIX . hash('sha256', $nonce . '|' . $timestamp_raw);
            if (get_transient($nonce_key) !== false) {
                return new WP_Error(
                    'acf_schema_api_replay_detected',
                    'Nonce has already been used.',
                    array('status' => 409)
                );
            }

            $body_hash = hash('sha256', (string) $request->get_body());
            $canonical = implode("\n", array(
                strtoupper((string) $request->get_method()),
                (string) $request->get_route(),
                $timestamp_raw,
                $nonce,
                $body_hash,
            ));
            $expected = hash_hmac('sha256', $canonical, $secret);

            if (!hash_equals($expected, $signature)) {
                return new WP_Error(
                    'acf_schema_api_signature_mismatch',
                    'Signed request verification failed.',
                    array('status' => 401)
                );
            }

            if (!set_transient($nonce_key, '1', $max_skew)) {
                return new WP_Error(
                    'acf_schema_api_nonce_store_failed',
                    'Unable to persist nonce for replay protection.',
                    array('status' => 500)
                );
            }

            return true;
        }

        private static function load_db_only_groups($existing_group_keys)
        {
            if (!function_exists('acf_get_field_groups')) {
                return new WP_Error(
                    'acf_schema_api_acf_missing',
                    'ACF is not active or unavailable.',
                    array('status' => 500)
                );
            }

            $groups = array();
            $warnings = array();
            $existing_lookup = array_fill_keys($existing_group_keys, true);
            $db_groups = acf_get_field_groups();

            if (!is_array($db_groups)) {
                return array(
                    'groups' => array(),
                    'warnings' => array(),
                );
            }

            foreach ($db_groups as $group) {
                if (!is_array($group)) {
                    continue;
                }

                $group_key = isset($group['key']) ? (string) $group['key'] : '';
                if (!self::is_valid_group_key($group_key)) {
                    $warnings[] = sprintf('Skipping DB group with invalid key: %s', $group_key);
                    continue;
                }
                if (isset($existing_lookup[$group_key])) {
                    continue;
                }

                $fields = acf_get_fields($group_key);
                $group['fields'] = is_array($fields) ? $fields : array();

                if (function_exists('acf_prepare_field_group_for_export')) {
                    $prepared = acf_prepare_field_group_for_export($group);
                    if (is_array($prepared)) {
                        $group = $prepared;
                    }
                }

                $prepared_key = isset($group['key']) ? (string) $group['key'] : '';
                if (!self::is_valid_group_key($prepared_key)) {
                    $warnings[] = sprintf('Skipping DB group after export prep due to invalid key: %s', $prepared_key);
                    continue;
                }

                $groups[$prepared_key] = $group;
            }

            return array(
                'groups' => $groups,
                'warnings' => $warnings,
            );
        }

        private static function validate_incoming_groups($incoming_groups)
        {
            $map = array();
            $errors = array();

            foreach ($incoming_groups as $idx => $group) {
                if (!is_array($group)) {
                    $errors[] = sprintf('field_groups[%d] must be an object.', $idx);
                    continue;
                }

                $group_key = isset($group['key']) ? (string) $group['key'] : '';
                if (!self::is_valid_group_key($group_key)) {
                    $errors[] = sprintf('field_groups[%d].key must match /^group_[A-Za-z0-9_]+$/.', $idx);
                    continue;
                }

                if (isset($map[$group_key])) {
                    $errors[] = sprintf('Duplicate group key in payload: %s', $group_key);
                    continue;
                }

                $field_errors = self::validate_group_fields($group, 'field_groups[' . $idx . ']');
                if (!empty($field_errors)) {
                    $errors = array_merge($errors, $field_errors);
                    continue;
                }

                $map[$group_key] = $group;
            }

            if (!empty($errors)) {
                return new WP_Error(
                    'acf_schema_api_validation_failed',
                    'Payload validation failed.',
                    array(
                        'status' => 400,
                        'errors' => $errors,
                    )
                );
            }

            return $map;
        }

        private static function validate_group_fields($group, $path)
        {
            $errors = array();

            if (isset($group['fields']) && !is_array($group['fields'])) {
                $errors[] = sprintf('%s.fields must be an array when provided.', $path);
                return $errors;
            }

            $walk = function ($fields, $parent_path) use (&$walk, &$errors) {
                if (!is_array($fields)) {
                    $errors[] = sprintf('%s must be an array.', $parent_path);
                    return;
                }

                foreach ($fields as $i => $field) {
                    $field_path = sprintf('%s[%d]', $parent_path, $i);
                    if (!is_array($field)) {
                        $errors[] = sprintf('%s must be an object.', $field_path);
                        continue;
                    }

                    if (isset($field['key'])) {
                        $field_key = (string) $field['key'];
                        if (!self::is_valid_field_key($field_key)) {
                            $errors[] = sprintf('%s.key must match /^field_[A-Za-z0-9_]+$/.', $field_path);
                        }
                    }

                    if (isset($field['sub_fields'])) {
                        $walk($field['sub_fields'], $field_path . '.sub_fields');
                    }

                    if (isset($field['layouts']) && is_array($field['layouts'])) {
                        foreach ($field['layouts'] as $layout_idx => $layout) {
                            if (!is_array($layout)) {
                                $errors[] = sprintf('%s.layouts[%d] must be an object.', $field_path, $layout_idx);
                                continue;
                            }
                            if (isset($layout['sub_fields'])) {
                                $walk($layout['sub_fields'], $field_path . '.layouts[' . $layout_idx . '].sub_fields');
                            }
                        }
                    }
                }
            };

            if (isset($group['fields'])) {
                $walk($group['fields'], $path . '.fields');
            }

            return $errors;
        }

        private static function validate_no_duplicate_sibling_field_names($incoming_map)
        {
            $errors = array();
            foreach ($incoming_map as $group_key => $group) {
                if (!is_array($group)) {
                    continue;
                }
                if (!isset($group['fields']) || !is_array($group['fields'])) {
                    continue;
                }

                $group_label = isset($group['title']) && is_string($group['title']) && $group['title'] !== ''
                    ? $group['title']
                    : $group_key;
                $context = sprintf('%s (%s)', $group_label, $group_key);
                self::collect_duplicate_sibling_names($group['fields'], $context, $errors);
            }

            return $errors;
        }

        private static function collect_duplicate_sibling_names($fields, $context, &$errors)
        {
            if (!is_array($fields)) {
                return;
            }

            $seen = array();
            foreach ($fields as $field) {
                if (!is_array($field)) {
                    continue;
                }
                $name = isset($field['name']) ? trim((string) $field['name']) : '';
                if ($name === '') {
                    continue;
                }
                if (isset($seen[$name])) {
                    $errors[] = sprintf('%s: duplicate sibling field name "%s".', $context, $name);
                } else {
                    $seen[$name] = true;
                }
            }

            foreach ($fields as $field) {
                if (!is_array($field)) {
                    continue;
                }

                $child_name = isset($field['name']) && trim((string) $field['name']) !== ''
                    ? trim((string) $field['name'])
                    : (isset($field['key']) ? (string) $field['key'] : 'field');
                $child_context = $context . '/' . $child_name;

                if (isset($field['sub_fields']) && is_array($field['sub_fields'])) {
                    self::collect_duplicate_sibling_names($field['sub_fields'], $child_context, $errors);
                }

                if (!isset($field['layouts'])) {
                    continue;
                }

                $layouts = $field['layouts'];
                if (is_array($layouts)) {
                    if (self::is_assoc_array($layouts)) {
                        foreach ($layouts as $layout) {
                            if (!is_array($layout)) {
                                continue;
                            }
                            $layout_name = isset($layout['name']) && trim((string) $layout['name']) !== ''
                                ? trim((string) $layout['name'])
                                : (isset($layout['key']) ? (string) $layout['key'] : 'layout');
                            if (isset($layout['sub_fields']) && is_array($layout['sub_fields'])) {
                                self::collect_duplicate_sibling_names(
                                    $layout['sub_fields'],
                                    $child_context . '/layout:' . $layout_name,
                                    $errors
                                );
                            }
                        }
                    } else {
                        foreach ($layouts as $layout) {
                            if (!is_array($layout)) {
                                continue;
                            }
                            $layout_name = isset($layout['name']) && trim((string) $layout['name']) !== ''
                                ? trim((string) $layout['name'])
                                : (isset($layout['key']) ? (string) $layout['key'] : 'layout');
                            if (isset($layout['sub_fields']) && is_array($layout['sub_fields'])) {
                                self::collect_duplicate_sibling_names(
                                    $layout['sub_fields'],
                                    $child_context . '/layout:' . $layout_name,
                                    $errors
                                );
                            }
                        }
                    }
                }
            }
        }

        private static function validate_field_key_stability($current_map, $incoming_map)
        {
            $errors = array();

            foreach ($incoming_map as $group_key => $incoming_group) {
                if (!isset($current_map[$group_key])) {
                    continue;
                }

                $current_keys = self::collect_group_field_keys($current_map[$group_key]);
                $incoming_keys = self::collect_group_field_keys($incoming_group);

                $removed = array_diff(array_keys($current_keys), array_keys($incoming_keys));
                $added = array_diff(array_keys($incoming_keys), array_keys($current_keys));

                if (empty($removed) && empty($added)) {
                    continue;
                }

                sort($removed);
                sort($added);

                $parts = array();
                if (!empty($removed)) {
                    $parts[] = sprintf(
                        'removed (%d): %s',
                        count($removed),
                        self::format_key_preview($removed)
                    );
                }
                if (!empty($added)) {
                    $parts[] = sprintf(
                        'added (%d): %s',
                        count($added),
                        self::format_key_preview($added)
                    );
                }

                $errors[] = sprintf('Group %s field key set changed - %s.', $group_key, implode('; ', $parts));
            }

            return $errors;
        }

        private static function collect_group_field_keys($group)
        {
            $keys = array();
            self::collect_field_keys_recursive($group, $keys);
            return $keys;
        }

        private static function collect_field_keys_recursive($node, &$keys)
        {
            if (!is_array($node)) {
                return;
            }

            foreach ($node as $key => $value) {
                if ($key === 'key' && is_string($value) && self::is_valid_field_key($value)) {
                    $keys[$value] = true;
                }
                self::collect_field_keys_recursive($value, $keys);
            }
        }

        private static function format_key_preview($keys)
        {
            $max = 10;
            $slice = array_slice($keys, 0, $max);
            $text = implode(', ', $slice);
            if (count($keys) > $max) {
                $text .= ', ...';
            }
            return $text;
        }

        private static function build_change_plan($current_map, $incoming_map)
        {
            $create = array();
            $update = array();
            $unchanged = array();

            foreach ($incoming_map as $group_key => $incoming_group) {
                if (!isset($current_map[$group_key])) {
                    $create[] = $group_key;
                    continue;
                }

                $current_norm = self::normalize_for_hash($current_map[$group_key]);
                $incoming_norm = self::normalize_for_hash($incoming_group);
                if ($current_norm === $incoming_norm) {
                    $unchanged[] = $group_key;
                } else {
                    $update[] = $group_key;
                }
            }

            return array(
                'create' => $create,
                'update' => $update,
                'unchanged' => $unchanged,
                'create_count' => count($create),
                'update_count' => count($update),
                'unchanged_count' => count($unchanged),
            );
        }

        private static function maybe_import_groups_to_db($incoming_map, $plan)
        {
            $report = array(
                'attempted' => 0,
                'imported' => 0,
                'skipped' => 0,
                'errors' => array(),
            );

            if (!function_exists('acf_import_field_group')) {
                $report['skipped'] = count($plan['create']) + count($plan['update']);
                $report['errors'][] = 'acf_import_field_group() not available. JSON files were written; DB sync may still require ACF sync process.';
                return $report;
            }

            foreach (array_merge($plan['create'], $plan['update']) as $group_key) {
                $report['attempted']++;
                try {
                    acf_import_field_group($incoming_map[$group_key]);
                    $report['imported']++;
                } catch (Throwable $e) {
                    $report['errors'][] = sprintf('Import failed for %s: %s', $group_key, $e->getMessage());
                }
            }

            return $report;
        }

        private static function compute_schema_hash($group_map)
        {
            if (!is_array($group_map)) {
                return hash('sha256', '');
            }

            ksort($group_map);
            $normalized = array();
            foreach ($group_map as $group_key => $group) {
                $normalized[$group_key] = self::normalize_for_hash($group);
            }

            $encoded = wp_json_encode($normalized, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (!is_string($encoded)) {
                return hash('sha256', '');
            }

            return hash('sha256', $encoded);
        }

        private static function normalize_for_hash($value)
        {
            if (is_array($value)) {
                if (self::is_assoc_array($value)) {
                    ksort($value);
                    foreach ($value as $k => $v) {
                        $value[$k] = self::normalize_for_hash($v);
                    }
                    return $value;
                }

                foreach ($value as $idx => $item) {
                    $value[$idx] = self::normalize_for_hash($item);
                }
                return $value;
            }

            return $value;
        }

        private static function is_assoc_array(array $arr)
        {
            if ($arr === array()) {
                return false;
            }

            return array_keys($arr) !== range(0, count($arr) - 1);
        }

        private static function is_valid_group_key($value)
        {
            return (bool) preg_match('/^group_[A-Za-z0-9_]+$/', $value);
        }

        private static function is_valid_field_key($value)
        {
            return (bool) preg_match('/^field_[A-Za-z0-9_]+$/', $value);
        }
    }
}

RG_ACF_Schema_API::init();
