<?php
/**
 * Plugin Name: ACF Schema API
 * Description: REST endpoints to pull and push ACF schema JSON plus plugin-managed bootstrap and content APIs for local automation.
 * Version: 1.5.9
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: RG Ops
 * Text Domain: acf-schema-api
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('RG_ACF_Schema_API')) {
    final class RG_ACF_Schema_API
    {
        const ROUTE_NAMESPACE = 'acf-schema/v1';
        const AUTOMATION_ROUTE_NAMESPACE = 'acf-automation/v1';
        const NONCE_TRANSIENT_PREFIX = 'acf_schema_api_nonce_';
        const OPTION_AUTOMATION_SITE_ID = 'acf_automation_site_id';
        const OPTION_AUTOMATION_SECRET_HASH = 'acf_automation_secret_hash';
        const OPTION_AUTOMATION_CLAIM_TOKEN_HASH = 'acf_automation_claim_token_hash';
        const OPTION_AUTOMATION_CLAIM_EXPIRES_AT = 'acf_automation_claim_expires_at';
        const OPTION_AUTOMATION_ALLOWED_RESOURCE_TYPES = 'acf_automation_allowed_resource_types';
        const OPTION_AUTOMATION_ENABLED = 'acf_automation_enabled';
        const OPTION_AUTOMATION_AUTO_EXPORT_DB_ONLY = 'acf_automation_auto_export_db_only';
        const TRANSIENT_AUTOMATION_SECRET_PREVIEW = 'acf_automation_secret_preview';
        const TRANSIENT_APP_PASSWORD_ENV_PREVIEW = 'acf_automation_app_password_env_preview';
        const CLAIM_TOKEN_TTL = DAY_IN_SECONDS;
        const SECRET_PREVIEW_TTL = 900;
        const ADMIN_PAGE_SLUG = 'acf-codex-automation';
        const HEADER_AUTOMATION_SITE = 'x-acf-automation-site';
        const HEADER_AUTOMATION_SECRET = 'x-acf-automation-secret';

        public static function init()
        {
            add_action('rest_api_init', array(__CLASS__, 'register_routes'));
            add_action('admin_menu', array(__CLASS__, 'register_admin_page'));
            add_filter('plugin_action_links_' . plugin_basename(__FILE__), array(__CLASS__, 'plugin_action_links'));
        }

        public static function register_routes()
        {
            register_rest_route(
                self::ROUTE_NAMESPACE,
                '/pull',
                array(
                    'methods' => WP_REST_Server::CREATABLE,
                    'callback' => array(__CLASS__, 'handle_pull'),
                    'permission_callback' => array(__CLASS__, 'schema_permission_check'),
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
                    'permission_callback' => array(__CLASS__, 'schema_permission_check'),
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
                        'delete_missing_groups' => array(
                            'type' => 'boolean',
                            'required' => false,
                            'default' => false,
                        ),
                        'suppress_legacy_build_hooks' => array(
                            'type' => 'boolean',
                            'required' => false,
                            'default' => true,
                        ),
                    ),
                )
            );

            register_rest_route(
                self::AUTOMATION_ROUTE_NAMESPACE,
                '/bootstrap/status',
                array(
                    'methods' => WP_REST_Server::READABLE,
                    'callback' => array(__CLASS__, 'handle_bootstrap_status'),
                    'permission_callback' => array(__CLASS__, 'bootstrap_status_permission_check'),
                )
            );

            register_rest_route(
                self::AUTOMATION_ROUTE_NAMESPACE,
                '/bootstrap/claim',
                array(
                    'methods' => WP_REST_Server::CREATABLE,
                    'callback' => array(__CLASS__, 'handle_bootstrap_claim'),
                    'permission_callback' => '__return_true',
                    'args' => array(
                        'claim_token' => array(
                            'type' => 'string',
                            'required' => true,
                        ),
                    ),
                )
            );

            register_rest_route(
                self::AUTOMATION_ROUTE_NAMESPACE,
                '/bootstrap/rotate',
                array(
                    'methods' => WP_REST_Server::CREATABLE,
                    'callback' => array(__CLASS__, 'handle_bootstrap_rotate'),
                    'permission_callback' => array(__CLASS__, 'admin_permission_check'),
                )
            );

            register_rest_route(
                self::AUTOMATION_ROUTE_NAMESPACE,
                '/content/(?P<resource_type>[A-Za-z0-9_-]+)/(?P<resource_id>[0-9]+)',
                array(
                    array(
                        'methods' => WP_REST_Server::READABLE,
                        'callback' => array(__CLASS__, 'handle_content_get'),
                        'permission_callback' => array(__CLASS__, 'content_permission_check'),
                    ),
                    array(
                        'methods' => WP_REST_Server::CREATABLE,
                        'callback' => array(__CLASS__, 'handle_content_post'),
                        'permission_callback' => array(__CLASS__, 'content_permission_check'),
                        'args' => array(
                            'dry_run' => array(
                                'type' => 'boolean',
                                'required' => false,
                                'default' => false,
                            ),
                        ),
                    ),
                )
            );
        }

        public static function activate()
        {
            self::ensure_automation_defaults();
            self::maybe_issue_claim_token(false);
        }

        public static function schema_permission_check(WP_REST_Request $request)
        {
            $auth = self::authenticate_request(
                $request,
                array(
                    'allow_plugin_secret' => true,
                    'allow_admin' => true,
                    'capability' => self::required_capability(),
                )
            );

            if (is_wp_error($auth)) {
                return $auth;
            }

            return true;
        }

        public static function bootstrap_status_permission_check(WP_REST_Request $request)
        {
            $auth = self::authenticate_request(
                $request,
                array(
                    'allow_plugin_secret' => true,
                    'allow_admin' => true,
                    'capability' => self::required_capability(),
                )
            );

            if (is_wp_error($auth)) {
                return $auth;
            }

            return true;
        }

        public static function admin_permission_check(WP_REST_Request $request)
        {
            $auth = self::authenticate_request(
                $request,
                array(
                    'allow_plugin_secret' => false,
                    'allow_admin' => true,
                    'capability' => self::required_capability(),
                )
            );

            if (is_wp_error($auth)) {
                return $auth;
            }

            return true;
        }

        public static function content_permission_check(WP_REST_Request $request)
        {
            $auth = self::authenticate_request(
                $request,
                array(
                    'allow_plugin_secret' => true,
                    'allow_admin' => true,
                    'capability' => self::required_capability(),
                )
            );

            if (is_wp_error($auth)) {
                return $auth;
            }

            return true;
        }

        public static function permission_check(WP_REST_Request $request)
        {
            return self::schema_permission_check($request);
        }

        public static function register_admin_page()
        {
            add_options_page(
                'AI Automation',
                'AI Automation',
                self::required_capability(),
                self::ADMIN_PAGE_SLUG,
                array(__CLASS__, 'render_admin_page')
            );
        }

        public static function plugin_action_links($links)
        {
            if (!current_user_can(self::required_capability())) {
                return $links;
            }

            $settings_link = sprintf(
                '<a href="%s">Settings</a>',
                esc_url(admin_url('options-general.php?page=' . self::ADMIN_PAGE_SLUG))
            );

            array_unshift($links, $settings_link);

            return $links;
        }

        public static function render_admin_page()
        {
            if (!current_user_can(self::required_capability())) {
                wp_die('Insufficient permissions.');
            }

            self::ensure_automation_defaults();

            $notice = '';
            $notice_type = 'updated';
            $claim_token = '';
            $env_block = '';
            $app_password_env_block = '';
            $json_dir = self::get_json_dir();

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                check_admin_referer('acf_automation_admin_action', 'acf_automation_nonce');
                $action = isset($_POST['acf_automation_action']) ? sanitize_key((string) $_POST['acf_automation_action']) : '';

                if ($action === 'generate_env_block') {
                    $automation_secret = self::issue_automation_secret();
                    $env_block = self::build_env_block($automation_secret);
                    $notice = 'Generated a new automation secret. Copy the .env block now; the secret is only shown once.';
                } elseif ($action === 'generate_wp_api_env_block') {
                    $app_password_result = self::issue_application_password_env_block_for_user(get_current_user_id());
                    if (is_wp_error($app_password_result)) {
                        $notice = $app_password_result->get_error_message();
                        $notice_type = 'notice-error';
                    } else {
                        $app_password_env_block = $app_password_result['env_block'];
                        $notice = 'Generated a new WordPress Application Password .env block for the current admin user. Copy it now; the password is only shown once.';
                    }
                } elseif ($action === 'generate_claim_token') {
                    $claim_token = self::maybe_issue_claim_token(true);
                    $notice = 'Generated a new one-time claim token.';
                } elseif ($action === 'rotate_secret') {
                    $automation_secret = self::issue_automation_secret();
                    $env_block = self::build_env_block($automation_secret);
                    $notice = 'Rotated automation access. Previous automation secret is now invalid. Copy the new .env block now; the secret is only shown once.';
                } elseif ($action === 'disable_automation') {
                    update_option(self::OPTION_AUTOMATION_ENABLED, false, false);
                    self::clear_automation_secret();
                    self::clear_claim_token();
                    $notice = 'Automation has been disabled.';
                    $notice_type = 'notice-warning';
                } elseif ($action === 'enable_automation') {
                    update_option(self::OPTION_AUTOMATION_ENABLED, true, false);
                    $automation_secret = self::issue_automation_secret();
                    $env_block = self::build_env_block($automation_secret);
                    $notice = 'Automation has been enabled. Copy the .env block now; the secret is only shown once.';
                } elseif ($action === 'enable_auto_export_db_only') {
                    update_option(self::OPTION_AUTOMATION_AUTO_EXPORT_DB_ONLY, true, false);
                    $notice = 'Automatic DB-only group export is now enabled for pull/push.';
                } elseif ($action === 'disable_auto_export_db_only') {
                    update_option(self::OPTION_AUTOMATION_AUTO_EXPORT_DB_ONLY, false, false);
                    $notice = 'Automatic DB-only group export has been disabled.';
                    $notice_type = 'notice-info';
                } elseif ($action === 'export_db_only_groups') {
                    $export_report = self::export_db_only_groups_to_json($json_dir);
                    if (is_wp_error($export_report)) {
                        $notice = $export_report->get_error_message();
                        $notice_type = 'notice-error';
                    } elseif (!empty($export_report['exported'])) {
                        $notice = sprintf(
                            'Exported %d DB-only field group%s to JSON.',
                            (int) $export_report['exported'],
                            ((int) $export_report['exported'] === 1) ? '' : 's'
                        );
                    } else {
                        $notice = 'No DB-only field groups needed export.';
                        $notice_type = 'notice-info';
                    }
                }
            }

            if ($env_block === '') {
                $preview_secret = self::get_automation_secret_preview();
                if ($preview_secret !== '') {
                    $env_block = self::build_env_block($preview_secret);
                }
            }

            if ($app_password_env_block === '') {
                $app_password_env_block = self::get_application_password_env_preview();
            }

            if ($env_block === '' && !self::is_automation_claimed() && self::is_automation_enabled()) {
                $automation_secret = self::issue_automation_secret();
                $env_block = self::build_env_block($automation_secret);
            }

            $status = self::build_bootstrap_status_payload(true, $claim_token);
            $strict_json_status = self::build_strict_json_status($json_dir);
            $claim_command = '';
            if (!empty($status['claim_token'])) {
                $claim_command = sprintf(
                    'scripts/bootstrap-repo.sh --claim-token %s',
                    $status['claim_token']
                );
            }
            $env_placeholder_block = '';
            if ($env_block === '' && $status['enabled']) {
                $env_placeholder_block = self::build_env_block('<rotate-to-generate-new-secret>');
            }
            ?>
            <div class="wrap">
                <h1>AI Automation</h1>
                <?php if ($notice !== '') : ?>
                    <div class="notice <?php echo esc_attr($notice_type); ?> is-dismissible"><p><?php echo esc_html($notice); ?></p></div>
                <?php endif; ?>

                <?php if ($env_block !== '') : ?>
                    <h2>Copy Into Your Repo <code>.env</code></h2>
                    <p>This automation secret is shown only once. Paste it into the target repo root as <code>.env</code>.</p>
                    <textarea readonly rows="10" style="width: 100%; max-width: 960px; font-family: monospace;" onclick="this.focus();this.select();"><?php echo esc_textarea($env_block); ?></textarea>
                <?php elseif ($env_placeholder_block !== '') : ?>
                    <h2>Repo <code>.env</code></h2>
                    <p>Automation is already configured. The current secret cannot be shown again because only a hash is stored. Use <strong>Rotate Secret and Show New .env Block</strong> to generate a fresh real secret.</p>
                    <textarea readonly rows="10" style="width: 100%; max-width: 960px; font-family: monospace;" onclick="this.focus();this.select();"><?php echo esc_textarea($env_placeholder_block); ?></textarea>
                <?php endif; ?>

                <h2>WP REST App Password</h2>
                <p>Generate a standard WordPress REST API Application Password block for the current admin user. This is useful when you want the local scripts to force legacy REST auth instead of plugin-secret auth.</p>
                <form method="post" style="margin-top: 8px;">
                    <?php wp_nonce_field('acf_automation_admin_action', 'acf_automation_nonce'); ?>
                    <input type="hidden" name="acf_automation_action" value="generate_wp_api_env_block" />
                    <?php submit_button('Generate WP REST App Password .env Block', 'secondary', 'submit', false); ?>
                </form>
                <?php if ($app_password_env_block !== '') : ?>
                    <textarea readonly rows="8" style="width: 100%; max-width: 960px; font-family: monospace; margin-top: 8px;" onclick="this.focus();this.select();"><?php echo esc_textarea($app_password_env_block); ?></textarea>
                <?php endif; ?>

                <h2>Schema JSON Status</h2>
                <?php if (is_wp_error($strict_json_status)) : ?>
                    <div class="notice notice-error inline"><p><?php echo esc_html($strict_json_status->get_error_message()); ?></p></div>
                <?php else : ?>
                    <table class="widefat striped" style="max-width: 960px;">
                        <tbody>
                            <tr><th>Strict JSON Only</th><td><?php echo esc_html($strict_json_status['strict_json_only'] ? 'Yes' : 'No'); ?></td></tr>
                            <tr><th>JSON Directory</th><td><code><?php echo esc_html($strict_json_status['json_dir']); ?></code></td></tr>
                            <tr><th>JSON Groups</th><td><?php echo esc_html((string) $strict_json_status['source_counts']['json']); ?></td></tr>
                            <tr><th>DB-only Groups</th><td><?php echo esc_html((string) $strict_json_status['source_counts']['db_only']); ?></td></tr>
                            <tr><th>Auto-export on Pull/Push</th><td><?php echo esc_html($strict_json_status['auto_export_enabled'] ? 'Enabled' : 'Disabled'); ?></td></tr>
                        </tbody>
                    </table>
                    <form method="post" style="margin-top: 8px;">
                        <?php wp_nonce_field('acf_automation_admin_action', 'acf_automation_nonce'); ?>
                        <input type="hidden" name="acf_automation_action" value="<?php echo esc_attr($strict_json_status['auto_export_enabled'] ? 'disable_auto_export_db_only' : 'enable_auto_export_db_only'); ?>" />
                        <?php submit_button($strict_json_status['auto_export_enabled'] ? 'Disable Auto-Export During Pull/Push' : 'Enable Auto-Export During Pull/Push', 'secondary', 'submit', false); ?>
                    </form>

                    <?php if (!empty($strict_json_status['source_counts']['db_only'])) : ?>
                        <p style="max-width: 960px;">
                            <?php if ($strict_json_status['strict_json_only']) : ?>
                                Strict JSON pull/push is blocked until these DB-only field groups are exported to JSON on the server.
                            <?php else : ?>
                                These field groups currently exist only in the database. Exporting them keeps JSON in sync with ACF.
                            <?php endif; ?>
                        </p>
                        <textarea readonly rows="8" style="width: 100%; max-width: 960px; font-family: monospace;" onclick="this.focus();this.select();"><?php echo esc_textarea(implode("\n", $strict_json_status['db_only_group_keys'])); ?></textarea>
                        <form method="post" style="margin-top: 8px;">
                            <?php wp_nonce_field('acf_automation_admin_action', 'acf_automation_nonce'); ?>
                            <input type="hidden" name="acf_automation_action" value="export_db_only_groups" />
                            <?php submit_button('Export DB-Only Groups to JSON', 'secondary', 'submit', false); ?>
                        </form>
                        <?php if (!$strict_json_status['auto_export_enabled']) : ?>
                            <p style="max-width: 960px;">
                                Automatic export can be enabled above. Developers can also override it with the <code>acf_schema_api_auto_export_db_only_groups</code> filter.
                            </p>
                        <?php endif; ?>
                    <?php else : ?>
                        <p style="max-width: 960px;">No DB-only field groups are currently blocking strict JSON pull/push.</p>
                    <?php endif; ?>

                    <?php if (!empty($strict_json_status['warnings'])) : ?>
                        <details style="max-width: 960px; margin: 12px 0;">
                            <summary>Schema scan warnings</summary>
                            <ul>
                                <?php foreach ($strict_json_status['warnings'] as $warning) : ?>
                                    <li><?php echo esc_html($warning); ?></li>
                                <?php endforeach; ?>
                            </ul>
                        </details>
                    <?php endif; ?>
                <?php endif; ?>

                <table class="widefat striped" style="max-width: 960px;">
                    <tbody>
                        <tr><th>Status</th><td><?php echo esc_html($status['claimed'] ? 'Claimed' : 'Unclaimed'); ?></td></tr>
                        <tr><th>Enabled</th><td><?php echo esc_html($status['enabled'] ? 'Yes' : 'No'); ?></td></tr>
                        <tr><th>Site ID</th><td><code><?php echo esc_html($status['site_id']); ?></code></td></tr>
                        <tr><th>Allowed resource types</th><td><code><?php echo esc_html(implode(',', $status['allowed_resource_types'])); ?></code></td></tr>
                        <tr><th>Schema pull path</th><td><code><?php echo esc_html($status['schema_pull_path']); ?></code></td></tr>
                        <tr><th>Schema push path</th><td><code><?php echo esc_html($status['schema_push_path']); ?></code></td></tr>
                        <tr><th>Content path</th><td><code><?php echo esc_html($status['content_base_path']); ?></code></td></tr>
                        <?php if (!empty($status['claim_token'])) : ?>
                            <tr><th>Claim token</th><td><code><?php echo esc_html($status['claim_token']); ?></code></td></tr>
                            <tr><th>Expires at</th><td><code><?php echo esc_html($status['claim_expires_at']); ?></code></td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>

                <form method="post" style="margin-top: 16px;">
                    <?php wp_nonce_field('acf_automation_admin_action', 'acf_automation_nonce'); ?>
                    <?php if ($status['enabled']) : ?>
                        <input type="hidden" name="acf_automation_action" value="<?php echo esc_attr($status['claimed'] ? 'rotate_secret' : 'generate_env_block'); ?>" />
                        <?php submit_button($status['claimed'] ? 'Rotate Secret and Show New .env Block' : 'Generate Copyable .env Block', 'primary', 'submit', false); ?>
                    <?php else : ?>
                        <input type="hidden" name="acf_automation_action" value="enable_automation" />
                        <?php submit_button('Enable Automation', 'primary', 'submit', false); ?>
                    <?php endif; ?>
                </form>

                <?php if ($status['enabled']) : ?>
                    <form method="post" style="margin-top: 8px;">
                        <?php wp_nonce_field('acf_automation_admin_action', 'acf_automation_nonce'); ?>
                        <input type="hidden" name="acf_automation_action" value="generate_claim_token" />
                        <?php submit_button('Advanced: Generate CLI Claim Token', 'secondary', 'submit', false); ?>
                    </form>
                    <?php if ($claim_command !== '') : ?>
                        <p><strong>Advanced CLI bootstrap:</strong> <code><?php echo esc_html($claim_command); ?></code></p>
                    <?php endif; ?>
                <?php endif; ?>

                <form method="post" style="margin-top: 8px;">
                    <?php wp_nonce_field('acf_automation_admin_action', 'acf_automation_nonce'); ?>
                    <input type="hidden" name="acf_automation_action" value="disable_automation" />
                    <?php submit_button('Disable Automation', 'delete', 'submit', false, array('onclick' => "return confirm('Disable automation and invalidate existing credentials?');")); ?>
                </form>
            </div>
            <?php
        }

        public static function handle_bootstrap_status(WP_REST_Request $request)
        {
            $auth = self::authenticate_request(
                $request,
                array(
                    'allow_plugin_secret' => true,
                    'allow_admin' => true,
                    'capability' => self::required_capability(),
                )
            );
            if (is_wp_error($auth)) {
                return $auth;
            }

            $include_claim_token = ($auth['mode'] === 'admin');
            $claim_token = '';
            if ($include_claim_token && !self::is_automation_claimed() && self::is_automation_enabled()) {
                $claim_token = self::maybe_issue_claim_token(true);
            }

            return rest_ensure_response(self::build_bootstrap_status_payload($include_claim_token, $claim_token));
        }

        public static function handle_bootstrap_claim(WP_REST_Request $request)
        {
            $https = self::ensure_https_request();
            if (is_wp_error($https)) {
                return $https;
            }

            self::ensure_automation_defaults();
            if (!self::is_automation_enabled()) {
                return new WP_Error(
                    'acf_automation_disabled',
                    'Automation is disabled for this site.',
                    array('status' => 403)
                );
            }

            $claim_token = trim((string) $request->get_param('claim_token'));
            if ($claim_token === '') {
                return new WP_Error(
                    'acf_automation_missing_claim_token',
                    'claim_token is required.',
                    array('status' => 400)
                );
            }

            $validation = self::validate_claim_token($claim_token);
            if (is_wp_error($validation)) {
                return $validation;
            }

            $secret = self::generate_secret(32);
            update_option(self::OPTION_AUTOMATION_SECRET_HASH, wp_hash_password($secret), false);
            self::clear_claim_token();

            $payload = self::build_bootstrap_status_payload(false, '');
            $payload['automation_secret'] = $secret;
            return rest_ensure_response($payload);
        }

        public static function handle_bootstrap_rotate(WP_REST_Request $request)
        {
            $auth = self::authenticate_request(
                $request,
                array(
                    'allow_plugin_secret' => false,
                    'allow_admin' => true,
                    'capability' => self::required_capability(),
                )
            );
            if (is_wp_error($auth)) {
                return $auth;
            }

            self::ensure_automation_defaults();
            self::clear_automation_secret();
            $claim_token = self::maybe_issue_claim_token(true);

            return rest_ensure_response(self::build_bootstrap_status_payload(true, $claim_token));
        }

        public static function handle_content_get(WP_REST_Request $request)
        {
            $auth = self::authenticate_request(
                $request,
                array(
                    'allow_plugin_secret' => true,
                    'allow_admin' => true,
                    'capability' => self::required_capability(),
                )
            );
            if (is_wp_error($auth)) {
                return $auth;
            }

            $resource_type = sanitize_key((string) $request['resource_type']);
            $resource_id = (int) $request['resource_id'];
            $post = self::load_content_resource($resource_type, $resource_id);
            if (is_wp_error($post)) {
                return $post;
            }

            $response = self::build_content_response($resource_type, $post, false, array());
            if (is_wp_error($response)) {
                return $response;
            }

            return rest_ensure_response($response);
        }

        public static function handle_content_post(WP_REST_Request $request)
        {
            $auth = self::authenticate_request(
                $request,
                array(
                    'allow_plugin_secret' => true,
                    'allow_admin' => true,
                    'capability' => self::required_capability(),
                )
            );
            if (is_wp_error($auth)) {
                return $auth;
            }

            $resource_type = sanitize_key((string) $request['resource_type']);
            $resource_id = (int) $request['resource_id'];
            $post = self::load_content_resource($resource_type, $resource_id);
            if (is_wp_error($post)) {
                return $post;
            }

            $payload = $request->get_json_params();
            if (!is_array($payload) || array_diff(array_keys($payload), array('acf')) !== array()) {
                return new WP_Error(
                    'acf_automation_bad_payload',
                    "Payload must be a JSON object with only an 'acf' object.",
                    array('status' => 400)
                );
            }
            if (!isset($payload['acf']) || !is_array($payload['acf'])) {
                return new WP_Error(
                    'acf_automation_bad_payload',
                    "Payload must include an 'acf' object.",
                    array('status' => 400)
                );
            }

            $dry_run = rest_sanitize_boolean($request->get_param('dry_run'));
            $requested_fields = array_keys($payload['acf']);

            if (!$dry_run) {
                $apply = self::apply_content_update($post->ID, $payload['acf']);
                if (is_wp_error($apply)) {
                    return $apply;
                }
            }

            $response = self::build_content_response($resource_type, get_post($post->ID), $dry_run, $requested_fields);
            if (is_wp_error($response)) {
                return $response;
            }

            return rest_ensure_response($response);
        }

        private static function required_capability()
        {
            return (string) apply_filters('acf_automation_required_capability', apply_filters('acf_schema_api_required_capability', 'manage_options'));
        }

        private static function authenticate_request(WP_REST_Request $request, $args = array())
        {
            $args = wp_parse_args(
                $args,
                array(
                    'allow_plugin_secret' => true,
                    'allow_admin' => true,
                    'capability' => self::required_capability(),
                )
            );

            if ($args['allow_plugin_secret'] && self::has_plugin_secret_headers($request)) {
                $plugin_auth = self::authenticate_plugin_secret($request);
                if (is_wp_error($plugin_auth)) {
                    return $plugin_auth;
                }
                return $plugin_auth;
            }

            if ($args['allow_admin'] && is_user_logged_in() && current_user_can($args['capability'])) {
                return array('mode' => 'admin');
            }

            return new WP_Error(
                'acf_automation_forbidden',
                sprintf('Authentication required with capability: %s', esc_html($args['capability'])),
                array('status' => 403)
            );
        }

        private static function has_plugin_secret_headers(WP_REST_Request $request)
        {
            return trim((string) $request->get_header(self::HEADER_AUTOMATION_SITE)) !== '' || trim((string) $request->get_header(self::HEADER_AUTOMATION_SECRET)) !== '';
        }

        private static function authenticate_plugin_secret(WP_REST_Request $request)
        {
            if (!self::is_automation_enabled()) {
                return new WP_Error(
                    'acf_automation_disabled',
                    'Automation is disabled for this site.',
                    array('status' => 403)
                );
            }

            $https = self::ensure_https_request();
            if (is_wp_error($https)) {
                return $https;
            }

            $site_id = trim((string) $request->get_header(self::HEADER_AUTOMATION_SITE));
            $secret = trim((string) $request->get_header(self::HEADER_AUTOMATION_SECRET));
            if ($site_id === '' || $secret === '') {
                return new WP_Error(
                    'acf_automation_missing_headers',
                    'Missing automation authentication headers.',
                    array('status' => 401)
                );
            }

            $stored_site_id = (string) get_option(self::OPTION_AUTOMATION_SITE_ID, '');
            $secret_hash = (string) get_option(self::OPTION_AUTOMATION_SECRET_HASH, '');
            if ($stored_site_id === '' || $secret_hash === '') {
                return new WP_Error(
                    'acf_automation_unclaimed',
                    'Automation secret has not been claimed for this site.',
                    array('status' => 401)
                );
            }

            if (!hash_equals($stored_site_id, $site_id)) {
                return new WP_Error(
                    'acf_automation_bad_site',
                    'Automation site ID did not match this site.',
                    array('status' => 401)
                );
            }

            if (!wp_check_password($secret, $secret_hash)) {
                return new WP_Error(
                    'acf_automation_bad_secret',
                    'Automation secret verification failed.',
                    array('status' => 401)
                );
            }

            return array(
                'mode' => 'plugin_secret',
                'site_id' => $stored_site_id,
            );
        }

        private static function ensure_https_request()
        {
            $secure = is_ssl();
            if (!$secure && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
                $secure = strtolower((string) $_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https';
            }
            if (!$secure && isset($_SERVER['HTTP_X_FORWARDED_SSL'])) {
                $secure = strtolower((string) $_SERVER['HTTP_X_FORWARDED_SSL']) === 'on';
            }

            if (!$secure) {
                return new WP_Error(
                    'acf_automation_https_required',
                    'Automation secret flows require HTTPS.',
                    array('status' => 400)
                );
            }

            return true;
        }

        private static function ensure_automation_defaults()
        {
            $site_id = (string) get_option(self::OPTION_AUTOMATION_SITE_ID, '');
            if ($site_id === '') {
                update_option(self::OPTION_AUTOMATION_SITE_ID, self::generate_site_id(), false);
            }

            if (get_option(self::OPTION_AUTOMATION_ENABLED, null) === null) {
                update_option(self::OPTION_AUTOMATION_ENABLED, true, false);
            }

            if (!is_array(get_option(self::OPTION_AUTOMATION_ALLOWED_RESOURCE_TYPES, null))) {
                update_option(self::OPTION_AUTOMATION_ALLOWED_RESOURCE_TYPES, self::default_allowed_resource_types(), false);
            }

            if (get_option(self::OPTION_AUTOMATION_AUTO_EXPORT_DB_ONLY, null) === null) {
                update_option(self::OPTION_AUTOMATION_AUTO_EXPORT_DB_ONLY, false, false);
            }
        }

        private static function generate_site_id()
        {
            $raw = function_exists('wp_generate_uuid4') ? wp_generate_uuid4() : uniqid('acf-site-', true);
            return 'site_' . preg_replace('/[^A-Za-z0-9_-]/', '', str_replace('.', '', (string) $raw));
        }

        private static function default_allowed_resource_types()
        {
            $types = array_keys(self::get_rest_resource_type_map());
            if (empty($types)) {
                $types = array('pages', 'posts');
            }

            return self::normalize_allowed_resource_types(
                apply_filters('acf_automation_allowed_resource_types', $types),
                $types
            );
        }

        private static function is_automation_enabled()
        {
            return (bool) get_option(self::OPTION_AUTOMATION_ENABLED, true);
        }

        private static function is_automation_claimed()
        {
            return trim((string) get_option(self::OPTION_AUTOMATION_SECRET_HASH, '')) !== '';
        }

        private static function clear_claim_token()
        {
            delete_option(self::OPTION_AUTOMATION_CLAIM_TOKEN_HASH);
            delete_option(self::OPTION_AUTOMATION_CLAIM_EXPIRES_AT);
        }

        private static function issue_automation_secret()
        {
            self::ensure_automation_defaults();

            $secret = self::generate_secret(24);
            update_option(self::OPTION_AUTOMATION_SECRET_HASH, wp_hash_password($secret), false);
            set_transient(self::TRANSIENT_AUTOMATION_SECRET_PREVIEW, $secret, self::SECRET_PREVIEW_TTL);
            self::clear_claim_token();

            return $secret;
        }

        private static function get_automation_secret_preview()
        {
            $secret = get_transient(self::TRANSIENT_AUTOMATION_SECRET_PREVIEW);
            return is_string($secret) ? trim($secret) : '';
        }

        private static function clear_automation_secret()
        {
            delete_option(self::OPTION_AUTOMATION_SECRET_HASH);
            delete_transient(self::TRANSIENT_AUTOMATION_SECRET_PREVIEW);
        }

        public static function issue_application_password_env_block_for_user($user_id)
        {
            if (!class_exists('WP_Application_Passwords')) {
                return new WP_Error(
                    'acf_automation_app_password_unavailable',
                    'WordPress Application Passwords are not available on this site.',
                    array('status' => 500)
                );
            }

            $user_id = (int) $user_id;
            if ($user_id <= 0) {
                return new WP_Error(
                    'acf_automation_app_password_bad_user',
                    'A valid user is required to generate an Application Password.',
                    array('status' => 400)
                );
            }

            $user = get_userdata($user_id);
            if (!$user instanceof WP_User || $user->user_login === '') {
                return new WP_Error(
                    'acf_automation_app_password_user_missing',
                    'The selected user could not be loaded.',
                    array('status' => 404)
                );
            }

            $app_name = self::build_application_password_name();
            self::delete_application_passwords_by_name($user_id, $app_name);

            $created = WP_Application_Passwords::create_new_application_password(
                $user_id,
                array(
                    'name' => $app_name,
                )
            );

            if (is_wp_error($created)) {
                return $created;
            }

            if (!is_array($created) || !isset($created[0]) || !is_string($created[0]) || trim($created[0]) === '') {
                return new WP_Error(
                    'acf_automation_app_password_create_failed',
                    'WordPress did not return a usable Application Password.',
                    array('status' => 500)
                );
            }

            $env_block = self::build_application_password_env_block($user->user_login, trim($created[0]));
            set_transient(self::TRANSIENT_APP_PASSWORD_ENV_PREVIEW, $env_block, self::SECRET_PREVIEW_TTL);

            return array(
                'env_block' => $env_block,
                'user_login' => $user->user_login,
                'name' => $app_name,
            );
        }

        private static function get_application_password_env_preview()
        {
            $preview = get_transient(self::TRANSIENT_APP_PASSWORD_ENV_PREVIEW);
            return is_string($preview) ? trim($preview) : '';
        }

        private static function build_application_password_name()
        {
            self::ensure_automation_defaults();
            $site_id = (string) get_option(self::OPTION_AUTOMATION_SITE_ID, '');
            if ($site_id !== '') {
                return 'ACF Automation API (' . $site_id . ')';
            }

            return 'ACF Automation API';
        }

        private static function delete_application_passwords_by_name($user_id, $app_name)
        {
            if (!class_exists('WP_Application_Passwords')) {
                return;
            }

            $passwords = WP_Application_Passwords::get_user_application_passwords($user_id);
            if (!is_array($passwords)) {
                return;
            }

            foreach ($passwords as $password) {
                if (!is_array($password)) {
                    continue;
                }

                $candidate_name = isset($password['name']) ? (string) $password['name'] : '';
                $candidate_uuid = isset($password['uuid']) ? (string) $password['uuid'] : '';
                if ($candidate_name !== $app_name || $candidate_uuid === '') {
                    continue;
                }

                WP_Application_Passwords::delete_application_password($user_id, $candidate_uuid);
            }
        }

        private static function maybe_issue_claim_token($force)
        {
            $now = time();
            $expires_at = (int) get_option(self::OPTION_AUTOMATION_CLAIM_EXPIRES_AT, 0);
            if (!$force && $expires_at > $now && trim((string) get_option(self::OPTION_AUTOMATION_CLAIM_TOKEN_HASH, '')) !== '') {
                return '';
            }

            $claim_token = self::generate_secret(20);
            update_option(self::OPTION_AUTOMATION_CLAIM_TOKEN_HASH, wp_hash_password($claim_token), false);
            update_option(self::OPTION_AUTOMATION_CLAIM_EXPIRES_AT, $now + self::CLAIM_TOKEN_TTL, false);

            return $claim_token;
        }

        private static function validate_claim_token($claim_token)
        {
            $claim_hash = trim((string) get_option(self::OPTION_AUTOMATION_CLAIM_TOKEN_HASH, ''));
            $expires_at = (int) get_option(self::OPTION_AUTOMATION_CLAIM_EXPIRES_AT, 0);
            if ($claim_hash === '' || $expires_at <= 0) {
                return new WP_Error(
                    'acf_automation_claim_missing',
                    'No active claim token is available for this site.',
                    array('status' => 409)
                );
            }

            if (time() > $expires_at) {
                self::clear_claim_token();
                return new WP_Error(
                    'acf_automation_claim_expired',
                    'Claim token has expired.',
                    array('status' => 410)
                );
            }

            if (!wp_check_password($claim_token, $claim_hash)) {
                return new WP_Error(
                    'acf_automation_claim_invalid',
                    'Claim token is invalid.',
                    array('status' => 401)
                );
            }

            return true;
        }

        private static function generate_secret($bytes)
        {
            try {
                return bin2hex(random_bytes($bytes));
            } catch (Throwable $e) {
                return bin2hex(wp_generate_password($bytes * 2, true, true));
            }
        }

        private static function build_bootstrap_status_payload($include_claim_token, $claim_token)
        {
            self::ensure_automation_defaults();

            $payload = array(
                'enabled' => self::is_automation_enabled(),
                'claimed' => self::is_automation_claimed(),
                'site_id' => (string) get_option(self::OPTION_AUTOMATION_SITE_ID, ''),
                'allowed_resource_types' => self::resolve_allowed_resource_types(),
                'target_base_url' => home_url('/'),
                'schema_pull_path' => '/wp-json/' . self::ROUTE_NAMESPACE . '/pull',
                'schema_push_path' => '/wp-json/' . self::ROUTE_NAMESPACE . '/push',
                'content_base_path' => '/wp-json/' . self::AUTOMATION_ROUTE_NAMESPACE . '/content',
                'claim_expires_at' => '',
            );

            if ($include_claim_token && !$payload['claimed'] && $claim_token !== '') {
                $payload['claim_token'] = $claim_token;
                $payload['claim_url'] = home_url('/wp-json/' . self::AUTOMATION_ROUTE_NAMESPACE . '/bootstrap/claim?claim_token=' . rawurlencode($claim_token));
                $expires_at = (int) get_option(self::OPTION_AUTOMATION_CLAIM_EXPIRES_AT, 0);
                $payload['claim_expires_at'] = $expires_at > 0 ? gmdate('c', $expires_at) : '';
                $payload['bootstrap_command'] = sprintf('scripts/bootstrap-repo.sh --claim-token %s', $claim_token);
            }

            return $payload;
        }

        private static function build_env_block($automation_secret)
        {
            $status = self::build_bootstrap_status_payload(false, '');
            $base_url = untrailingslashit((string) $status['target_base_url']);

            return implode(
                "\n",
                array(
                    'TARGET_BASE_URL=' . $base_url,
                    'ACF_AUTOMATION_SITE_ID=' . (string) $status['site_id'],
                    'ACF_AUTOMATION_SECRET=' . $automation_secret,
                    'ACF_AUTOMATION_SCHEMA_PULL_PATH=' . (string) $status['schema_pull_path'],
                    'ACF_AUTOMATION_SCHEMA_PUSH_PATH=' . (string) $status['schema_push_path'],
                    'ACF_AUTOMATION_CONTENT_BASE_PATH=' . (string) $status['content_base_path'],
                    'ALLOWED_RESOURCE_TYPES=' . implode(',', $status['allowed_resource_types']),
                )
            );
        }

        private static function build_application_password_env_block($username, $app_password)
        {
            $status = self::build_bootstrap_status_payload(false, '');
            $base_url = untrailingslashit((string) $status['target_base_url']);

            return implode(
                "\n",
                array(
                    'TARGET_BASE_URL=' . $base_url,
                    'ACF_AUTH_MODE=legacy',
                    'WP_API_USER=' . $username,
                    'WP_API_APP_PASSWORD=' . $app_password,
                    'ALLOWED_RESOURCE_TYPES=' . implode(',', $status['allowed_resource_types']),
                )
            );
        }

        private static function resolve_allowed_resource_types()
        {
            $stored_types = get_option(self::OPTION_AUTOMATION_ALLOWED_RESOURCE_TYPES, array());
            if (!is_array($stored_types)) {
                $stored_types = array();
            }

            $discovered_types = array_keys(self::get_rest_resource_type_map());
            $merged_types = array_merge($discovered_types, $stored_types);
            if (empty($merged_types)) {
                $merged_types = array('pages', 'posts');
            }

            return self::normalize_allowed_resource_types(
                apply_filters('acf_automation_allowed_resource_types', $merged_types),
                $merged_types
            );
        }

        private static function resolve_post_type_for_resource($resource_type)
        {
            $resource_type = self::normalize_resource_type_token($resource_type);
            if ($resource_type === '') {
                return '';
            }

            if (!in_array($resource_type, self::resolve_allowed_resource_types(), true)) {
                return '';
            }

            $resource_map = self::get_rest_resource_type_map();
            if (isset($resource_map[$resource_type])) {
                return $resource_map[$resource_type];
            }

            return '';
        }

        private static function load_content_resource($resource_type, $resource_id)
        {
            if ($resource_id <= 0) {
                return new WP_Error(
                    'acf_automation_bad_id',
                    'resource_id must be a positive integer.',
                    array('status' => 400)
                );
            }

            $post_type = self::resolve_post_type_for_resource($resource_type);
            if ($post_type === '') {
                return new WP_Error(
                    'acf_automation_bad_resource_type',
                    sprintf('resource_type %s is unsupported for this site.', esc_html((string) $resource_type)),
                    array(
                        'status' => 400,
                        'allowed_resource_types' => self::resolve_allowed_resource_types(),
                    )
                );
            }

            $post = get_post($resource_id);
            if (!$post instanceof WP_Post) {
                return new WP_Error(
                    'acf_automation_not_found',
                    'Resource not found.',
                    array('status' => 404)
                );
            }

            if ($post->post_type !== $post_type) {
                return new WP_Error(
                    'acf_automation_type_mismatch',
                    'Resource exists but does not match the requested resource type.',
                    array('status' => 400)
                );
            }

            return $post;
        }

        private static function load_acf_values($post_id)
        {
            if (!function_exists('get_fields')) {
                return new WP_Error(
                    'acf_automation_acf_missing',
                    'ACF functions are unavailable.',
                    array('status' => 500)
                );
            }

            $fields = get_fields($post_id, false);
            if (!is_array($fields)) {
                return array();
            }

            return $fields;
        }

        private static function build_content_response($resource_type, $post, $dry_run, $requested_fields)
        {
            $acf = self::load_acf_values($post->ID);
            if (is_wp_error($acf)) {
                return $acf;
            }

            return array(
                'id' => (int) $post->ID,
                'type' => (string) $resource_type,
                'post_type' => (string) $post->post_type,
                'status' => (string) $post->post_status,
                'slug' => (string) $post->post_name,
                'title' => (string) $post->post_title,
                'dry_run' => (bool) $dry_run,
                'requested_fields' => array_values($requested_fields),
                'acf' => $acf,
            );
        }

        private static function apply_content_update($post_id, $acf_payload)
        {
            if (!function_exists('update_field')) {
                return new WP_Error(
                    'acf_automation_acf_missing',
                    'ACF update_field() is unavailable.',
                    array('status' => 500)
                );
            }

            foreach ($acf_payload as $field_name => $value) {
                $field_name = sanitize_key((string) $field_name);
                if ($field_name === '') {
                    return new WP_Error(
                        'acf_automation_bad_field_name',
                        'ACF payload contains an invalid field name.',
                        array('status' => 400)
                    );
                }

                try {
                    update_field($field_name, $value, $post_id);
                } catch (Throwable $e) {
                    return new WP_Error(
                        'acf_automation_update_failed',
                        sprintf('Failed updating field %s: %s', $field_name, $e->getMessage()),
                        array('status' => 500)
                    );
                }
            }

            return true;
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
            $signature_state = self::verify_signed_push_request($request);
            if (is_wp_error($signature_state)) {
                return $signature_state;
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
            $delete_missing_groups = (bool) $request->get_param('delete_missing_groups');
            $suppress_legacy_build_hooks = (bool) $request->get_param('suppress_legacy_build_hooks');

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
                'delete_missing_groups' => $delete_missing_groups,
                'suppress_legacy_build_hooks' => $suppress_legacy_build_hooks,
                'plan' => $plan,
                'source_counts' => $state['source_counts'],
                'signature_required' => !empty($signature_state['required']),
                'signature_verified' => !empty($signature_state['verified']),
            );

            if (!empty($state['warnings'])) {
                $result['warnings'] = $state['warnings'];
            }

            if ($dry_run) {
                return rest_ensure_response($result);
            }

            $json_dir_ready = self::ensure_json_dir_ready($json_dir, false);
            if (is_wp_error($json_dir_ready)) {
                return $json_dir_ready;
            }

            $groups_to_write = array();
            foreach (array_merge($plan['create'], $plan['update']) as $group_key) {
                $groups_to_write[$group_key] = $incoming_map[$group_key];
            }

            $write_report = self::write_group_json_files($json_dir, $groups_to_write);
            $write_errors = $write_report['errors'];

            $delete_report = array(
                'requested' => $delete_missing_groups,
                'attempted' => 0,
                'deleted' => 0,
                'missing_file' => 0,
                'keys' => array(),
                'missing_keys' => array(),
            );
            if ($delete_missing_groups) {
                foreach ($plan['removed'] as $group_key) {
                    $delete_report['attempted']++;
                    $target_file = trailingslashit($json_dir) . sanitize_file_name($group_key . '.json');
                    if (!file_exists($target_file)) {
                        $delete_report['missing_file']++;
                        $delete_report['missing_keys'][] = $group_key;
                        continue;
                    }

                    if (!@unlink($target_file)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                        $write_errors[] = sprintf('Failed deleting target file for %s.', $group_key);
                        continue;
                    }

                    $delete_report['deleted']++;
                    $delete_report['keys'][] = $group_key;
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

            $import_to_db = self::should_import_groups_to_db();
            $legacy_build_hook_guard = self::begin_legacy_build_hook_guard(
                $suppress_legacy_build_hooks,
                ($import_to_db || $delete_missing_groups)
            );

            try {
                if ($import_to_db) {
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

                if ($delete_missing_groups) {
                    $db_delete_report = self::maybe_delete_groups_from_db($plan['removed']);
                } else {
                    $db_delete_report = array(
                        'requested' => false,
                        'attempted' => 0,
                        'deleted' => 0,
                        'missing' => 0,
                        'errors' => array(),
                        'keys' => array(),
                        'missing_keys' => array(),
                        'mode' => 'skipped',
                        'reason' => 'DB deletion runs only when delete_missing_groups=true.',
                    );
                }
            } finally {
                self::restore_legacy_build_hook_guard($legacy_build_hook_guard);
            }

            if (!empty($db_delete_report['errors'])) {
                return new WP_Error(
                    'acf_schema_api_db_delete_failed',
                    'One or more removed field groups failed to delete from DB.',
                    array(
                        'status' => 500,
                        'errors' => $db_delete_report['errors'],
                        'report' => $db_delete_report,
                    )
                );
            }

            $refreshed = self::load_effective_groups($json_dir);
            if (is_wp_error($refreshed)) {
                return $refreshed;
            }

            $result['applied'] = true;
            $result['schema_hash_after'] = self::compute_schema_hash($refreshed['groups']);
            $result['import_report'] = $import_report;
            $result['delete_report'] = $delete_report;
            $result['db_delete_report'] = $db_delete_report;
            $result['legacy_build_hook_guard'] = self::summarize_legacy_build_hook_guard($legacy_build_hook_guard);
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

        private static function ensure_json_dir_ready($json_dir, $create_if_missing)
        {
            if (!is_dir($json_dir)) {
                if (!$create_if_missing) {
                    return new WP_Error(
                        'acf_schema_api_missing_dir',
                        'ACF JSON directory does not exist.',
                        array('status' => 500)
                    );
                }

                if (!wp_mkdir_p($json_dir)) {
                    return new WP_Error(
                        'acf_schema_api_mkdir_failed',
                        'ACF JSON directory could not be created.',
                        array(
                            'status' => 500,
                            'json_dir' => $json_dir,
                        )
                    );
                }
            }

            if (!is_writable($json_dir)) {
                return new WP_Error(
                    'acf_schema_api_not_writable',
                    'ACF JSON directory is not writable.',
                    array(
                        'status' => 500,
                        'json_dir' => $json_dir,
                    )
                );
            }

            return true;
        }

        private static function write_group_json_files($json_dir, $group_map)
        {
            $report = array(
                'attempted' => 0,
                'written' => 0,
                'keys' => array(),
                'errors' => array(),
            );

            if (!is_array($group_map) || empty($group_map)) {
                return $report;
            }

            ksort($group_map);
            foreach ($group_map as $group_key => $group) {
                $report['attempted']++;

                if (!self::is_valid_group_key($group_key)) {
                    $report['errors'][] = sprintf('Invalid group key for JSON export: %s.', (string) $group_key);
                    continue;
                }

                $filename = sanitize_file_name($group_key . '.json');
                $target_file = trailingslashit($json_dir) . $filename;
                $encoded = wp_json_encode($group, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

                if (!is_string($encoded)) {
                    $report['errors'][] = sprintf('Failed to encode JSON for %s.', $group_key);
                    continue;
                }

                $tmp_file = sprintf(
                    '%s.tmp-%s',
                    $target_file,
                    function_exists('wp_generate_uuid4') ? wp_generate_uuid4() : uniqid('', true)
                );

                $written = @file_put_contents($tmp_file, $encoded . PHP_EOL, LOCK_EX); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                if ($written === false) {
                    $report['errors'][] = sprintf('Failed writing temporary file for %s.', $group_key);
                    continue;
                }

                if (!@rename($tmp_file, $target_file)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                    @unlink($tmp_file); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                    $report['errors'][] = sprintf('Failed replacing target file for %s.', $group_key);
                    continue;
                }

                $report['written']++;
                $report['keys'][] = $group_key;
            }

            return $report;
        }

        private static function build_strict_json_status($json_dir = '')
        {
            if (is_wp_error($json_dir)) {
                return $json_dir;
            }

            if ($json_dir === '') {
                $json_dir = self::get_json_dir();
                if (is_wp_error($json_dir)) {
                    return $json_dir;
                }
            }

            $json_state = self::load_groups_from_load_json_paths($json_dir);
            if (is_wp_error($json_state)) {
                return $json_state;
            }

            $db_state = self::load_db_only_groups(array_keys($json_state['groups']));
            if (is_wp_error($db_state)) {
                return $db_state;
            }

            $db_only_keys = array_keys($db_state['groups']);
            sort($db_only_keys);

            return array(
                'strict_json_only' => self::is_strict_json_only(),
                'auto_export_enabled' => self::should_auto_export_db_only_groups(),
                'json_dir' => $json_dir,
                'db_only_group_keys' => $db_only_keys,
                'source_counts' => array(
                    'json' => count($json_state['groups']),
                    'db_only' => count($db_state['groups']),
                    'total' => count($json_state['groups']) + count($db_state['groups']),
                ),
                'warnings' => array_merge($json_state['warnings'], $db_state['warnings']),
            );
        }

        private static function export_db_only_groups_to_json($json_dir = '', $json_state = null, $db_state = null)
        {
            if (is_wp_error($json_dir)) {
                return $json_dir;
            }

            if ($json_dir === '') {
                $json_dir = self::get_json_dir();
                if (is_wp_error($json_dir)) {
                    return $json_dir;
                }
            }

            if (!is_array($json_state)) {
                $json_state = self::load_groups_from_load_json_paths($json_dir);
                if (is_wp_error($json_state)) {
                    return $json_state;
                }
            }

            if (!is_array($db_state)) {
                $db_state = self::load_db_only_groups(array_keys($json_state['groups']));
                if (is_wp_error($db_state)) {
                    return $db_state;
                }
            }

            $report = array(
                'json_dir' => $json_dir,
                'attempted' => count($db_state['groups']),
                'exported' => 0,
                'keys' => array(),
                'warnings' => array_merge($json_state['warnings'], $db_state['warnings']),
                'errors' => array(),
            );

            if (empty($db_state['groups'])) {
                return $report;
            }

            $json_dir_ready = self::ensure_json_dir_ready($json_dir, true);
            if (is_wp_error($json_dir_ready)) {
                return $json_dir_ready;
            }

            $write_report = self::write_group_json_files($json_dir, $db_state['groups']);
            $report['exported'] = $write_report['written'];
            $report['keys'] = $write_report['keys'];
            $report['errors'] = $write_report['errors'];

            if (!empty($report['errors'])) {
                return new WP_Error(
                    'acf_schema_api_db_export_failed',
                    'One or more DB-only field groups failed to export to JSON.',
                    array(
                        'status' => 500,
                        'report' => $report,
                        'errors' => $report['errors'],
                    )
                );
            }

            $refreshed_status = self::build_strict_json_status($json_dir);
            if (!is_wp_error($refreshed_status)) {
                $report['source_counts_after'] = $refreshed_status['source_counts'];
                $report['db_only_group_keys_after'] = $refreshed_status['db_only_group_keys'];
                $report['warnings_after'] = $refreshed_status['warnings'];
            }

            return $report;
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

            $auto_export_attempted = false;
            if (self::is_strict_json_only() && !empty($db_state['groups']) && self::should_auto_export_db_only_groups()) {
                $auto_export_attempted = true;
                $export_report = self::export_db_only_groups_to_json($json_dir, $json_state, $db_state);
                if (is_wp_error($export_report)) {
                    return $export_report;
                }

                $json_state = self::load_groups_from_load_json_paths($json_dir);
                if (is_wp_error($json_state)) {
                    return $json_state;
                }

                $db_state = self::load_db_only_groups(array_keys($json_state['groups']));
                if (is_wp_error($db_state)) {
                    return $db_state;
                }
            }

            if (self::is_strict_json_only() && !empty($db_state['groups'])) {
                $db_only_keys = array_keys($db_state['groups']);
                sort($db_only_keys);
                return new WP_Error(
                    'acf_schema_api_strict_json_violation',
                    'Strict JSON mode is enabled and DB-only field groups were detected. Export these groups to JSON before pull/push.',
                    array(
                        'status' => 409,
                        'json_dir' => $json_dir,
                        'auto_export_enabled' => self::should_auto_export_db_only_groups(),
                        'auto_export_attempted' => $auto_export_attempted,
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

        private static function should_auto_export_db_only_groups()
        {
            return (bool) apply_filters('acf_schema_api_auto_export_db_only_groups', self::is_auto_export_db_only_enabled());
        }

        private static function is_auto_export_db_only_enabled()
        {
            return (bool) get_option(self::OPTION_AUTOMATION_AUTO_EXPORT_DB_ONLY, false);
        }

        private static function should_require_signed_push()
        {
            return (bool) apply_filters('acf_schema_api_require_signed_push', false);
        }

        private static function should_import_groups_to_db()
        {
            return (bool) apply_filters('acf_schema_api_import_to_db', false);
        }

        private static function should_suppress_legacy_build_hooks()
        {
            return (bool) apply_filters('acf_schema_api_suppress_legacy_build_hooks', true);
        }

        private static function begin_legacy_build_hook_guard($requested, $has_db_operations)
        {
            $guard = array(
                'requested' => (bool) $requested,
                'has_db_operations' => (bool) $has_db_operations,
                'enabled' => false,
                'reason' => '',
                'removed_count' => 0,
                'restored_count' => 0,
                'removed_callbacks' => array(),
                'restore_errors' => array(),
            );

            if (!$guard['requested']) {
                $guard['reason'] = 'disabled_by_request';
                return $guard;
            }

            if (!$guard['has_db_operations']) {
                $guard['reason'] = 'no_db_operations';
                return $guard;
            }

            if (!self::should_suppress_legacy_build_hooks()) {
                $guard['reason'] = 'disabled_by_filter';
                return $guard;
            }

            $guard['enabled'] = true;
            $hooks = array('save_post', 'save_post_acf-field-group', 'save_post_acf-field');
            foreach ($hooks as $hook) {
                if (!isset($GLOBALS['wp_filter'][$hook]) || !($GLOBALS['wp_filter'][$hook] instanceof WP_Hook)) {
                    continue;
                }

                $hook_object = $GLOBALS['wp_filter'][$hook];
                if (!isset($hook_object->callbacks) || !is_array($hook_object->callbacks) || empty($hook_object->callbacks)) {
                    continue;
                }

                $callbacks_snapshot = $hook_object->callbacks;
                foreach ($callbacks_snapshot as $priority => $callbacks) {
                    foreach ($callbacks as $callback_data) {
                        if (!isset($callback_data['function'])) {
                            continue;
                        }

                        $callback = $callback_data['function'];
                        $match = self::is_legacy_build_save_post_callback($callback, $hook);
                        if (!$match['match']) {
                            continue;
                        }

                        $accepted_args = isset($callback_data['accepted_args']) ? (int) $callback_data['accepted_args'] : 1;
                        if (!remove_action($hook, $callback, (int) $priority)) {
                            continue;
                        }

                        $guard['removed_count']++;
                        $guard['removed_callbacks'][] = array(
                            'hook' => $hook,
                            'priority' => (int) $priority,
                            'accepted_args' => $accepted_args,
                            'callback' => $callback,
                            'callback_label' => $match['meta']['callback'],
                            'source_file' => $match['meta']['source_file'],
                            'reason' => $match['meta']['reason'],
                        );
                    }
                }
            }

            return $guard;
        }

        private static function restore_legacy_build_hook_guard(&$guard)
        {
            if (empty($guard['removed_callbacks']) || !is_array($guard['removed_callbacks'])) {
                return;
            }

            foreach ($guard['removed_callbacks'] as $callback_data) {
                try {
                    add_action(
                        $callback_data['hook'],
                        $callback_data['callback'],
                        (int) $callback_data['priority'],
                        (int) $callback_data['accepted_args']
                    );
                    $guard['restored_count']++;
                } catch (Throwable $e) {
                    $guard['restore_errors'][] = sprintf(
                        'Failed restoring %s on %s: %s',
                        $callback_data['callback_label'],
                        $callback_data['hook'],
                        $e->getMessage()
                    );
                }
            }
        }

        private static function summarize_legacy_build_hook_guard($guard)
        {
            $summary = array(
                'requested' => !empty($guard['requested']),
                'has_db_operations' => !empty($guard['has_db_operations']),
                'enabled' => !empty($guard['enabled']),
                'removed_count' => isset($guard['removed_count']) ? (int) $guard['removed_count'] : 0,
                'restored_count' => isset($guard['restored_count']) ? (int) $guard['restored_count'] : 0,
            );

            if (!empty($guard['reason'])) {
                $summary['reason'] = (string) $guard['reason'];
            }

            if (!empty($guard['removed_callbacks']) && is_array($guard['removed_callbacks'])) {
                $summary['removed_callbacks'] = array();
                foreach ($guard['removed_callbacks'] as $callback_data) {
                    $summary['removed_callbacks'][] = array(
                        'hook' => $callback_data['hook'],
                        'priority' => (int) $callback_data['priority'],
                        'callback' => $callback_data['callback_label'],
                        'source_file' => $callback_data['source_file'],
                        'reason' => $callback_data['reason'],
                    );
                }
            }

            if (!empty($guard['restore_errors']) && is_array($guard['restore_errors'])) {
                $summary['restore_errors'] = array_values($guard['restore_errors']);
            }

            return $summary;
        }

        private static function is_legacy_build_save_post_callback($callback, $hook)
        {
            $meta = array(
                'hook' => (string) $hook,
                'callback' => self::describe_callable($callback),
                'source_file' => '',
                'reason' => '',
            );

            $source = self::get_callback_source_meta($callback);
            $source_file = '';
            if (!empty($source['file'])) {
                $source_file = wp_normalize_path((string) $source['file']);
                $meta['source_file'] = $source_file;
            }

            $is_match = false;
            if ($meta['callback'] === 'my_project_updated_trigger_generate') {
                $is_match = true;
                $meta['reason'] = 'legacy_callback_name';
            } elseif ($source_file !== '' && preg_match('#/functions/run-build\.php$#i', $source_file)) {
                $is_match = true;
                $meta['reason'] = 'run_build_source_file';
            } elseif ($source_file !== '' && preg_match('#/themes/[^/]+/functions\.php$#i', $source_file)) {
                $snippet = strtolower((string) $source['snippet']);
                if (strpos($snippet, 'codepipelineclient') !== false || strpos($snippet, 'startpipelineexecution') !== false) {
                    $is_match = true;
                    $meta['reason'] = 'functions_php_codepipeline';
                }
            }

            $is_match = (bool) apply_filters('acf_schema_api_match_legacy_build_callback', $is_match, $callback, $meta);
            return array(
                'match' => $is_match,
                'meta' => $meta,
            );
        }

        private static function describe_callable($callback)
        {
            if (is_string($callback)) {
                return $callback;
            }

            if ($callback instanceof Closure) {
                return 'closure';
            }

            if (is_array($callback) && count($callback) === 2) {
                $target = $callback[0];
                $method = (string) $callback[1];
                if (is_object($target)) {
                    return get_class($target) . '::' . $method;
                }

                if (is_string($target)) {
                    return $target . '::' . $method;
                }
            }

            if (is_object($callback) && method_exists($callback, '__invoke')) {
                return get_class($callback) . '::__invoke';
            }

            return 'callable';
        }

        private static function get_callback_source_meta($callback)
        {
            $meta = array(
                'file' => '',
                'start_line' => 0,
                'end_line' => 0,
                'snippet' => '',
            );

            try {
                $reflection = null;
                if ($callback instanceof Closure) {
                    $reflection = new ReflectionFunction($callback);
                } elseif (is_string($callback)) {
                    if (!function_exists($callback)) {
                        return $meta;
                    }
                    $reflection = new ReflectionFunction($callback);
                } elseif (is_array($callback) && count($callback) === 2) {
                    $target = $callback[0];
                    $method = (string) $callback[1];
                    if (!method_exists($target, $method)) {
                        return $meta;
                    }
                    $reflection = new ReflectionMethod($target, $method);
                } elseif (is_object($callback) && method_exists($callback, '__invoke')) {
                    $reflection = new ReflectionMethod($callback, '__invoke');
                }

                if (!$reflection) {
                    return $meta;
                }

                $file = $reflection->getFileName();
                if (!is_string($file) || $file === '') {
                    return $meta;
                }

                $start_line = (int) $reflection->getStartLine();
                $end_line = (int) $reflection->getEndLine();
                if ($start_line <= 0 || $end_line < $start_line) {
                    $start_line = 0;
                    $end_line = 0;
                }

                $meta['file'] = $file;
                $meta['start_line'] = $start_line;
                $meta['end_line'] = $end_line;
                $meta['snippet'] = self::read_file_lines($file, $start_line, $end_line);
            } catch (Throwable $e) {
                return $meta;
            }

            return $meta;
        }

        private static function read_file_lines($file, $start_line, $end_line)
        {
            if (!is_string($file) || $file === '' || !is_readable($file)) {
                return '';
            }

            $start_line = (int) $start_line;
            $end_line = (int) $end_line;
            if ($start_line <= 0 || $end_line < $start_line) {
                return '';
            }

            $max_lines = 200;
            if (($end_line - $start_line + 1) > $max_lines) {
                $end_line = $start_line + $max_lines - 1;
            }

            $lines = file($file, FILE_IGNORE_NEW_LINES);
            if (!is_array($lines) || empty($lines)) {
                return '';
            }

            $slice = array_slice($lines, $start_line - 1, $end_line - $start_line + 1);
            if (empty($slice)) {
                return '';
            }

            return implode("\n", $slice);
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

        private static function get_rest_resource_type_map()
        {
            $map = array();
            $post_types = get_post_types(array('show_in_rest' => true), 'objects');

            foreach ($post_types as $post_type => $object) {
                $post_type_token = self::normalize_resource_type_token($post_type);
                if ($post_type_token !== '') {
                    $map[$post_type_token] = (string) $post_type;
                }

                $rest_base = '';
                if (is_object($object) && !empty($object->rest_base)) {
                    $rest_base = self::normalize_resource_type_token((string) $object->rest_base);
                }

                if ($rest_base !== '') {
                    $map[$rest_base] = (string) $post_type;
                }
            }

            ksort($map);
            return $map;
        }

        private static function normalize_allowed_resource_types($types, $fallback)
        {
            if (!is_array($types) || empty($types)) {
                $types = $fallback;
            }

            $normalized = array();
            foreach ($types as $type) {
                $type = self::normalize_resource_type_token($type);
                if ($type !== '') {
                    $normalized[] = $type;
                }
            }

            if (empty($normalized)) {
                return array_values(array_unique($fallback));
            }

            return array_values(array_unique($normalized));
        }

        private static function normalize_resource_type_token($type)
        {
            if (!is_string($type) && !is_numeric($type)) {
                return '';
            }

            $type = trim((string) $type);
            if ($type === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $type)) {
                return '';
            }

            return sanitize_key($type);
        }

        private static function verify_signed_push_request(WP_REST_Request $request)
        {
            if (!self::should_require_signed_push()) {
                return array(
                    'required' => false,
                    'verified' => false,
                );
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

            return array(
                'required' => true,
                'verified' => true,
            );
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
            $removed = array();

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

            foreach ($current_map as $group_key => $_current_group) {
                if (!isset($incoming_map[$group_key])) {
                    $removed[] = $group_key;
                }
            }

            return array(
                'create' => $create,
                'update' => $update,
                'unchanged' => $unchanged,
                'removed' => $removed,
                'create_count' => count($create),
                'update_count' => count($update),
                'unchanged_count' => count($unchanged),
                'removed_count' => count($removed),
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

        private static function maybe_delete_groups_from_db($removed_group_keys)
        {
            $report = array(
                'requested' => true,
                'attempted' => 0,
                'deleted' => 0,
                'missing' => 0,
                'errors' => array(),
                'keys' => array(),
                'missing_keys' => array(),
            );

            if (!is_array($removed_group_keys) || empty($removed_group_keys)) {
                return $report;
            }

            if (!function_exists('acf_delete_field_group')) {
                $report['errors'][] = 'acf_delete_field_group() is unavailable; cannot delete removed groups from DB.';
                return $report;
            }

            foreach ($removed_group_keys as $group_key) {
                if (!self::is_valid_group_key((string) $group_key)) {
                    $report['errors'][] = sprintf('Invalid removed group key: %s', (string) $group_key);
                    continue;
                }

                $report['attempted']++;
                $group_id = self::resolve_db_group_id_by_key((string) $group_key);
                if ($group_id <= 0) {
                    $report['missing']++;
                    $report['missing_keys'][] = (string) $group_key;
                    continue;
                }

                try {
                    $deleted = acf_delete_field_group($group_id);
                    if (!$deleted) {
                        $report['errors'][] = sprintf('Delete failed for %s (ID %d).', (string) $group_key, $group_id);
                        continue;
                    }
                    $report['deleted']++;
                    $report['keys'][] = (string) $group_key;
                } catch (Throwable $e) {
                    $report['errors'][] = sprintf('Delete failed for %s: %s', (string) $group_key, $e->getMessage());
                }
            }

            return $report;
        }

        private static function resolve_db_group_id_by_key($group_key)
        {
            if (function_exists('acf_get_field_group')) {
                $group = acf_get_field_group($group_key);
                if (is_array($group) && isset($group['ID'])) {
                    return (int) $group['ID'];
                }
            }

            if (!function_exists('acf_get_field_groups')) {
                return 0;
            }

            $groups = acf_get_field_groups();
            if (!is_array($groups)) {
                return 0;
            }

            foreach ($groups as $group) {
                if (!is_array($group)) {
                    continue;
                }
                $candidate_key = isset($group['key']) ? (string) $group['key'] : '';
                if ($candidate_key !== $group_key) {
                    continue;
                }
                return isset($group['ID']) ? (int) $group['ID'] : 0;
            }

            return 0;
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

register_activation_hook(__FILE__, array('RG_ACF_Schema_API', 'activate'));
RG_ACF_Schema_API::init();
