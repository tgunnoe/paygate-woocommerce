<?php

/*
  Plugin Name: Paygate for WooCommerce
  Plugin URI:  https://github.com/moov-io/paygate
  Description: Check out on Woocommerce with ACH payments
  Author:      tgunnoe
  Text Domain: Paygate
  Author URI:  https://github.com/tgunnoe
 */


// Exit if accessed directly
if (false === defined('ABSPATH')) {
  exit;
}

define("PAYGATE_VERSION", "1.0.0");

// Ensures WooCommerce is loaded before initializing the BitPay plugin
// REQUIRED
add_action('plugins_loaded', 'woocommerce_paygate_init', 0);

// Set up hook to display admin notices on install (for migration)
add_action( 'admin_notices', 'paygate_admin_notice_show_error_message' );
add_action( 'admin_notices', 'paygate_admin_notice_show_success_message' );

// Register the activation hook
//register_activation_hook(__FILE__, 'woocommerce_paygate_activate');

function woocommerce_paygate_init()
{
  //Don't init if we somehow already have the paygate gateway
  if (true === class_exists('WC_Gateway_Paygate'))
  {
    return;
  }

  //Don't init if we don't have wc_payment_gateway (required WP class)
  if (false === class_exists('WC_Payment_Gateway'))
  {
    return;
  }

  class WC_Gateway_Paygate extends WC_Payment_Gateway
  {
    private $is_initialized = false;

    /**
     * Constructor for the gateway.
     * REQUIRED CLASS
     */
    public function __construct()
    {
      // General
      $this->id                 = 'paygate';
      //$this->icon               = plugin_dir_url(__FILE__).'assets/img/paygate_icon.png';
      //Set to false, does not create custom credit card form
      $this->has_fields         = false;
      //Creates the order button
      $this->order_button_text  = __('Proceed to Checkout', 'paygate');
      $this->method_title       = 'Paygate';
      $this->method_description = 'Paygate is the standard for firearms-related ecommerce';

      //Defines fields on the admin page
      $this->init_form_fields();

      // Load the settings - this populates the various get_option items (really?)
      $this->init_settings();

      // Define user set variables
      $this->title              = $this->get_option('title');
      $this->description        = $this->get_option('description');
      //$this->order_states       = $this->get_option('order_states');
      $this->debug              = 'yes' === $this->get_option('debug', 'no');

      // Define Paygate settings
      $this->paygate_endpoint          = $this->get_option('paygate_endpoint');
      $this->paygate_gateway_mode      = $this->get_option('paygate_gateway_mode');
      $this->paygate_client_id         = $this->get_option('paygate_client_id');
      $this->paygate_client_secret     = $this->get_option('paygate_client_secret');

      // Define debugging & informational settings
      $this->debug_php_version    = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
      $this->debug_plugin_version = constant("PAYGATE_VERSION");

      $this->log('Paygate Woocommerce payment plugin object constructor called. Plugin is v' . $this->debug_plugin_version . ' and server is PHP v' . $this->debug_php_version);
      $this->log('    [Info] $this->paygate_client_id    = ' . $this->paygate_client_id);

      // Actions
      //Standard save function for the admin settings form fields
      add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'process_admin_options'));
      //Used to save the "order states" custom field
      //add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'save_order_states'));

      // Valid for use and IPN Callback
      if (false === $this->is_valid_for_use())
      {
        $this->enabled = 'no';
        $this->log('    [Info] The plugin is NOT valid for use!');
      }
      else
      {
        $this->enabled = 'yes';
        $this->log('    [Info] The plugin is ok to use.');

        add_action('woocommerce_api_wc_gateway_paygate', array($this, 'paygate_webhook'));
        add_action('woocommerce_order_item_add_action_buttons', array($this, 'add_capture_button'));
        add_action('save_post', array($this, 'capture_order_handler'));
        add_action( 'wp_footer', array($this, 'paygate_modal_footer'));
      }

      $this->is_initialized = true;
    }

    public function get_icon() {
      return
        '<img src="/wp-content/plugins/paygate-for-woocommerce/assets/img/card-visa.png" alt="Credit Card" />' .
        '<img src="/wp-content/plugins/paygate-for-woocommerce/assets/img/card-mastercard.png" alt="Credit Card" />';
    }

    //Used in IPN callback. Confirm that the payment we're IPN'd about is actually a paygate payment method
    public function is_paygate_payment_method($order)
    {
      $actualMethod = '';

      if(method_exists($order, 'get_payment_method'))
      {
          $actualMethod = $order->get_payment_method();
      }
      else
      {
          $actualMethod = get_post_meta( $order->get_id(), '_payment_method', true );
      }

      return $actualMethod === 'paygate';
    }

    public function __destruct()
    {
    }

    public function is_valid_for_use()
    {
      // Check that API credentials are set
      if (
        true === is_null($this->paygate_endpoint) ||
        true === is_null($this->paygate_gateway_mode) ||
        true === is_null($this->paygate_client_id) ||
        true === is_null($this->paygate_client_secret)
      )
      {
          return false;
      }

      $this->log('    [Info] Plugin is valid for use.');

      return true;
    }

    /**
     * Initialise Gateway Settings Form Fields
     * REQUIRED CLASS
     */
    public function init_form_fields()
    {
      $this->log('    [Info] Entered init_form_fields()...');
      $log_file = 'paygate-' . sanitize_file_name( wp_hash( 'paygate' ) ) . '-log';
      $logs_href = get_bloginfo('wpurl') . '/wp-admin/admin.php?page=wc-status&tab=logs&log_file=' . $log_file;

      $this->form_fields = array(
        'title' => array(
          'title'       => __('Title', 'paygate'),
          'type'        => 'text',
          'description' => __('Controls the name of this payment method as displayed to the customer during checkout.', 'paygate'),
          'default'     => __('Paygate', 'paygate'),
          'desc_tip'    => true,
        ),
        'description' => array(
          'title'       => __('Customer Message', 'paygate'),
          'type'        => 'textarea',
          'description' => __('Message to explain how the customer will be paying for the purchase.', 'paygate'),
          'default'     => 'You will be redirected to Paygate to complete your purchase.',
          'desc_tip'    => true,
        ),
        'paygate_endpoint' => array(
          'title'       => __('Paygate URL', 'paygate'),
          'type'        => 'text',
          'description' => __('Your Paygate gateway URL'),
          'default'     => __('https://paygate.deathathletic.com', 'paygate'),
          'desc_tip'    => true,
        ),
        'paygate_client_id' => array(
          'title'       => __('Paygate Client ID', 'paygate'),
          'type'        => 'text',
          'description' => __('Your Paygate client ID'),
          'default'     => __('12345', 'paygate'),
          'desc_tip'    => true,
        ),
        'paygate_client_secret' => array(
          'title'       => __('Paygate Client Secret', 'paygate'),
          'type'        => 'text',
          'description' => __('Your Paygate client Secret'),
          'default'     => __('abcd1234', 'paygate'),
          'desc_tip'    => true,
        ),
        'paygate_gateway_mode' => array(
          'title'       => __('Paygate Gateway Mode', 'paygate'),
          'type'        => 'select',
          'description' => __('Select "SALE" to capture immediately, select "AUTHORIZE" to manually capture later.'),
          'options'     => array(
              'SALE'    => 'Sale',
              'AUTHORIZE' => 'Authorize',
          ),
          'default'     => __('AUTHORIZE', 'paygate'),
          'desc_tip'    => true,
        ),
        'debug' => array(
          'title'       => __('Debug Log', 'paygate'),
          'type'        => 'checkbox',
          'label'       => sprintf(__('Enable logging <a href="%s" class="button">View Logs</a>', 'paygate'), $logs_href),
          'default'     => 'no',
          'description' => sprintf(__('Log Paygate events, such as webhook requests, inside <code>%s</code>', 'paygate'), wc_get_log_file_path('paygate')),
          'desc_tip'    => true,
        ),
        /*'notification_url' => array(
          'title'       => __('Notification URL', 'btcpay'),
          'type'        => 'url',
          'description' => __('BTCPay will send IPNs for orders to this URL with the BTCPay invoice data', 'btcpay'),
          'default'     => '',
          'placeholder' => WC()->api_request_url('WC_Gateway_BtcPay'),
          'desc_tip'    => true,
        ),
        'redirect_url' => array(
          'title'       => __('Redirect URL', 'btcpay'),
          'type'        => 'url',
          'description' => __('After paying the BTCPay invoice, users will be redirected back to this URL', 'btcpay'),
          'default'     => '',
          'placeholder' => $this->get_return_url(),
          'desc_tip'    => true,
        ),*/
      );

      $this->log('    [Info] Initialized form fields: ' . var_export($this->form_fields, true));
      $this->log('    [Info] Leaving init_form_fields()...');
    }

    /**
     * HTML output for form field type `order_states`
     */
    /*public function generate_order_states_html()
    {
      $this->log('    [Info] Entered generate_order_states_html()...');

      ob_start();

      $bp_statuses = array(
        'new'=>'New Order',
        'paid'=>'Paid',
        'confirmed'=>'Confirmed',
        'complete'=>'Complete',
        'invalid'=>'Invalid',
        'expired'=>'Expired',
        'event_invoice_paidAfterExpiration'=>'Paid after expiration',
        'event_invoice_expiredPaidPartial' => 'Expired with partial payment'
      );

      $df_statuses = array(
        'new'=>'wc-pending',
        'paid'=>'wc-on-hold',
        'confirmed'=>'wc-processing',
        'complete'=>'wc-processing',
        'invalid'=>'wc-failed',
        'expired'=>'wc-cancelled',
        'event_invoice_paidAfterExpiration' => 'wc-failed',
        'event_invoice_expiredPaidPartial' => 'wc-failed'
      );

      $wc_statuses = wc_get_order_statuses();
      $wc_statuses = array('BTCPAY_IGNORE' => '') + $wc_statuses;

      ?>

      <tr valign="top">
          <th scope="row" class="titledesc">Order States:</th>
          <td class="forminp" id="btcpay_order_states">
              <table cellspacing="0">
                  <?php

                      foreach ($bp_statuses as $bp_state => $bp_name) {
                      ?>
                      <tr>
                      <th><?php echo $bp_name; ?></th>
                      <td>
                          <select name="woocommerce_btcpay_order_states[<?php echo $bp_state; ?>]">
                          <?php

                          $order_states = get_option('woocommerce_btcpay_settings');
                          $order_states = $order_states['order_states'];
                          foreach ($wc_statuses as $wc_state => $wc_name) {
                              $current_option = $order_states[$bp_state];

                              if (true === empty($current_option)) {
                                  $current_option = $df_statuses[$bp_state];
                              }

                              if ($current_option === $wc_state) {
                                  echo "<option value=\"$wc_state\" selected>$wc_name</option>\n";
                              } else {
                                  echo "<option value=\"$wc_state\">$wc_name</option>\n";
                              }
                          }

                          ?>
                          </select>
                      </td>
                      </tr>
                      <?php
                  }

                  ?>
              </table>
          </td>
      </tr>

      <?php

      $this->log('    [Info] Leaving generate_order_states_html()...');
      return ob_get_clean();
    }*/

    /**
     * Output for the order received page.
     * Simply clears out the cart
     */
    public function thankyou_page($order_id)
    {
      $this->log('    [Info] Entered thankyou_page with order_id =  ' . $order_id);

      // Remove cart
      WC()->cart->empty_cart();

      // Intentionally blank.
      $this->log('    [Info] Leaving thankyou_page with order_id =  ' . $order_id);
    }

    /**
     * Process the payment and return the result
     * REQUIRED CLASS
     *
     * This must return an array with a "result" and a "redirect" param
     *
     * @param   int     $order_id
     * @return  array
     */
    public function process_payment($order_id)
    {
      $this->log('    [Info] Entered process_payment() with order_id = ' . $order_id . '...');

      if (true === empty($order_id))
      {
        $this->log('    [Error] The Paygate payment plugin was called to process a payment but the order_id was missing.');
        throw new \Exception('The Paygate payment plugin was called to process a payment but the order_id was missing. Cannot continue!');
      }

      //Get order details
      $order = wc_get_order( $order_id );

      if (false === $order)
      {
        $this->log('    [Error] The Paygate payment plugin was called to process a payment but could not retrieve the order details for order_id ' . $order_id);
        throw new \Exception('The Paygate payment plugin was called to process a payment but could not retrieve the order details for order_id ' . $order_id . '. Cannot continue!');
      }

      $url = $this->paygate_endpoint;
      if(substr($url, -1) != '/') {
        $url .= '/';
      }

      $transaction_id = $order->get_order_number();

      //Get notification url (URL that IPNs will be sent to)
      //$webhook_url = $this->get_option('notification_url', WC()->api_request_url('WC_Gateway_Paygate'));
      $webhook_url = WC()->api_request_url('WC_Gateway_Paygate');
      $this->log('    [Info] Generating payment form for order ' . $order->get_order_number() . '. Notify URL: ' . $webhook_url);

      // Mark new order according to user settings (we're awaiting the payment)
      /*$new_order_states = $this->get_option('order_states');
      $new_order_status = $new_order_states['new'];*/
      $new_order_status = 'pending';
      $this->log('    [Info] Changing order status to: '.$new_order_status);
      $order->update_status($new_order_status);
      $this->log('    [Info] Changed order status result');

      //get_return_url - the url woocommerce thinks we should redirect to after payment
      $thanks_link = $this->get_return_url($order);
      $this->log('    [Info] The variable thanks_link = ' . $thanks_link . '...');

      // Redirect URL & Notification URL
      //Our own custom redirect url
      //$redirect_url = $this->get_option('redirect_url', $thanks_link);
      $redirect_url = $thanks_link;

      //If our custom redirect URL does not equal the thanks link, append an "order-received=<orderid>" param
      /*if($redirect_url !== $thanks_link)
      {
        $order_received_len = strlen('order-received');
        if(substr($redirect_url, -$order_received_len) === 'order-received')
        {
          $this->log('substr($redirect_url, -$order_received_pos) === order-received');
          $redirect_url = $redirect_url . '=' . $order->get_id();
        }
        else
        {
          $redirect_url = add_query_arg( 'order-received', $order->get_id(), $redirect_url);
        }
        $redirect_url = add_query_arg( 'key', $order->get_order_key(), $redirect_url);
      }*/

      $this->log('    [Info] The variable redirect_url = ' . $redirect_url  . '...');
      $this->log('    [Info] Notification URL is now set to: ' . $webhook_url . '...');

      $order_total = $order->calculate_totals();
      $frequency = 'SINGLE';
      $transactionType = $this->paygate_gateway_mode;
      $username = $this->paygate_client_id;

      error_log($order->get_customer_ip_address());

      $additionalInfo = array();
      $additionalInfo['billing_first_name'] = trim($order->get_billing_first_name());
      $additionalInfo['billing_last_name'] = trim($order->get_billing_last_name());
      $additionalInfo['billing_email'] = trim($order->get_billing_email());
      $additionalInfo['billing_street_1'] = trim($order->get_billing_address_1());
      $additionalInfo['billing_street_2'] = trim($order->get_billing_address_2());
      $additionalInfo['billing_city'] = trim($order->get_billing_city());
      $additionalInfo['billing_state'] = trim($order->get_billing_state());
      $additionalInfo['billing_postal_code'] = trim($order->get_billing_postcode());
      $additionalInfo['billing_country'] = trim($order->get_billing_country());
      $additionalInfo['ip_address'] = trim($order->get_customer_ip_address());
      $additionalInfoEncrypted = $this->encryptOpenSSL(json_encode($additionalInfo), $this->paygate_client_secret);

      $paygateUrl = $url . '/?transactionId=' . $transaction_id . '&webhookUrl=' . $webhook_url . '&redirectUrl=' . $redirect_url . '&amount=' . $order_total . '&frequency=' . $frequency . '&customerId=' . $username . '&transactionType=' . $transactionType . '&additionalInfo=' . $additionalInfoEncrypted;
      $unencoded_hash = hash_hmac('sha256', $paygateUrl, $this->paygate_client_secret, true);
      $request_url_hash = urlencode(base64_encode($unencoded_hash));
      $paygateUrl .= '&requestHash=' . $request_url_hash;

      //Assign variables to the woocommerce order
      update_post_meta($order_id, 'paygate_amount', $order_total);
      update_post_meta($order_id, 'paygate_gateway_mode', $transactionType);

      //Update some more items on the woocommerce order
      //$this->update_btcpay($order_id, $responseData);

      // Reduce stock levels
      if (function_exists('wc_reduce_stock_levels'))
      {
        wc_reduce_stock_levels($order_id);
      }
      else
      {
        $order->reduce_order_stock();
      }

      $this->log('    [Info] Leaving process_payment()...');

      // Redirect the customer to the BitPay invoice
      return array(
        'result'   => 'success',
        'redirect' => '/checkout/?paygate_checkout_url=' . urlencode($paygateUrl)
      );
    }

    private function encryptOpenSSL($plain_text, $passphrase)
    {
			$salt = openssl_random_pseudo_bytes(256);
			$iv = openssl_random_pseudo_bytes(16);
			$iterations = 999;

			$key = hash_pbkdf2("sha512", $passphrase, $salt, $iterations, 64);

			$encrypted_data = openssl_encrypt($plain_text, 'aes-256-cbc', hex2bin($key), OPENSSL_RAW_DATA, $iv);

			$data = array("ciphertext" => base64_encode($encrypted_data), "iv" => bin2hex($iv), "salt" => bin2hex($salt));
			return base64_encode(json_encode($data));
    }

    //Set up to be the callback for this gateway plugin
    public function paygate_webhook()
    {
      $this->log('    [Info] Entered paygate_webhook()...');

      //Get POST data and confirm it even exists
      $post = file_get_contents("php://input");
      if (true === empty($post))
      {
        $this->log('    [Error] No post data sent to webhook handler!');
        error_log('[Error] Paygate plugin received empty POST data for a webhook message.');
        wp_die('No post data');
      }
      else
      {
        $this->log('    [Info] The post data sent to webhook handler is present...');
        $this->log($post);
      }

      $paygate_header_hash = $_SERVER['HTTP_X_PAYGATE_WEBHOOK_SIGNATURE'];
      $paygate_generated_hash = urlencode(base64_encode(hash_hmac('sha256', $post, $this->paygate_client_secret, true)));
      $this->log('    [Info] Generated hash: ' . $paygate_generated_hash . ' / Header hash: ' . $paygate_header_hash);

      if($paygate_header_hash != $paygate_generated_hash)
      {
        $this->log('    [Error] Header hash does not match generated hash! Generated hash: ' . $paygate_generated_hash . ' / Header hash: ' . $paygate_header_hash);
        error_log('[Error] Paygate plugin received webhook message with hash mismatch.');
        wp_die('No post data');
      }
      else
      {
        $this->log('    [Info] Matched hash, message from Paygate is valid');
      }

      try
      {
        $this->log('    [Info] Successfully decoded post data');
        $post = json_decode($post);
      }
      catch(Exception $e)
      {
        $this->log('    [Error] Malformed post data sent to webhook handler');
        error_log('[Error] Paygate plugin received malformed POST data for a webhook message.');
        wp_die('Malformed post data');
      }

      $order_id = $post->transactionId;

      if (false === isset($order_id) && true === empty($order_id))
      {
        $this->log('    [Error] The Paygate payment plugin was called to process a webhook message but could not obtain the order ID from the post body.');
        throw new \Exception('The Paygate payment plugin was called to process a webhook message but could not obtain the order ID from the post body. Cannot continue!');
      }
      else
      {
        $this->log('    [Info] Order ID is: ' . $order_id);
      }

      //this is for the basic and advanced woocommerce order numbering plugins
      //if we need to apply other filters, just add them in place of the this one
      $order_id = apply_filters('woocommerce_order_id_from_number', $order_id);

      $order = wc_get_order($order_id);

      if (false === $order || ('WC_Order' !== get_class($order) && 'WC_Admin_Order' !== get_class($order) && 'Automattic\WooCommerce\Admin\Overrides\Order' != get_class($order)))
      {
        $this->log('    [Error] The Paygate payment plugin was called to process a webhook message but could not retrieve the order details for order_id: "' . $order_id . '". If you use an alternative order numbering system, please see class-wc-gateway-paygate.php to apply a search filter.');
        throw new \Exception('The Paygate payment plugin was called to process a webhook message but could not retrieve the order details for order_id ' . $order_id . '. Order was ' . ($order === false ? 'False' : 'Not False (' . get_class($order) . ')') . '. Cannot continue!');
      }
      else
      {
        $this->log('    [Info] Order details retrieved successfully...');
      }

      //Confirm the order used the paygate method
      if(!$this->is_paygate_payment_method($order))
      {
        $this->log('    [Info] Not using paygate payment method...');
        $this->log('    [Info] Leaving paygate_webhook()...');
        return;
      }

      $expected_amount = $order->get_total();

      if (false === isset($expected_amount) || true === empty($expected_amount))
      {
        $this->log('    [Info] Receiving webhook message for an order which has no price. How did you manage this?');
        return;
      }

      if($expected_amount !== $post->amount)
      {
        $this->log('    [Error] Received webhook message for order '. $order_id . ' with amount ' . $post->amount . ' while expected amount is ' . $expected_amount);
        throw new \Exception('Received webhook message for order '. $order_id . ' with amount ' . $post->amount . ' while expected amount is ' . $expected_amount);
      }

      $expected_transaction_type = get_post_meta($order->get_id(), 'paygate_gateway_mode', true);

      if (false === isset($expected_transaction_type) || true === empty($expected_transaction_type))
      {
        $this->log('    [Info] Receiving webhook message for an order which has no expected transaction type.');
        return;
      }

      if($expected_transaction_type !== $post->transactionType)
      {
        $this->log('    [Error] Received webhook message for order '. $order_id . ' with transaction type ' . $post->transactionType . ' while expected transaction type is ' . $expected_transaction_type);
        throw new \Exception('Received webhook message for order '. $order_id . ' with transaction type ' . $post->transactionType . ' while expected transaction type is ' . $expected_transaction_type);
      }

      //Confirm that this order matches the one the IPN is for
      //TODO: SET THIS UP
      /*$expected_invoiceId = get_post_meta($order_id, 'BTCPay_id', true);

      if (false === isset($expected_invoiceId) || true === empty($expected_invoiceId))
      {
        $this->log('    [Info] Receiving IPN for an order which has no expected invoice ID, ignoring the IPN...');
        return;
      }

      if($expected_invoiceId !== $json['id'])
      {
        $this->log('    [Error] Received IPN for order '. $order_id . ' with BTCPay invoice id ' . $json['id'] . ' while expected BTCPay invoice is ' . $expected_invoiceId);
        throw new \Exception('Received IPN for order '. $order_id . ' with BTCPay invoice id ' . $json['id'] . ' while expected BTCPay invoice is ' . $expected_invoiceId);
      }*/

      //Set up all the Paygate statuses
      $order_states = $this->get_option('order_states');

      $paid_status      = 'processing';
      $on_hold_status   = 'on-hold';
      $invalid_status   = 'failed';

      //Determine what to do based on the paygate order status
      $checkStatus = $post->resultNumber;

      if (false === isset($checkStatus) && true === empty($checkStatus))
      {
        $this->log('    [Error] The Paygate payment plugin was called to process a webhook message but could not obtain the current status from the webhook.');
        throw new \Exception('The Paygate payment plugin was called to process a webhook message but could not obtain the current status from the webhook. Cannot continue!');
      }
      else
      {
        $this->log('    [Info] The current status for this invoice is ' . $checkStatus);
      }

      // The "paid" IPN message is received almost
      // immediately after the BitPay invoice is paid.
      if($expected_transaction_type == 'SALE' && $checkStatus == '1') {
        $this->log('    [Info] This order has not been updated yet so setting new status...');
        $order->update_status($paid_status);
        $order->add_order_note(__('Successful payment via Paygate.' . $this->format_webhook_info($post), 'paygate'));
      }
      else if($expected_transaction_type == 'AUTHORIZE' && $checkStatus == '1') {
        $this->log('    [Info] This order has not been updated yet so setting new status...');
        $order->update_status($on_hold_status);
        $order->add_order_note(__('Successful authorization via Paygate. Capture using the "Capture" button. ' . $this->format_webhook_info($post), 'paygate'));
      }
      else {
        $this->log('    [Info] This order has a problem so setting "invalid" status...');
        $order->update_status($invalid_status, __('Paygate checkout failed for this order! Do not ship the product for this order!', 'paygate'));
        $order->add_order_note(__('Failed payment attempt via Paygate.' . $this->format_webhook_info($post), 'paygate'));
      }

      $this->update_paygate_metadata($order_id, $post);

      $this->log('    [Info] Leaving paygate_webhook()...');
    }

    public function format_webhook_info($post)
    {
      return
        'Amount ' . $post->amount .
        ', Paygate ID (Unique) ' . $post->transactionIdUnique .
        ', Transaction Type ' . $post->transactionType .
        ', Transaction Frequency ' . $post->transactionFrequency .
        ', Remote ID ' . $post->remoteTransactionId .
        ', Result Number ' . $post->resultNumber .
        ', Result Code ' . $post->resultCode .
        ', Message: "' . $post->resultText . '"';
    }

    public function update_paygate_metadata($order_id, $post)
    {
      update_post_meta($order_id, 'paygate_transaction_id_unique', $post->transactionIdUnique);
      update_post_meta($order_id, 'paygate_remote_transaction_id', $post->remoteTransactionId);
      update_post_meta($order_id, 'paygate_result_number', $post->resultNumber);
      update_post_meta($order_id, 'paygate_result_code', $post->resultCode);
      update_post_meta($order_id, 'paygate_message', $post->resultText);
    }

    function add_capture_button($order) {

        //Only add on paygate auth orders
        if($this->is_paygate_payment_method($order) != 'paygate') {
          return;
        }

        $status = $order->get_status();
        if($status != 'on-hold') {
          return;
        }

        $expected_transaction_type = get_post_meta($order->get_id(), 'paygate_gateway_mode', true);
        if($expected_transaction_type != 'AUTHORIZE') {
          return;
        }

        $classes = array(
          'button',
          'paygate-for-woocommerce-gateway-capture',
          'button-primary'
        );

        ?>

        <button type="button" onclick="document.getElementById('capture_order').value = 1; document.post.submit();" class="<?php echo esc_attr( implode( ' ', $classes ) ); ?>"><?php _e( 'Capture Charge', 'paygate' ); ?></button>
        <input type="hidden" value="0" id="capture_order" name="capture_order" />

        <?php
    }

    function capture_order_handler($post_id) {
        // If this isn't the admin panel, return
        if(!is_admin()) {
            return;
        }

        $order = wc_get_order($post_id);

        // If this isn't a 'woocommercer order' post, don't update it.
        if(!$order) {
          return;
        }

        //If this is not our capture order
        if(!isset($_POST['capture_order']) || !$_POST['capture_order']) {
          return;
        }

        //Confirm the order used the paygate method
        if($this->is_paygate_payment_method($order) != 'paygate') {
          set_transient( 'paygate_admin_notice_show_error_message', 'Called paygate capture function on non-paygate order', 5 );
          return;
        }

        $status = $order->get_status();
        if($status != 'on-hold') {
          set_transient( 'paygate_admin_notice_show_error_message', 'Cannot capture paygate order, order is not in the expected state (on hold)', 5 );
          return;
        }

        $expected_transaction_type = get_post_meta($order->get_id(), 'paygate_gateway_mode', true);
        if($expected_transaction_type != 'AUTHORIZE') {
          set_transient( 'paygate_admin_notice_show_error_message', 'Cannot capture paygate order, order is not an authorize-type order', 5 );
          return;
        }

        $remoteTransactionId = get_post_meta($order->get_id(), 'paygate_remote_transaction_id', true);
        if(!$remoteTransactionId) {
          set_transient( 'paygate_admin_notice_show_error_message', 'Cannot capture paygate order, order does not have a remote transaction id', 5 );
          return;
        }

        try {
          $url = $this->paygate_endpoint;
          $capture_url = $url . '/api/capture?remoteTransactionId=' . $remoteTransactionId;
          $unencoded_hash = hash_hmac('sha256', $capture_url, $this->paygate_client_secret, true);
          $request_url_hash = urlencode(base64_encode($unencoded_hash));
          $capture_url .= '&requestHash=' . $request_url_hash;

          $curl = curl_init();
          curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_URL => $capture_url
          ]);

          $resp = curl_exec($curl);
          curl_close($curl);

          $resp = json_decode($resp);

          if($resp->error) {
            set_transient( 'paygate_admin_notice_show_error_message', $resp->error, 5 );
            $order->add_order_note(__('Failed to capture authorized payment via Paygate. Error was: ' . $resp->error, 'paygate'));
            return;
          }

          if(!$resp->success) {
            set_transient( 'paygate_admin_notice_show_error_message', 'Capture response was something unexpected', 5 );
            return;
          }

          $order->update_status('processing');
          $order->add_order_note(__('Successfully captured authorized payment via Paygate.', 'paygate'));
          set_transient( 'paygate_admin_notice_show_success_message', 'Successfully captured authorized payment via Paygate', 5 );
        }
        catch(Exception $e) {
          set_transient( 'paygate_admin_notice_show_error_message', $e->getMessage(), 5 );
          return;
        }
    }

    function paygate_modal_footer() {
      ?>
      <script type="text/javascript">
        function getUrlVars() {
          var vars = {};
          var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi, function(m,key,value) {
            vars[key] = value;
          });
          return vars;
        }

        $(document).ready(function() {
          if(!$('body').hasClass('woocommerce-checkout')) {
            return;
          }

          var paygateCheckoutUrl = decodeURIComponent(getUrlVars()['paygate_checkout_url']);
          if(!paygateCheckoutUrl || paygateCheckoutUrl.indexOf("<?php echo($this->paygate_endpoint); ?>") != 0) {
            return;
          }

          if(paygateCheckoutUrl) {
            $('div#popup-modal-paygate-checkout iframe').attr('src', paygateCheckoutUrl);
            MicroModal.show('popup-modal-paygate-checkout');
          }
        });
      </script>
      <div class="modal micromodal-slide popup-modal" id="popup-modal-paygate-checkout" aria-hidden="true">
        <div class="modal__overlay" tabindex="-1" data-micromodal-close>
          <div class="modal__container" role="dialog" aria-modal="true" aria-labelledby="modal-title" style="padding: 0;">
            <main class="modal__content" id="modal-content" style="overflow: hidden; line-height: 0; border: 0;">
              <iframe width="400" style="height: 709px; margin: 0; border: 0;"></iframe>
            </main>
          </div>
        </div>
      </div>

      <?php
    }

    public function log($message)
    {
      if (true === isset($this->debug) && 'yes' == $this->debug)
      {
        if (false === isset($this->logger) || true === empty($this->logger))
        {
            $this->logger = new WC_Logger();
        }

        $this->logger->add('paygate', $message);
      }
    }
  }

  /**
  * Add BitPay Payment Gateway to WooCommerce
  * REQUIRED ITEM
  **/
  function wc_add_paygate($methods)
  {
    $methods[] = 'WC_Gateway_Paygate';
    return $methods;
  }

  add_filter('woocommerce_payment_gateways', 'wc_add_paygate');

  /**
   * Add Settings and Logs link to the plugin entry in the plugins menu
   **/
  add_filter('plugin_action_links', 'paygate_plugin_action_links', 10, 2);

  function paygate_plugin_action_links($links, $file)
  {
    static $this_plugin;

    if (false === isset($this_plugin) || true === empty($this_plugin)) {
      $this_plugin = plugin_basename(__FILE__);
    }

    if ($file == $this_plugin) {
      $log_file = 'paygate-' . sanitize_file_name( wp_hash( 'paygate' ) ) . '-log';
      $settings_link = '<a href="' . get_bloginfo('wpurl') . '/wp-admin/admin.php?page=wc-settings&tab=checkout&section=wc_gateway_paygate">Settings</a>';
      $logs_link = '<a href="' . get_bloginfo('wpurl') . '/wp-admin/admin.php?page=wc-status&tab=logs&log_file=' . $log_file . '">Logs</a>';
      array_unshift($links, $settings_link, $logs_link);
    }

    return $links;
  }

  //Used to modify the thankyou page
  function action_woocommerce_thankyou_paygate($order_id)
  {
    $wc_order = wc_get_order($order_id);

    if($wc_order === false)
    {
        return;
    }

    $order_data     = $wc_order->get_data();
    $status         = $order_data['status'];

    $payment_status = file_get_contents(plugin_dir_path(__FILE__) . 'templates/paymentStatus.tpl');
    $payment_status = str_replace('{$statusTitle}', _x('Payment Status', 'woocommerce_paygate'), $payment_status);

    switch ($status)
    {
        case 'on-hold':
          $status_desctiption = _x('Payment authorized', 'woocommerce_paygate');
          break;
        case 'processing':
          $status_desctiption = _x('Payment processing', 'woocommerce_paygate');
          break;
        case 'completed':
          $status_desctiption = _x('Payment completed', 'woocommerce_paygate');
          break;
        case 'failed':
          $status_desctiption = _x('Payment failed', 'woocommerce_paygate');
          break;
        default:
          $status_desctiption = _x(ucfirst($status), 'woocommerce_paygate');
          break;
    }

    echo str_replace('{$paymentStatus}', $status_desctiption, $payment_status);
  }

  add_action("woocommerce_thankyou_paygate", 'action_woocommerce_thankyou_paygate', 10, 1);
}

//Called if we fail requirements in activate
/*function woocommerce_btcpay_failed_requirements()
{
  global $wp_version;
  global $woocommerce;

  $errors = array();
  if (extension_loaded('openssl')  === false)
  {
    $errors[] = 'The BTCPay payment plugin requires the OpenSSL extension for PHP in order to function. Please contact your web server administrator for assistance.';
  }
  // PHP 5.4+ required
  if (true === version_compare(PHP_VERSION, '5.4.0', '<'))
  {
    $errors[] = 'Your PHP version is too old. The BTCPay payment plugin requires PHP 5.4 or higher to function. Please contact your web server administrator for assistance.';
  }

  // Wordpress 3.9+ required
  if (true === version_compare($wp_version, '3.9', '<'))
  {
    $errors[] = 'Your WordPress version is too old. The BTCPay payment plugin requires Wordpress 3.9 or higher to function. Please contact your web server administrator for assistance.';
  }

  // WooCommerce required
  if (true === empty($woocommerce))
  {
    $errors[] = 'The WooCommerce plugin for WordPress needs to be installed and activated. Please contact your web server administrator for assistance.';
  }
  elseif (true === version_compare($woocommerce->version, '2.2', '<'))
  {
    $errors[] = 'Your WooCommerce version is too old. The BTCPay payment plugin requires WooCommerce 2.2 or higher to function. Your version is '.$woocommerce->version.'. Please contact your web server administrator for assistance.';
  }

  // GMP or BCMath required
  if (false === extension_loaded('gmp') && false === extension_loaded('bcmath'))
  {
    $errors[] = 'The BTCPay payment plugin requires the GMP or BC Math extension for PHP in order to function. Please contact your web server administrator for assistance.';
  }

  // Curl required
  if (false === extension_loaded('curl'))
  {
    $errors[] = 'The BTCPay payment plugin requires the Curl extension for PHP in order to function. Please contact your web server administrator for assistance.';
  }

  if (false === empty($errors))
  {
    return implode("<br>\n", $errors);
  }
  else
  {
    return false;
  }
}*/

// Activating the plugin
/*function woocommerce_btcpay_activate()
{
  // Check for Requirements
  $failed = woocommerce_btcpay_failed_requirements();

  $plugins_url = admin_url('plugins.php');

  // Requirements met, activate the plugin
  if ($failed === false)
  {
    // Deactivate any older versions that might still be present
    $plugins = get_plugins();

    foreach ($plugins as $file => $plugin)
    {
      //Alert that Bitpay needs to be deleted
      if ('Bitpay Woocommerce' === $plugin['Name'] && true === is_plugin_active($file))
      {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die('BtcPay for WooCommerce requires that the old plugin, <b>Bitpay Woocommerce</b>, is deactivated and deleted.<br><a href="'.$plugins_url.'">Return to plugins screen</a>');
      }

      //Alert that an older version of btcpay for woocommerce must be deactivated
      if ('BTCPay for WooCommerce' === $plugin['Name'] && true === is_plugin_active($file) && (0 > version_compare( $plugin['Version'], '3.0' )))
      {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die('BtcPay for WooCommerce requires that the 2.x version of this plugin is deactivated. <br><a href="'.$plugins_url.'">Return to plugins screen</a>');
      }

      //Migrating from a version > 2.0. Try to pull btcpay settings first, if not, bitpay settings
      if('BTCPay for WooCommerce' === $plugin['Name'] && (0 > version_compare( $plugin['Version'], '3.0.1' )))
      {
        update_option('woocommerce_btcpay_key',
          get_option( 'woocommerce_btcpay_key', get_option('woocommerce_bitpay_key', null) )
        );

        update_option('woocommerce_btcpay_pub',
          get_option( 'woocommerce_btcpay_pub', get_option('woocommerce_bitpay_pub', null) )
        );

        update_option('woocommerce_btcpay_sin',
          get_option( 'woocommerce_btcpay_sin', get_option('woocommerce_bitpay_sin', null) )
        );

        update_option('woocommerce_btcpay_token',
          get_option( 'woocommerce_btcpay_token', get_option('woocommerce_bitpay_token', null) )
        );

        update_option('woocommerce_btcpay_label',
          get_option( 'woocommerce_btcpay_label', get_option('woocommerce_bitpay_label', null) )
        );

        update_option('woocommerce_btcpay_network',
          get_option( 'woocommerce_btcpay_network', get_option('woocommerce_bitpay_network', null) )
        );

        update_option('woocommerce_btcpay_settings',
          get_option( 'woocommerce_btcpay_settings', get_option('woocommerce_bitpay_settings', null) )
        );

        update_option('woocommerce_btcpay_url',
          get_option( 'woocommerce_btcpay_url', get_option('woocommerce_bitpay_url', null) )
        );

        update_option('woocommerce_btcpay_notification_url',
          get_option( 'woocommerce_btcpay_notification_url', get_option('woocommerce_bitpay_notification_url', null) )
        );

        update_option('woocommerce_btcpay_redirect_url',
          get_option( 'woocommerce_btcpay_redirect_url', get_option('woocommerce_bitpay_redirect_url', null) )
        );

        update_option('woocommerce_btcpay_transaction_speed',
          get_option( 'woocommerce_btcpay_transaction_speed', get_option('woocommerce_bitpay_transaction_speed', null) )
        );

        update_option('woocommerce_btcpay_order_states',
          get_option( 'woocommerce_btcpay_order_states', get_option('woocommerce_bitpay_order_states', null) )
        );


        set_transient( 'fx_admin_notice_show_migration_message', true, 5 );
      }
    }

    update_option('woocommerce_btcpay_version', constant("BTCPAY_VERSION"));

  }
  else
  {
    // Requirements not met, return an error message
    wp_die($failed . '<br><a href="'.$plugins_url.'">Return to plugins screen</a>');
  }
}*/

function paygate_admin_notice_show_success_message()
{
  $success_message = get_transient( 'paygate_admin_notice_show_success_message' );

  if($success_message != null)
  {
      ?>

      <div class="notice notice-success is-dismissible">
          <p><?php echo $success_message ?></p>
      </div>

      <?php
      //Delete transient, only display this notice once.
      delete_transient( 'paygate_admin_notice_show_success_message' );
  }
}

function paygate_admin_notice_show_error_message()
{
  $error_message = get_transient( 'paygate_admin_notice_show_error_message' );

  if($error_message != null)
  {
      ?>

      <div class="notice notice-error is-dismissible">
          <p><?php echo $error_message ?></p>
      </div>

      <?php
      //Delete transient, only display this notice once.
      delete_transient( 'paygate_admin_notice_show_error_message' );
  }
}
