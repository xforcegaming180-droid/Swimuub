# SwimHub License System - Polar Integration Guide

This document explains how to configure the SwimHub license system to work with Polar.sh for automated license key delivery.

## Overview

The system has been updated to use Polar.sh for payment processing and license key delivery. After a customer completes payment on Polar, they are redirected to a waiting page that automatically retrieves and displays their license key.

## Architecture

1. Customer clicks "Purchase" button on website
2. Customer is redirected to Polar.sh checkout page
3. After successful payment, Polar redirects to `/waiting?checkout_id={CHECKOUT_ID}`
4. Waiting page polls the server for the license key
5. Server webhook receives payment notification from Polar and assigns license key
6. License key is displayed to customer on the waiting page

## Polar Configuration

### 1. Product Setup in Polar

For each product (Regular Monthly, Regular Lifetime, Master Monthly, Master Lifetime, Nightly):

1. Create a product in your Polar.sh dashboard
2. Set the product name and price
3. Configure the success URL to: `https://swimhub.club/waiting?checkout_id={CHECKOUT_ID}`
   - The `{CHECKOUT_ID}` placeholder will be automatically replaced by Polar with the actual checkout ID
4. Note down the checkout URL for each product

### 2. Update Checkout URLs

Update the Polar checkout URLs in `/purchase.html` (or configure them as environment variables):

```javascript
const polarCheckoutUrls = {
    'regular-monthly': 'YOUR_POLAR_CHECKOUT_URL_HERE',
    'regular-lifetime': 'YOUR_POLAR_CHECKOUT_URL_HERE',
    'master-monthly': 'YOUR_POLAR_CHECKOUT_URL_HERE',
    'master-lifetime': 'YOUR_POLAR_CHECKOUT_URL_HERE',
    'nightly': 'YOUR_POLAR_CHECKOUT_URL_HERE'
};
```

### 3. Webhook Configuration

1. In your Polar.sh dashboard, go to Settings → Webhooks
2. Add a new webhook endpoint: `https://swimhub.club/webhook/polar`
3. Subscribe to these events:
   - `checkout.completed`
   - `order.created`
   - `payment.success`
4. Copy the webhook signing secret
5. Add it to your environment variables as `POLAR_WEBHOOK_SECRET`

### 4. Environment Variables

Add these environment variables to your server:

```bash
# Polar Webhook Configuration
POLAR_WEBHOOK_SECRET=your_webhook_secret_here

# Optional: Skip signature verification for testing (NOT recommended for production)
POLAR_SKIP_SIGNATURE=false

# Optional: Polar checkout URLs (can be hardcoded in frontend instead)
POLAR_URL_REGULAR_MONTHLY=https://polar.sh/...
POLAR_URL_REGULAR_LIFETIME=https://polar.sh/...
POLAR_URL_MASTER_MONTHLY=https://polar.sh/...
POLAR_URL_MASTER_LIFETIME=https://polar.sh/...
POLAR_URL_NIGHTLY=https://polar.sh/...

# Discord Admin Notifications (optional)
ADMIN_DISCORD_ID=your_discord_id
DISCORD_BOT_TOKEN=your_bot_token
```

## Adding License Keys to Stock

License keys need to be pre-loaded into the database. Use one of these methods:

### Method 1: Discord Bot Command (Recommended)

```
/addlicense keys:KEY1,KEY2,KEY3
```

### Method 2: API Endpoint

```bash
curl -X POST https://swimhub.club/api/licenses/add \
  -H "Content-Type: application/json" \
  -d '{
    "keys": ["KEY1", "KEY2", "KEY3"],
    "token": "YOUR_INTERNAL_PROCESS_TOKEN"
  }'
```

### Method 3: Direct Database Insert

```sql
INSERT INTO licenses (key_value, status, created_at, updated_at)
VALUES 
  ('KEY1', 'available', now(), now()),
  ('KEY2', 'available', now(), now()),
  ('KEY3', 'available', now(), now());
```

## Testing the Flow

1. Go to `/purchase` on your website
2. Click a "Purchase" button
3. Complete the checkout on Polar (use test mode)
4. Verify you're redirected to `/waiting?checkout_id=xxx`
5. Verify the license key appears after a few seconds
6. Check that you can copy the license key

## URL Rewriting

The website now supports clean URLs without `.html` extensions:

- `/purchase` → serves `purchase.html`
- `/success` → serves `success.html`
- `/waiting` → serves `waiting.html`
- `/terms` → serves `terms.html`
- `/privacy` → serves `privacy.html`

Old URLs with `.html` extensions still work for backwards compatibility.

## API Endpoints

### GET `/api/claim-key?checkout_id={id}`

Polls for license key availability after payment.

**Response:**
```json
{
  "status": "ready",
  "key": "XXXX-XXXX-XXXX-XXXX"
}
```

or

```json
{
  "status": "pending"
}
```

### POST `/webhook/polar`

Receives webhooks from Polar.sh and assigns license keys.

### GET `/api/licenses/stock`

Returns current license stock statistics.

**Response:**
```json
{
  "success": true,
  "total": 100,
  "available": 75,
  "used": 25
}
```

## Troubleshooting

### License key not appearing on waiting page

1. Check webhook logs to ensure Polar is sending webhooks
2. Verify webhook signature is correct
3. Check that there are available license keys in stock (`/api/licenses/stock`)
4. Check server logs for errors

### Webhook signature verification failing

1. Verify `POLAR_WEBHOOK_SECRET` matches the secret in Polar dashboard
2. Check that the webhook endpoint is publicly accessible
3. Temporarily set `POLAR_SKIP_SIGNATURE=true` for testing (NOT for production)

### No available license keys

1. Check stock with `/api/licenses/stock`
2. Add more keys using one of the methods above
3. Ensure keys are marked as `status='available'` in database

## Security Notes

1. **Never** set `POLAR_SKIP_SIGNATURE=true` in production
2. Keep `POLAR_WEBHOOK_SECRET` and `INTERNAL_PROCESS_TOKEN` secure
3. Use environment variables, never commit secrets to git
4. Enable rate limiting on all public endpoints
5. Monitor webhook logs for suspicious activity

## Migration from Old System

The old Discord OAuth flow has been removed. If you had pending purchases in the old system:

1. They will not automatically work with the new Polar system
2. Customers should make new purchases through Polar
3. Old database tables (`pending_purchases`, `user_licenses`) can be archived but are kept for reference

## Support

For issues with:
- Payment processing: Contact Polar.sh support
- License key delivery: Check server logs and webhook delivery in Polar dashboard
- Website issues: Check browser console and server logs
