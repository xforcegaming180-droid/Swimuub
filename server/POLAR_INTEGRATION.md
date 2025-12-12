# Polar.sh Integration Setup Guide

## Overview
This system integrates with Polar.sh to automatically deliver license keys to customers after purchase. The workflow is:

1. Customer completes purchase on Polar.sh
2. Polar sends webhook to your server
3. Server assigns a license key and stores it with checkout_id
4. Polar redirects customer to success page with checkout_id
5. Success page polls server to retrieve and display the license key
6. Admin receives Discord notification with purchase details

## Prerequisites

- Node.js 18+ 
- PostgreSQL database
- Discord bot with DM permissions
- Polar.sh account with webhook support

## Installation

1. Install dependencies:
```bash
cd server
npm install
```

2. Set up environment variables (see Configuration section below)

3. Run the server:
```bash
npm start
```

## Configuration

Create a `.env` file in the `server` directory with the following variables:

```bash
# Database
DATABASE_URL=postgresql://user:password@host:port/database

# Discord Bot
DISCORD_BOT_TOKEN=your_discord_bot_token
DISCORD_CLIENT_ID=your_discord_client_id
DISCORD_CLIENT_SECRET=your_discord_client_secret
DISCORD_GUILD_ID=your_discord_server_id
ADMIN_DISCORD_ID=your_discord_user_id

# Polar.sh
POLAR_WEBHOOK_SECRET=your_polar_webhook_secret
POLAR_SKIP_SIGNATURE=false  # Set to true only for testing

# Server
PORT=3000
WEBSITE_URL=https://your-domain.com
```

## Database Setup

The server automatically creates the required tables on startup:

### `licenses` Table
Stores available and assigned license keys.

```sql
CREATE TABLE licenses (
  id SERIAL PRIMARY KEY,
  key_value TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'available',  -- 'available' or 'used'
  owner_email TEXT,
  checkout_id TEXT,
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now()
);
```

### Adding License Keys

You can add keys via the API:

```bash
curl -X POST http://localhost:3000/api/licenses/add \
  -H "Content-Type: application/json" \
  -d '{
    "keys": ["KEY1-XXXX-XXXX", "KEY2-XXXX-XXXX"],
    "token": "your_internal_process_token"
  }'
```

Or directly in the database:

```sql
INSERT INTO licenses (key_value, status) 
VALUES ('YOUR-KEY-HERE', 'available');
```

## Polar.sh Configuration

### 1. Set Up Webhook

In your Polar.sh dashboard:

1. Go to Webhooks settings
2. Add webhook URL: `https://your-domain.com/webhook/polar`
3. Copy the webhook secret to your `.env` file as `POLAR_WEBHOOK_SECRET`
4. Enable the following events:
   - `checkout.completed`
   - `order.created`
   - `checkout.updated`
   - `payment.success`

### 2. Configure Success URL

Set your Polar product's success URL to:

```
https://your-domain.com/success.html?checkout_id={{CHECKOUT_ID}}
```

Make sure Polar replaces `{{CHECKOUT_ID}}` with the actual checkout ID.

## API Endpoints

### POST /webhook/polar
Receives webhooks from Polar.sh when purchases are completed.

**Headers:**
- `webhook-signature`: Signature for verification
- `webhook-timestamp`: Timestamp for signature

**Body:**
```json
{
  "type": "checkout.completed",
  "id": "event_id",
  "data": {
    "id": "checkout_123",
    "customer": {
      "email": "customer@example.com"
    }
  }
}
```

**Response:**
```json
{
  "received": true,
  "success": true
}
```

### GET /api/claim-key
Polling endpoint for frontend to retrieve license keys.

**Query Parameters:**
- `checkout_id` (required): The checkout ID from Polar

**Response (pending):**
```json
{
  "status": "pending"
}
```

**Response (ready):**
```json
{
  "status": "ready",
  "key": "XXXXX-XXXXX-XXXXX"
}
```

**Rate Limits:**
- Webhook: 100 requests per 15 minutes per IP
- Polling: 120 requests per minute per IP

## Frontend Integration

The `success.html` page automatically:

1. Extracts `checkout_id` from URL parameters
2. Polls `/api/claim-key` every 2 seconds
3. Displays the license key when ready
4. Shows a loading spinner while waiting
5. Times out after 2 minutes with error message

### Example URL
```
https://your-domain.com/success.html?checkout_id=checkout_abc123
```

## Security Features

1. **Webhook Signature Verification**: Uses HMAC-SHA256 with rawBody
2. **Rate Limiting**: Prevents abuse of API endpoints
3. **Row-Level Locking**: Prevents race conditions when assigning keys (FOR UPDATE SKIP LOCKED)
4. **SQL Injection Prevention**: All queries use parameterized statements
5. **Duplicate Prevention**: Webhook event IDs are tracked to prevent duplicate processing

## Troubleshooting

### "Invalid Polar webhook signature"

**Causes:**
- Webhook secret mismatch
- Request body modified before verification
- Missing rawBody middleware

**Solutions:**
1. Verify `POLAR_WEBHOOK_SECRET` matches Polar dashboard
2. Check that no middleware modifies the request body before the webhook handler
3. Set `POLAR_SKIP_SIGNATURE=true` temporarily to bypass (dev only!)

### Keys not appearing on frontend

**Causes:**
- No `checkout_id` in URL
- No available keys in database
- Webhook not processed successfully

**Solutions:**
1. Check browser console for errors
2. Verify URL has `?checkout_id=...` parameter
3. Check server logs for webhook processing
4. Verify database has keys with `status='available'`

```sql
-- Check available keys
SELECT COUNT(*) FROM licenses WHERE status='available';

-- Check if specific checkout has a key
SELECT * FROM licenses WHERE checkout_id='your_checkout_id';
```

### No Discord notification

**Causes:**
- Bot not logged in
- Invalid `ADMIN_DISCORD_ID`
- Bot lacks DM permissions

**Solutions:**
1. Check server logs for Discord login success
2. Verify `ADMIN_DISCORD_ID` is your actual Discord user ID
3. Ensure bot can send DMs (check Privacy Settings)

## Testing

### Test Webhook Locally

```bash
# Generate test signature
SECRET="your_webhook_secret"
PAYLOAD='{"type":"checkout.completed","id":"test","data":{"id":"checkout_test","customer":{"email":"test@example.com"}}}'
TIMESTAMP=$(date +%s)
SIGNATURE=$(echo -n "${TIMESTAMP}.${PAYLOAD}" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64)

# Send test webhook
curl -X POST http://localhost:3000/webhook/polar \
  -H "Content-Type: application/json" \
  -H "webhook-signature: v1,${SIGNATURE}" \
  -H "webhook-timestamp: ${TIMESTAMP}" \
  -d "$PAYLOAD"
```

### Test Polling Endpoint

```bash
# Check if key is ready (should return pending if no webhook processed yet)
curl "http://localhost:3000/api/claim-key?checkout_id=checkout_test"
```

## Production Deployment

### Environment Variables Checklist
- [ ] `DATABASE_URL` configured
- [ ] `DISCORD_BOT_TOKEN` set
- [ ] `DISCORD_CLIENT_ID` set
- [ ] `DISCORD_CLIENT_SECRET` set
- [ ] `DISCORD_GUILD_ID` set
- [ ] `ADMIN_DISCORD_ID` set
- [ ] `POLAR_WEBHOOK_SECRET` set
- [ ] `POLAR_SKIP_SIGNATURE` set to `false`
- [ ] `WEBSITE_URL` set to your domain
- [ ] `PORT` set (if not using default 3000)

### Pre-launch Tasks
1. Add initial license keys to database
2. Test webhook with Polar test mode
3. Verify Discord notifications work
4. Test full purchase flow end-to-end
5. Set up monitoring/logging
6. Configure HTTPS/SSL certificate

## Monitoring

Key metrics to monitor:
- Available license key count
- Webhook success/failure rate
- Average time from purchase to key delivery
- Rate limit violations
- Database connection pool status

## Support

For issues related to:
- **Polar.sh**: Contact Polar support
- **Discord bot**: Check Discord.js documentation
- **Database**: Check PostgreSQL logs
- **Server**: Check application logs with `pm2 logs` or `docker logs`
