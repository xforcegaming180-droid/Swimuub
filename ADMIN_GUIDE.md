# SwimHub Admin Quick Start Guide

## 🚀 Getting Started

### First Time Setup

1. **Configure Environment Variables**
   ```bash
   cd server
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Start the Server**
   ```bash
   npm start
   ```

4. **Verify Health**
   ```bash
   curl http://localhost:3000/health
   ```

## 📦 Managing License Keys

### Adding License Keys

Use the Discord bot command `/addlicense`:

1. Type `/addlicense` in your Discord server
2. A modal will appear
3. Paste your license keys (one per line)
4. Submit the modal
5. Bot will confirm how many keys were added

**Example Input:**
```
SWIM-1234-5678-ABCD
SWIM-2345-6789-BCDE
SWIM-3456-7890-CDEF
```

**Tips:**
- Keys are automatically converted to uppercase
- Duplicate keys are detected and skipped
- You can add up to 4000 characters worth of keys at once (about 80-100 keys)

### Checking Stock Levels

Use `/stock` command to see:
- **Polar Integration Keys**: Generic keys for all products
- **Legacy Product Keys**: Product-specific keys (if any)
- **Grand Total**: Complete inventory overview

### Understanding Stock Status

The health endpoint returns stock status:
- **good**: More than 10 keys available ✅
- **low**: Between 1-10 keys available ⚠️
- **out_of_stock**: 0 keys available 🚨

## 🔔 Notifications

### Low Stock Alert
When available keys drop to 10 or below, you'll receive a Discord DM:

```
⚠️ Low License Stock Alert
License key inventory is running low!

Available Keys: 8
Used Keys: 42
Total Keys: 50

Please add more keys soon
```

### Out of Stock Alert
When you run out of keys completely:

```
🚨 OUT OF STOCK - CRITICAL
No license keys available! Customers cannot complete purchases.

Available Keys: 0
Status: ❌ Out of Stock

ADD KEYS IMMEDIATELY
```

### Purchase Notifications
Every time a customer purchases, you get a notification with:
- License key assigned
- Customer email
- Checkout ID

## 🔧 Configuration

### Adjusting Low Stock Threshold

In your `.env` file:
```bash
# Alert when stock drops to this level or below
LOW_STOCK_THRESHOLD=10
```

Recommended values:
- **Small operation**: 5-10 keys
- **Medium operation**: 20-30 keys
- **Large operation**: 50+ keys

### Rate Limiting

Default limits (configured in code):
- Webhooks: 100 requests per 15 minutes
- Polling: 120 requests per minute
- Health checks: 100 requests per 15 minutes

## 📊 Monitoring

### Health Check Endpoint

**URL**: `https://your-domain.com/health`

**Response Example:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "services": {
    "database": "connected",
    "discord": "connected"
  },
  "stock": {
    "available": 45,
    "total": 100,
    "status": "good"
  }
}
```

**Use Cases:**
- Set up uptime monitoring (UptimeRobot, Pingdom, etc.)
- Create stock alerts based on the API
- Monitor service health in real-time
- Integrate with dashboards (Grafana, DataDog)

### Setting Up Monitoring

**UptimeRobot Example:**
1. Add new monitor
2. Type: HTTP(s)
3. URL: `https://your-domain.com/health`
4. Interval: 5 minutes
5. Alert when status is not "healthy"

**Custom Script Example:**
```bash
#!/bin/bash
# check-stock.sh

HEALTH_URL="https://your-domain.com/health"
ALERT_THRESHOLD=20

AVAILABLE=$(curl -s $HEALTH_URL | jq -r '.stock.available')

if [ "$AVAILABLE" -lt "$ALERT_THRESHOLD" ]; then
  echo "⚠️ Stock is low: $AVAILABLE keys remaining"
  # Send alert via your preferred method
fi
```

## 🛠️ Troubleshooting

### No Keys Being Assigned

**Check:**
1. Verify keys exist in database: `/stock` command
2. Check Polar webhook is configured correctly
3. View server logs for errors
4. Test webhook: `curl -X GET https://your-domain.com/webhook/polar`

### Discord Notifications Not Working

**Check:**
1. Bot is logged in: Check server logs
2. `ADMIN_DISCORD_ID` is correct
3. Bot has permission to send DMs
4. You haven't blocked the bot

### Health Check Returns Unhealthy

**Possible Issues:**
- Database connection failed
- Discord bot disconnected
- Server error

**Fix:**
1. Check database connection string
2. Verify Discord bot token
3. Review server logs for errors

## 📝 Common Tasks

### Adding Bulk Keys

**Method 1: Discord Command (Recommended)**
Use `/addlicense` for up to 100 keys at once

**Method 2: API Endpoint**
```bash
curl -X POST https://your-domain.com/api/licenses/add \
  -H "Content-Type: application/json" \
  -d '{
    "keys": ["KEY1", "KEY2", "KEY3"],
    "token": "YOUR_INTERNAL_PROCESS_TOKEN"
  }'
```

**Method 3: Direct Database**
```sql
INSERT INTO licenses (key_value, status, created_at, updated_at)
VALUES
  ('KEY1', 'available', now(), now()),
  ('KEY2', 'available', now(), now()),
  ('KEY3', 'available', now(), now());
```

### Checking Recent Purchases

```sql
SELECT 
  key_value,
  owner_email,
  checkout_id,
  created_at
FROM licenses
WHERE status = 'used'
ORDER BY updated_at DESC
LIMIT 10;
```

### Finding Unused Keys

```sql
SELECT 
  key_value,
  created_at
FROM licenses
WHERE status = 'available'
ORDER BY created_at ASC;
```

## 🔐 Security Best Practices

1. **Keep `INTERNAL_PROCESS_TOKEN` secret** - Never share it
2. **Use strong webhook secrets** - 32+ random characters
3. **Monitor rate limiting** - Check for abuse attempts
4. **Regular backups** - Backup your database
5. **Update dependencies** - Keep packages up to date

## 🎯 Daily Checklist

- [ ] Check stock levels (`/stock` or `/health`)
- [ ] Review recent purchases (Discord notifications)
- [ ] Monitor for any alerts
- [ ] Ensure health check is green
- [ ] Add keys if stock is low

## 🆘 Emergency Procedures

### Out of Stock Emergency

1. **Immediate**: Add keys using `/addlicense`
2. **Verify**: Run `/stock` to confirm keys added
3. **Test**: Do a test purchase if possible
4. **Monitor**: Watch for purchase completions

### Database Connection Lost

1. Check database service status
2. Verify `DATABASE_URL` environment variable
3. Restart server if needed
4. Check health endpoint recovers

### Discord Bot Offline

1. Verify `DISCORD_BOT_TOKEN` is correct
2. Check bot has required permissions
3. Restart server
4. Confirm bot appears online in Discord

## 📞 Support

For help or issues:
1. Check this guide first
2. Review server logs
3. Check the health endpoint
4. Review [CHANGES.md](./CHANGES.md) for recent updates
5. Contact development team

---

**Last Updated**: December 2024  
**Version**: 2.0.0
