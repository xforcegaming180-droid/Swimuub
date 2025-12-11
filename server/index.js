// index.js - full file (drop into your project, restart server)
// Includes: raw body capture for webhooks, Polar + Fungies handlers, Discord bot, DB helpers.
// Also serves checkout.html at /checkout and /checkout.html (Option A)

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const fetch = global.fetch || require('node-fetch'); // Node18+ has global fetch
const { Client, GatewayIntentBits, EmbedBuilder, REST, Routes, SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

const app = express();
const PORT = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ---------- Basic constants (copy or adapt PRODUCTS to your config) ----------
const PRODUCTS = {
  'regular-monthly': { name: 'Regular Monthly', duration: 30 },
  'regular-lifetime': { name: 'Regular Lifetime', duration: -1 },
  'master-monthly': { name: 'Master Monthly', duration: 30 },
  'master-lifetime': { name: 'Master Lifetime', duration: -1 },
  'nightly': { name: 'Nightly', duration: 7 }
};

// ---------- Middleware: Capture raw body for webhook HMAC ----------
app.use(express.json({
  verify: (req, res, buf) => {
    // store raw body buffer for HMAC verification
    req.rawBody = buf;
  }
}));
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Option A: serve checkout page at /checkout and /checkout.html ----------
app.get('/checkout', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'checkout.html'));
});
app.get('/checkout.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'checkout.html'));
});

// ---------- Discord client ----------
const discordClient = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers, GatewayIntentBits.DirectMessages, GatewayIntentBits.GuildMessages],
  partials: ['CHANNEL'] // to allow DMs
});

// ---------- Utility DB helpers (kept simple and synchronous-looking) ----------
async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS pending_purchases (
        session_id TEXT PRIMARY KEY,
        discord_id TEXT,
        discord_username TEXT,
        email TEXT,
        product TEXT,
        access_token TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT now()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS license_stock (
        license_key TEXT PRIMARY KEY,
        product_type TEXT,
        claimed BOOLEAN DEFAULT FALSE,
        claimed_by TEXT,
        claimed_at TIMESTAMP
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_licenses (
        id serial PRIMARY KEY,
        discord_id TEXT,
        discord_username TEXT,
        license_key TEXT,
        product_type TEXT,
        product_name TEXT,
        expires_at TIMESTAMP,
        is_lifetime BOOLEAN DEFAULT FALSE,
        assigned_at TIMESTAMP DEFAULT now()
      );
    `);
  } finally {
    client.release();
  }
}

async function savePendingPurchase(sessionId, data) {
  const client = await pool.connect();
  try {
    await client.query(
      `INSERT INTO pending_purchases (session_id, discord_id, discord_username, email, product, access_token)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (session_id) DO UPDATE SET
         discord_id = EXCLUDED.discord_id,
         discord_username = EXCLUDED.discord_username,
         email = EXCLUDED.email,
         product = EXCLUDED.product,
         access_token = EXCLUDED.access_token`,
      [sessionId, data.discordId, data.discordUsername, data.email, data.product, data.accessToken]
    );
  } finally {
    client.release();
  }
}

async function getPendingPurchase(sessionId) {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM pending_purchases WHERE session_id = $1', [sessionId]);
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function getPendingPurchaseByEmail(email) {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM pending_purchases WHERE email = $1 ORDER BY created_at DESC LIMIT 1', [email]);
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function getPendingPurchaseByDiscordId(discordId) {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM pending_purchases WHERE discord_id = $1 ORDER BY created_at DESC LIMIT 1', [discordId]);
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function getMostRecentPendingPurchase() {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM pending_purchases ORDER BY created_at DESC LIMIT 1');
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function markPurchaseCompleted(sessionId, licenseKey) {
  const client = await pool.connect();
  try {
    await client.query('UPDATE pending_purchases SET status = $1 WHERE session_id = $2', ['completed', sessionId]);
  } finally {
    client.release();
  }
}

// ---------- License stock helpers ----------
async function getAvailableKey(productType) {
  const client = await pool.connect();
  try {
    const result = await client.query(
      'SELECT license_key FROM license_stock WHERE product_type = $1 AND claimed = FALSE LIMIT 1',
      [productType]
    );
    return result.rows[0]?.license_key || null;
  } finally {
    client.release();
  }
}

async function claimKey(licenseKey, discordId) {
  const client = await pool.connect();
  try {
    await client.query(
      'UPDATE license_stock SET claimed = TRUE, claimed_by = $1, claimed_at = CURRENT_TIMESTAMP WHERE license_key = $2',
      [discordId, licenseKey]
    );
  } finally {
    client.release();
  }
}

async function assignLicenseToUser(discordId, discordUsername, licenseKey, productType) {
  const product = PRODUCTS[productType];
  const now = new Date();
  const expiresAt = product.duration === -1 ? null : new Date(now.getTime() + product.duration * 24 * 60 * 60 * 1000);

  const client = await pool.connect();
  try {
    await client.query(
      `INSERT INTO user_licenses (discord_id, discord_username, license_key, product_type, product_name, expires_at, is_lifetime)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [discordId, discordUsername, licenseKey, productType, product.name, expiresAt, product.duration === -1]
    );
  } finally {
    client.release();
  }
}

// ---------- Discord messaging / admin notifications ----------
async function sendLicenseDM(discordId, licenseKey, product) {
  try {
    const user = await discordClient.users.fetch(discordId);

    const embed = new EmbedBuilder()
      .setColor(0x00d4ff)
      .setTitle('🎉 SwimHub License Key')
      .setDescription('Thank you for your purchase!')
      .addFields(
        { name: '📦 Product', value: product.name, inline: true },
        { name: '⏰ Type', value: product.duration === -1 ? 'Lifetime' : `${product.duration} Days`, inline: true },
        { name: '\u200B', value: '\u200B' },
        { name: '🔑 Your License Key', value: `\`\`\`${licenseKey}\`\`\`` }
      )
      .setFooter({ text: 'SwimHub • Keep this key safe!' })
      .setTimestamp();

    await user.send({ embeds: [embed] });
    return true;
  } catch (error) {
    console.error('Failed to send DM to user:', error);
    return false;
  }
}

async function logPurchase(discordId, username, licenseKey, productType, dmSuccess) {
  try {
    const admin = await discordClient.users.fetch(process.env.ADMIN_USER_ID);
    const product = PRODUCTS[productType];

    const embed = new EmbedBuilder()
      .setColor(dmSuccess ? 0x10b981 : 0xf59e0b)
      .setTitle(dmSuccess ? '💰 New Purchase!' : '💰 New Purchase - ⚠️ MANUAL DELIVERY NEEDED')
      .setDescription(dmSuccess ? 'License delivered successfully!' : '**User has DMs closed. Please deliver the key manually.**')
      .addFields(
        { name: 'Product', value: product.name, inline: true },
        { name: 'User', value: `<@${discordId}>`, inline: true },
        { name: 'Username', value: username, inline: true },
        { name: 'User ID', value: `\`${discordId}\``, inline: true },
        { name: 'Delivery Status', value: dmSuccess ? '✅ Sent to DMs' : '❌ Failed - Manual delivery required', inline: true },
        { name: '🔑 License Key', value: `\`${licenseKey}\``, inline: false }
      )
      .setTimestamp();

    await admin.send({ embeds: [embed] });
  } catch (error) {
    console.error('Failed to log purchase:', error);
  }
}

async function notifyOutOfStock(productType, discordId) {
  try {
    const admin = await discordClient.users.fetch(process.env.ADMIN_USER_ID);
    const product = PRODUCTS[productType];

    const embed = new EmbedBuilder()
      .setColor(0xef4444)
      .setTitle('⚠️ OUT OF STOCK!')
      .setDescription(`Someone tried to purchase but we're out of keys!`)
      .addFields(
        { name: 'Product', value: product.name, inline: true },
        { name: 'User ID', value: discordId ? `<@${discordId}>` : 'Unknown', inline: true }
      )
      .setTimestamp();

    await admin.send({ embeds: [embed] });
  } catch (error) {
    console.error('Failed to notify out of stock:', error);
  }
}

async function notifyAdminSessionNotFound(customerEmail, sessionId, order) {
  try {
    const admin = await discordClient.users.fetch(process.env.ADMIN_USER_ID);

    const embed = new EmbedBuilder()
      .setColor(0xef4444)
      .setTitle('⚠️ Payment Received - Session Not Found!')
      .setDescription('A payment was received but the session could not be found. You may need to manually verify and deliver.')
      .addFields(
        { name: 'Customer Email', value: customerEmail || 'Not provided', inline: true },
        { name: 'Session ID Attempted', value: sessionId || 'None', inline: true },
        { name: 'Order Number', value: order?.number || order?.id || 'Unknown', inline: true }
      )
      .setTimestamp();

    await admin.send({ embeds: [embed] });
  } catch (error) {
    console.error('Failed to notify about session not found:', error);
  }
}

// ---------- Simple web routes (OAuth flow + session) ----------
function getWebsiteUrl() {
  return process.env.WEBSITE_URL || `http://localhost:${PORT}`;
}

app.get('/auth/discord', (req, res) => {
  const { product } = req.query;
  if (!product || !PRODUCTS[product]) {
    return res.status(400).json({ error: 'Invalid product' });
  }
  const state = Buffer.from(JSON.stringify({ product, timestamp: Date.now() })).toString('base64');
  const redirectUri = `${getWebsiteUrl()}/auth/discord/callback`;

  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'identify email guilds.join',
    state: state
  });

  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) {
    return res.redirect('/purchase?error=auth_failed');
  }
  try {
    const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
    const { product } = stateData;
    const redirectUri = `${getWebsiteUrl()}/auth/discord/callback`;

    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri
      })
    });

    const tokens = await tokenResponse.json();
    if (!tokens.access_token) throw new Error('Failed to get access token');

    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const user = await userResponse.json();

    // try to add to guild
    try {
      await fetch(`https://discord.com/api/guilds/${process.env.DISCORD_GUILD_ID}/members/${user.id}`, {
        method: 'PUT',
        headers: {
          Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ access_token: tokens.access_token })
      });
    } catch (e) {
      console.log('User may already be in server');
    }

    const sessionId = uuidv4();
    await savePendingPurchase(sessionId, {
      discordId: user.id,
      discordUsername: user.username,
      email: user.email,
      product: product,
      accessToken: tokens.access_token
    });

    // Redirect to checkout.html on your site (use getWebsiteUrl() if frontend is separate)
    res.redirect(`/checkout?session=${sessionId}&product=${product}&user=${encodeURIComponent(user.username)}`);
  } catch (error) {
    console.error('OAuth error:', error);
    res.redirect('/purchase?error=auth_failed');
  }
});

app.get('/api/session/:sessionId', async (req, res) => {
  const session = await getPendingPurchase(req.params.sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json({
    discordUsername: session.discord_username,
    product: session.product,
    productName: PRODUCTS[session.product]?.name
  });
});

app.get('/api/checkout-url/:sessionId', async (req, res) => {
  const session = await getPendingPurchase(req.params.sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });

  const productIds = {
    'regular-monthly': process.env.POLAR_PRODUCT_REGULAR_MONTHLY,
    'regular-lifetime': process.env.POLAR_PRODUCT_REGULAR_LIFETIME,
    'master-monthly': process.env.POLAR_PRODUCT_MASTER_MONTHLY,
    'master-lifetime': process.env.POLAR_PRODUCT_MASTER_LIFETIME,
    'nightly': process.env.POLAR_PRODUCT_NIGHTLY
  };

  const productId = productIds[session.product];
  if (process.env.POLAR_ACCESS_TOKEN && productId) {
    try {
      const response = await fetch('https://api.polar.sh/v1/checkouts', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.POLAR_ACCESS_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          products: [productId],
          metadata: { sessionId: req.params.sessionId, discordId: session.discord_id, discordUsername: session.discord_username },
          customer_email: session.email || undefined,
          success_url: `${process.env.WEBSITE_URL}/success.html?session=${req.params.sessionId}`
        })
      });
      if (response.ok) {
        const checkout = await response.json();
        console.log('Created Polar checkout session:', checkout.id);
        return res.json({ checkoutUrl: checkout.url, checkoutId: checkout.id, embedEnabled: true });
      } else {
        const errorData = await response.json();
        console.error('Polar API error:', errorData);
      }
    } catch (error) {
      console.error('Failed to create Polar checkout:', error);
    }
  }

  const checkoutUrls = {
    'regular-monthly': process.env.POLAR_URL_REGULAR_MONTHLY || process.env.FUNGIES_URL_REGULAR_MONTHLY,
    'regular-lifetime': process.env.POLAR_URL_REGULAR_LIFETIME || process.env.FUNGIES_URL_REGULAR_LIFETIME,
    'master-monthly': process.env.POLAR_URL_MASTER_MONTHLY || process.env.FUNGIES_URL_MASTER_MONTHLY,
    'master-lifetime': process.env.POLAR_URL_MASTER_LIFETIME || process.env.FUNGIES_URL_MASTER_LIFETIME,
    'nightly': process.env.POLAR_URL_NIGHTLY || process.env.FUNGIES_URL_NIGHTLY
  };

  const baseUrl = checkoutUrls[session.product];
  if (!baseUrl) return res.status(400).json({ error: 'Product not configured' });

  const metadata = { sessionId: req.params.sessionId, discordId: session.discord_id, discordUsername: session.discord_username };
  const checkoutUrl = `${baseUrl}?metadata=${encodeURIComponent(JSON.stringify(metadata))}`;

  res.json({ checkoutUrl, embedEnabled: true });
});

app.get('/api/payment-status/:sessionId', async (req, res) => {
  const session = await getPendingPurchase(req.params.sessionId);
  if (!session) return res.status(404).json({ status: 'not_found' });
  res.json({ status: session.status || 'pending', product: session.product, productName: PRODUCTS[session.product]?.name });
});

// ---------- Webhook processing (Polar) ----------
const processedWebhooks = new Set();

app.post('/webhook/polar', async (req, res) => {
  try {
    console.log('=== POLAR WEBHOOK RECEIVED ===');
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('Body (parsed):', JSON.stringify(req.body && typeof req.body === 'object' ? { type: req.body.type } : req.body));

    // --- Polar webhook signature verification ---
    // Header format (from Polar): "v1,<base64signature>"
    const signatureHeader =
      (req.headers['webhook-signature'] || req.headers['x-polar-signature'] || '');
    const webhookSecret = process.env.POLAR_WEBHOOK_SECRET || '';

    if (webhookSecret && signatureHeader) {
      // Extract the actual signature part (strip the "v1," prefix if present)
      const parts = signatureHeader.split(',');
      const signatureValue =
        parts.length > 1 ? parts[1].trim() : (parts[0] || '').trim();

      // Polar also sends a timestamp header; many providers sign: "<timestamp>.<raw-body>"
      const timestamp =
        req.headers['webhook-timestamp'] ||
        req.headers['x-polar-timestamp'] ||
        '';

      // Use exact raw body bytes (what Polar signed)
      const raw =
        (req.rawBody && req.rawBody.length)
          ? req.rawBody.toString('utf8')
          : JSON.stringify(req.body || {});

      const signedPayload = timestamp ? `${timestamp}.${raw}` : raw;

      const hmac = crypto.createHmac('sha256', webhookSecret);
      const expectedBase64 = hmac.update(signedPayload).digest('base64');

      console.log('Polar signature header:', signatureHeader);
      console.log('Extracted signature value:', signatureValue);
      console.log('Webhook timestamp:', timestamp);
      console.log('Computed expected (base64):', expectedBase64);

      if (signatureValue !== expectedBase64) {
        console.error('Invalid Polar webhook signature');
        console.error('Expected (base64):', expectedBase64);
        console.error('Received:', signatureValue);
        return res.status(401).json({ error: 'Invalid signature' });
      }
      console.log('✅ Polar signature verified');
    }

    const event = req.body;
    const eventId = event.id || event.event_id || `${Date.now()}-${Math.random()}`;

    if (processedWebhooks.has(eventId)) {
      console.log('⚠️ Duplicate webhook ignored:', eventId);
      return res.status(200).json({ received: true, duplicate: true });
    }
    processedWebhooks.add(eventId);
    if (processedWebhooks.size > 1000) {
      const idsArray = Array.from(processedWebhooks);
      for (let i = 0; i < 500; i++) processedWebhooks.delete(idsArray[i]);
    }

    console.log('Event type:', event.type);
    const successEvents = ['checkout.completed', 'order.created', 'order.paid', 'payment.success', 'payment_success'];

    if (successEvents.includes(event.type)) {
      const data = event.data || event;
      const customer = data.customer || data.user || {};
      const metadata = data.metadata || data.custom_data || data.customData || {};

      let parsedMetadata = metadata;
      if (typeof metadata === 'string') {
        try { parsedMetadata = JSON.parse(metadata); } catch (e) { parsedMetadata = {}; }
      }

      const customerEmail = customer.email || data.email;
      let session = null;

      if (parsedMetadata?.sessionId) {
        session = await getPendingPurchase(parsedMetadata.sessionId);
      }
      if (!session && parsedMetadata?.discordId) {
        session = await getPendingPurchaseByDiscordId(parsedMetadata.discordId);
      }
      if (!session && customerEmail) {
        session = await getPendingPurchaseByEmail(customerEmail);
      }
      if (!session) {
        session = await getMostRecentPendingPurchase();
      }

      if (!session) {
        console.error('No pending session found for customer:', customerEmail);
        await notifyAdminSessionNotFound(customerEmail, parsedMetadata?.sessionId || null, data);
        return res.status(200).json({ received: true, error: 'Session not found' });
      }

      console.log('Found session:', session);

      const licenseKey = await getAvailableKey(session.product);
      if (!licenseKey) {
        console.error('No keys in stock for:', session.product);
        await notifyOutOfStock(session.product, session.discord_id);
        return res.status(200).json({ received: true, error: 'Out of stock' });
      }

      await claimKey(licenseKey, session.discord_id);
      await assignLicenseToUser(session.discord_id, session.discord_username, licenseKey, session.product);
      await markPurchaseCompleted(session.session_id, licenseKey);

      const dmSuccess = await sendLicenseDM(session.discord_id, licenseKey, PRODUCTS[session.product]);
      await logPurchase(session.discord_id, session.discord_username, licenseKey, session.product, dmSuccess);

      console.log('✅ License delivered:', licenseKey, 'to', session.discord_username);
    }

    return res.status(200).json({ received: true });
  } catch (error) {
    console.error('Polar webhook error:', error);
    return res.status(200).json({ received: true, error: error.message });
  }
});

// ---------- Fungies webhook (kept for backward compatibility) ----------
app.post('/webhook/fungies', async (req, res) => {
  try {
    console.log('=== FUNGIES WEBHOOK RECEIVED ===');
    console.log('Headers:', JSON.stringify(req.headers, null, 2));

    const signature = req.headers['x-fngs-signature'];
    if (process.env.FUNGIES_WEBHOOK_SECRET && signature) {
      const hmac = crypto.createHmac('sha256', process.env.FUNGIES_WEBHOOK_SECRET);
      const expectedSignature = `sha256_${hmac.update(req.rawBody || Buffer.from(JSON.stringify(req.body))).digest('hex')}`;

      if (signature !== expectedSignature) {
        console.error('Invalid Fungies webhook signature');
        console.error('Expected:', expectedSignature);
        console.error('Received:', signature);
        return res.status(401).json({ error: 'Invalid signature' });
      }
      console.log('✅ Fungies signature verified');
    }

    const event = req.body;
    console.log('Event type:', event.type);

    if (event.type === 'payment_success') {
      const { items, order, customer } = event.data;
      const customerEmail = customer?.email;

      let session = null;
      let customData = null;
      if (order?.customData) customData = order.customData;
      else if (order?.custom_data) customData = order.custom_data;
      else if (event.data?.customData) customData = event.data.customData;
      else if (event.data?.custom_data) customData = event.data.custom_data;
      else if (items?.[0]?.customData) customData = items[0].customData;
      else if (items?.[0]?.custom_data) customData = items[0].custom_data;

      if (typeof customData === 'string') {
        try { customData = JSON.parse(customData); } catch (e) { customData = null; }
      }

      if (customData?.sessionId) session = await getPendingPurchase(customData.sessionId);
      if (!session && customData?.discordId) session = await getPendingPurchaseByDiscordId(customData.discordId);
      if (!session && customerEmail) session = await getPendingPurchaseByEmail(customerEmail);
      if (!session) session = await getMostRecentPendingPurchase();

      if (!session) {
        console.error('No pending session found for Fungies customer:', customerEmail);
        await notifyAdminSessionNotFound(customerEmail, customData?.sessionId || null, order);
        return res.status(200).json({ received: true, error: 'Session not found' });
      }

      const licenseKey = await getAvailableKey(session.product);
      if (!licenseKey) {
        console.error('No keys in stock for:', session.product);
        await notifyOutOfStock(session.product, session.discord_id);
        return res.status(200).json({ received: true, error: 'Out of stock' });
      }

      await claimKey(licenseKey, session.discord_id);
      await assignLicenseToUser(session.discord_id, session.discord_username, licenseKey, session.product);
      await markPurchaseCompleted(session.session_id, licenseKey);

      const dmSuccess = await sendLicenseDM(session.discord_id, licenseKey, PRODUCTS[session.product]);
      await logPurchase(session.discord_id, session.discord_username, licenseKey, session.product, dmSuccess);

      console.log('✅ Fungies: License delivered:', licenseKey, 'to', session.discord_username);
    }

    return res.status(200).json({ received: true });
  } catch (error) {
    console.error('Fungies webhook error:', error);
    return res.status(200).json({ received: true, error: error.message });
  }
});

// ---------- Slash commands / interaction handlers (register basic commands) ----------
const commands = [
  new SlashCommandBuilder().setName('license').setDescription('View your SwimHub licenses'),
  new SlashCommandBuilder().setName('addkey').setDescription('Add license key(s) to stock').setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
  new SlashCommandBuilder().setName('stock').setDescription('Check license key stock').setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
  new SlashCommandBuilder()
    .setName('givekey')
    .setDescription('Give a license key to a user')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .addUserOption(option => option.setName('user').setDescription('The user to give the key to').setRequired(true))
    .addStringOption(option => option.setName('product').setDescription('Product type').setRequired(true)
      .addChoices(
        { name: 'Regular Monthly', value: 'regular-monthly' },
        { name: 'Regular Lifetime', value: 'regular-lifetime' },
        { name: 'Master Monthly', value: 'master-monthly' },
        { name: 'Master Lifetime', value: 'master-lifetime' },
        { name: 'Nightly', value: 'nightly' }
      ))
].map(c => c.toJSON());

async function registerCommands() {
  const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_BOT_TOKEN);
  try {
    console.log('Registering slash commands.');
    await rest.put(Routes.applicationGuildCommands(process.env.DISCORD_CLIENT_ID, process.env.DISCORD_GUILD_ID), { body: commands });
    console.log('✅ Slash commands registered!');
  } catch (err) {
    console.error('Failed to register commands:', err);
  }
}

discordClient.on('interactionCreate', async (interaction) => {
  if (interaction.isCommand()) {
    const name = interaction.commandName;
    if (name === 'license') {
      await interaction.reply({ content: 'Not implemented in this snippet', ephemeral: true });
    } else if (name === 'givekey') {
      const user = interaction.options.getUser('user');
      const product = interaction.options.getString('product');
      const key = await getAvailableKey(product);
      if (!key) return interaction.reply({ content: `No keys for ${product}`, ephemeral: true });
      await claimKey(key, user.id);
      await assignLicenseToUser(user.id, user.username, key, product);
      await sendLicenseDM(user.id, key, PRODUCTS[product]);
      await interaction.reply({ content: `Gave ${PRODUCTS[product].name} to <@${user.id}>`, ephemeral: true });
    } else {
      await interaction.reply({ content: 'Unknown command', ephemeral: true });
    }
  }
});

// ---------- Start ----------
discordClient.once('ready', async () => {
  console.log(`✅ Bot logged in as ${discordClient.user.tag}`);
  await registerCommands();
});

async function start() {
  await initDatabase();
  app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
  await discordClient.login(process.env.DISCORD_BOT_TOKEN);
}
start().catch(console.error);

// Periodic cleanup
setInterval(async () => {
  const client = await pool.connect();
  try {
    await client.query("DELETE FROM pending_purchases WHERE created_at < NOW() - INTERVAL '1 hour'");
  } finally {
    client.release();
  }
}, 60 * 60 * 1000);
