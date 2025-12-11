// ==================== SWIMHUB LICENSE MANAGEMENT SYSTEM ====================
// Complete integrated system:  Database + Discord Bot + Express Server
// Features: Manual license key addition, automatic assignment, admin notifications

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const fetch = global.fetch || require('node-fetch');
const { 
  Client, 
  GatewayIntentBits, 
  EmbedBuilder, 
  REST, 
  Routes, 
  SlashCommandBuilder, 
  PermissionFlagsBits,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle
} = require('discord.js');

const app = express();
const PORT = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ---------- CONSTANTS ----------
const PRODUCTS = {
  'regular-monthly': { name: 'Regular Monthly', duration: 30 },
  'regular-lifetime': { name: 'Regular Lifetime', duration: -1 },
  'master-monthly': { name: 'Master Monthly', duration: 30 },
  'master-lifetime': { name: 'Master Lifetime', duration: -1 },
  'nightly':  { name: 'Nightly', duration: 7 }
};

const processedWebhooks = new Set();

// ---------- DISCORD CLIENT ----------
const discordClient = new Client({
  intents: [
    GatewayIntentBits. Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: ['CHANNEL', 'MESSAGE']
});

// ---------- MIDDLEWARE ----------
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- DATABASE INITIALIZATION ----------
async function initDatabase() {
  const client = await pool.connect();
  try {
    // Pending purchases table
    await client.query(`
      CREATE TABLE IF NOT EXISTS pending_purchases (
        session_id TEXT PRIMARY KEY,
        discord_id TEXT,
        discord_username TEXT,
        email TEXT,
        product TEXT,
        access_token TEXT,
        status TEXT DEFAULT 'pending',
        license_key TEXT,
        created_at TIMESTAMP DEFAULT now(),
        updated_at TIMESTAMP DEFAULT now()
      );
    `);

    // License stock table
    await client.query(`
      CREATE TABLE IF NOT EXISTS license_stock (
        id SERIAL PRIMARY KEY,
        license_key TEXT UNIQUE NOT NULL,
        product_type TEXT,
        status TEXT DEFAULT 'available',
        claimed BOOLEAN DEFAULT FALSE,
        claimed_by TEXT,
        claimed_at TIMESTAMP,
        customer_email TEXT,
        customer_discord_id TEXT,
        created_at TIMESTAMP DEFAULT now(),
        updated_at TIMESTAMP DEFAULT now()
      );
    `);

    // User licenses table
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_licenses (
        id SERIAL PRIMARY KEY,
        discord_id TEXT,
        discord_username TEXT,
        license_key TEXT UNIQUE,
        product_type TEXT,
        product_name TEXT,
        expires_at TIMESTAMP,
        is_lifetime BOOLEAN DEFAULT FALSE,
        assigned_at TIMESTAMP DEFAULT now()
      );
    `);

    // Purchase log table
    await client.query(`
      CREATE TABLE IF NOT EXISTS purchase_log (
        id SERIAL PRIMARY KEY,
        license_key TEXT,
        customer_email TEXT,
        customer_discord_id TEXT,
        customer_username TEXT,
        product_type TEXT,
        amount DECIMAL(10, 2),
        payment_method TEXT,
        transaction_id TEXT,
        purchase_date TIMESTAMP DEFAULT now()
      );
    `);

    console.log('✅ Database tables initialized');
  } finally {
    client.release();
  }
}

// ---------- DATABASE HELPERS ----------

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
         product = EXCLUDED. product,
         access_token = EXCLUDED.access_token,
         updated_at = now()`,
      [sessionId, data. discordId, data.discordUsername, data.email, data.product, data.accessToken]
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
    const result = await client.query(
      'SELECT * FROM pending_purchases WHERE email = $1 AND status = $2 ORDER BY created_at DESC LIMIT 1',
      [email, 'pending']
    );
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function getPendingPurchaseByDiscordId(discordId) {
  const client = await pool. connect();
  try {
    const result = await client.query(
      'SELECT * FROM pending_purchases WHERE discord_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT 1',
      [discordId, 'pending']
    );
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function getMostRecentPendingPurchase() {
  const client = await pool.connect();
  try {
    const result = await client.query(
      'SELECT * FROM pending_purchases WHERE status = $1 ORDER BY created_at DESC LIMIT 1',
      ['pending']
    );
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function markPurchaseCompleted(sessionId, licenseKey) {
  const client = await pool.connect();
  try {
    await client.query(
      'UPDATE pending_purchases SET status = $1, license_key = $2, updated_at = now() WHERE session_id = $3',
      ['completed', licenseKey, sessionId]
    );
  } finally {
    client.release();
  }
}

async function getAvailableLicenseKey(productType) {
  const client = await pool.connect();
  try {
    const result = await client.query(
      `SELECT * FROM license_stock 
       WHERE product_type = $1 AND status = $2 AND claimed = FALSE 
       ORDER BY created_at ASC LIMIT 1`,
      [productType, 'available']
    );
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function claimLicenseKey(licenseKeyId, discordId, customerEmail = null) {
  const client = await pool.connect();
  try {
    await client.query(
      `UPDATE license_stock 
       SET claimed = TRUE, claimed_by = $1, claimed_at = now(), 
           customer_discord_id = $1, customer_email = $2, status = $3, updated_at = now()
       WHERE id = $4`,
      [discordId, customerEmail, 'assigned', licenseKeyId]
    );
  } finally {
    client.release();
  }
}

async function assignLicenseToUser(discordId, discordUsername, licenseKey, productType) {
  const product = PRODUCTS[productType];
  const now = new Date();
  const expiresAt = product.duration === -1 
    ? null 
    : new Date(now.getTime() + product.duration * 24 * 60 * 60 * 1000);

  const client = await pool.connect();
  try {
    await client.query(
      `INSERT INTO user_licenses (discord_id, discord_username, license_key, product_type, product_name, expires_at, is_lifetime)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (license_key) DO NOTHING`,
      [discordId, discordUsername, licenseKey, productType, product.name, expiresAt, product.duration === -1]
    );
  } finally {
    client.release();
  }
}

async function logPurchase(licenseKey, customerEmail, discordId, discordUsername, productType) {
  const client = await pool.connect();
  try {
    await client.query(
      `INSERT INTO purchase_log (license_key, customer_email, customer_discord_id, customer_username, product_type, payment_method)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [licenseKey, customerEmail, discordId, discordUsername, productType, 'polar']
    );
  } finally {
    client.release();
  }
}

async function addLicenseKeyToStock(licenseKey, productType = 'swimhub') {
  const client = await pool.connect();
  try {
    const result = await client.query(
      `INSERT INTO license_stock (license_key, product_type, status, created_at, updated_at)
       VALUES ($1, $2, $3, now(), now())
       ON CONFLICT (license_key) DO NOTHING
       RETURNING *`,
      [licenseKey, productType, 'available']
    );
    return result. rows[0] || null;
  } finally {
    client.release();
  }
}

async function getStockCount() {
  const client = await pool.connect();
  try {
    const result = await client.query(
      'SELECT COUNT(*) as count FROM license_stock WHERE status = $1 AND claimed = FALSE',
      ['available']
    );
    return parseInt(result.rows[0].count) || 0;
  } finally {
    client.release();
  }
}

async function getLicenseStats() {
  const client = await pool.connect();
  try {
    const result = await client. query(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN status = 'available' AND claimed = FALSE THEN 1 ELSE 0 END) as available,
        SUM(CASE WHEN status = 'assigned' OR claimed = TRUE THEN 1 ELSE 0 END) as used
      FROM license_stock
    `);
    return result.rows[0] || { total: 0, available: 0, used: 0 };
  } finally {
    client.release();
  }
}

// ---------- WEBHOOK HANDLERS ----------

async function sendLicenseDM(discordId, licenseKey, product) {
  if (!discordClient || !discordId) return false;
  
  try {
    const user = await discordClient.users. fetch(discordId);
    const embed = new EmbedBuilder()
      .setColor('#10b981')
      .setTitle('🎉 Your License Key is Ready!')
      .setDescription('Thank you for your purchase!')
      .addFields(
        { name: 'Product', value: product.name, inline: true },
        { name:  'Duration', value: product.duration === -1 ? 'Lifetime' : `${product.duration} days`, inline: true },
        { name: 'License Key', value: `\`${licenseKey}\``, inline: false },
        { name: 'How to Activate', value: 'Use the license key in our Discord server or website', inline: false }
      )
      .setFooter({ text: 'SwimHub License System' })
      .setTimestamp();

    await user.send({ embeds: [embed] });
    return true;
  } catch (error) {
    console.error('Failed to send license DM:', error. message);
    return false;
  }
}

async function sendAdminNotification(customerInfo, licenseKey, product) {
  if (!discordClient || !process.env.ADMIN_DISCORD_ID) return;

  try {
    const admin = await discordClient.users. fetch(process.env.ADMIN_DISCORD_ID);
    const purchaseEmbed = new EmbedBuilder()
      .setColor('#667eea')
      .setTitle('📦 New Purchase Notification')
      .setDescription('A new customer has completed a purchase')
      .addFields(
        { name: 'Customer', value: customerInfo.discord_username || 'Unknown', inline: true },
        { name: 'Discord ID', value: customerInfo.discord_id || 'N/A', inline: true },
        { name: 'Email', value: customerInfo.email || 'N/A', inline:  false },
        { name: 'Product', value: product.name, inline: true },
        { name: 'Duration', value: product.duration === -1 ? 'Lifetime' : `${product.duration} days`, inline: true },
        { name: 'License Key', value: `\`${licenseKey}\``, inline: false },
        { name: 'Remaining Stock', value: `${await getStockCount()} keys available`, inline: false }
      )
      .setFooter({ text: 'SwimHub Admin Dashboard' })
      .setTimestamp();

    await admin.send({ embeds: [purchaseEmbed] });
    console.log('✅ Admin notification sent');
  } catch (error) {
    console.error('Failed to send admin notification:', error.message);
  }
}

async function processCheckoutPayload(payload) {
  const data = payload.data || payload;
  const customer = data.customer || data.user || {};
  let metadata = data.metadata || data. custom_data || data.customData || {};

  if (typeof metadata === 'string') {
    try { metadata = JSON.parse(metadata); } catch (e) { metadata = {}; }
  }

  const customerEmail = customer.email || data.email;
  let session = null;

  if (metadata?. sessionId) {
    session = await getPendingPurchase(metadata. sessionId);
  }
  if (! session && metadata?.discordId) {
    session = await getPendingPurchaseByDiscordId(metadata. discordId);
  }
  if (!session && customerEmail) {
    session = await getPendingPurchaseByEmail(customerEmail);
  }
  if (!session) {
    session = await getMostRecentPendingPurchase();
  }

  if (! session) {
    console.error('❌ No pending session found for customer:', customerEmail);
    return { success:  false, reason: 'no_pending_session' };
  }

  // Get available license key
  const availableKey = await getAvailableLicenseKey(session.product);
  if (!availableKey) {
    console.error('❌ No available license keys in stock for:', session.product);
    return { success: false, reason: 'no_available_keys' };
  }

  const licenseKey = availableKey. license_key;

  // Claim the license
  await claimLicenseKey(availableKey.id, session.discord_id, session.email);
  
  // Assign to user
  await assignLicenseToUser(session.discord_id, session.discord_username, licenseKey, session.product);
  
  // Mark purchase as completed
  await markPurchaseCompleted(session.session_id, licenseKey);
  
  // Log the purchase
  await logPurchase(licenseKey, session. email, session.discord_id, session.discord_username, session. product);

  // Send license to user
  const dmSuccess = await sendLicenseDM(session.discord_id, licenseKey, PRODUCTS[session.product]);
  
  // Send admin notification
  await sendAdminNotification(session, licenseKey, PRODUCTS[session.product]);

  console.log('✅ License delivered:', licenseKey, 'to', session.discord_username);
  return { success:  true, licenseKey, dmSuccess };
}

// ---------- ROUTES ----------

app.get('/checkout', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'checkout.html'));
});

app.get('/checkout. html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'checkout.html'));
});

// Polar webhook
app.post('/webhook/polar', async (req, res) => {
  try {
    console.log('=== POLAR WEBHOOK RECEIVED ===');
    
    const signatureHeader = req.headers['webhook-signature'] || '';
    const webhookSecret = (process.env.POLAR_WEBHOOK_SECRET || '').trim();
    const skipSig = process.env.POLAR_SKIP_SIGNATURE === 'true';

    let signatureValid = skipSig;

    if (!signatureValid && webhookSecret && signatureHeader) {
      const parts = signatureHeader.split(',');
      const signatureValue = parts. length > 1 ? parts[1].trim() : parts[0].trim();
      const timestamp = req.headers['webhook-timestamp'] || '';
      const raw = req.rawBody ?  req.rawBody. toString('utf8') : JSON.stringify(req.body);

      const candidates = [
        { label: 'timestamp + raw', payload: `${timestamp}. ${raw}` },
        { label: 'raw', payload: raw }
      ];

      for (const c of candidates) {
        const h = crypto.createHmac('sha256', webhookSecret).update(c.payload).digest('base64');
        if (h === signatureValue) {
          signatureValid = true;
          break;
        }
      }
    }

    if (!signatureValid) {
      console.error('Invalid Polar webhook signature');
      return res.status(401).json({ error: 'Invalid signature' });
    }

    const event = req.body;
    const eventId = event.id || `${Date.now()}-${Math.random()}`;

    if (processedWebhooks.has(eventId)) {
      console.log('⚠️ Duplicate webhook ignored');
      return res.status(200).json({ received: true, duplicate: true });
    }

    processedWebhooks.add(eventId);

    const successEvents = ['checkout. completed', 'order.created', 'checkout.updated', 'payment.success'];

    if (successEvents.includes(event.type)) {
      const result = await processCheckoutPayload(event);
      if (! result.success) {
        return res.status(200).json({ received: true, error: result.reason });
      }
    }

    return res.status(200).json({ received: true });
  } catch (error) {
    console.error('Polar webhook error:', error);
    return res.status(200).json({ received: true, error: error.message });
  }
});

// License API endpoints
app.post('/api/licenses/add', async (req, res) => {
  const { keys, token } = req.body;

  if (!token || token !== process.env. INTERNAL_PROCESS_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (!Array.isArray(keys) || keys.length === 0) {
    return res.status(400).json({ error: 'Keys must be a non-empty array' });
  }

  try {
    for (const key of keys) {
      await addLicenseKeyToStock(key. trim().toUpperCase(), 'swimhub');
    }

    const stock = await getStockCount();
    console.log(`✅ Added ${keys.length} license keys.  Total available: ${stock}`);
    
    res.json({
      success: true,
      count: keys.length,
      stock
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/licenses/stock', async (req, res) => {
  try {
    const stats = await getLicenseStats();
    res.json({ success: true, ... stats });
  } catch (error) {
    res.status(500).json({ error: error. message });
  }
});

// Slash commands
const commands = [
  new SlashCommandBuilder()
    .setName('addlicense')
    .setDescription('Add license keys to stock')
    .addStringOption(opt => opt
      .setName('keys')
      .setDescription('Comma-separated license keys')
      .setRequired(true)
    )
    .setDefaultMemberPermissions(PermissionFlagsBits. Administrator),

  new SlashCommandBuilder()
    .setName('stock')
    .setDescription('Check license stock status')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),

  new SlashCommandBuilder()
    .setName('license')
    .setDescription('View your license information')
].map(c => c.toJSON());

async function registerCommands() {
  const rest = new REST({ version: '10' }).setToken(process.env. DISCORD_BOT_TOKEN);
  try {
    console.log('Registering slash commands...');
    await rest.put(
      Routes.applicationGuildCommands(process.env. DISCORD_CLIENT_ID, process.env. DISCORD_GUILD_ID),
      { body: commands }
    );
    console.log('✅ Commands registered');
  } catch (error) {
    console.error('Failed to register commands:', error);
  }
}

// Command handlers
discordClient.on('interactionCreate', async (interaction) => {
  if (! interaction.isCommand()) return;

  try {
    if (interaction.commandName === 'addlicense') {
      const isAdmin = interaction.member?. permissions.has(PermissionFlagsBits.Administrator);
      if (!isAdmin) {
        return interaction.reply({ content: '❌ Admin only', ephemeral: true });
      }

      const keysInput = interaction.options.getString('keys');
      const keys = keysInput.split(',').map(k => k.trim()).filter(k => k);

      if (keys.length === 0) {
        return interaction. reply({ content: '❌ No valid keys provided', ephemeral: true });
      }

      await interaction. deferReply({ ephemeral:  true });

      for (const key of keys) {
        await addLicenseKeyToStock(key. toUpperCase(), 'swimhub');
      }

      const stock = await getStockCount();

      const embed = new EmbedBuilder()
        .setColor('#10b981')
        .setTitle('✅ Keys Added')
        .addFields(
          { name: 'Keys Added', value: keys.length. toString(), inline: true },
          { name: 'Total Stock', value: stock. toString(), inline: true }
        );

      await interaction.editReply({ embeds: [embed] });
    } 
    else if (interaction.commandName === 'stock') {
      const isAdmin = interaction.member?.permissions.has(PermissionFlagsBits.Administrator);
      if (!isAdmin) {
        return interaction.reply({ content: '❌ Admin only', ephemeral: true });
      }

      const stats = await getLicenseStats();

      const embed = new EmbedBuilder()
        .setColor('#667eea')
        .setTitle('📊 License Stock')
        .addFields(
          { name: 'Available', value: stats.available?. toString() || '0', inline: true },
          { name: 'Assigned', value: stats. used?.toString() || '0', inline: true },
          { name:  'Total', value: stats. total?.toString() || '0', inline: true }
        );

      interaction.reply({ embeds: [embed], ephemeral: true });
    }
    else if (interaction. commandName === 'license') {
      await interaction.reply({
        content: 'Check your Discord DMs for your license key information',
        ephemeral: true
      });
    }
  } catch (error) {
    console.error('Command error:', error);
    if (! interaction.replied) {
      interaction.reply({ content: '❌ Command failed', ephemeral: true });
    }
  }
});

discordClient.once('ready', async () => {
  console.log(`✅ Bot logged in as ${discordClient.user. tag}`);
  await registerCommands();
});

// Start server
async function start() {
  try {
    await initDatabase();
    
    app.listen(PORT, () => {
      console. log(`✅ Server running on port ${PORT}`);
    });

    await discordClient.login(process. env.DISCORD_BOT_TOKEN);
  } catch (error) {
    console.error('Startup error:', error);
    process.exit(1);
  }
}

start();

// Cleanup
process.on('SIGINT', () => {
  console.log('Shutting down.. .');
  discordClient.destroy();
  pool.end();
  process.exit(0);
});
