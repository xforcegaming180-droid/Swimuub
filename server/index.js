// SwimHub License Bot - Railway Deployment
// Uses PostgreSQL for persistent storage, manual key management

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { 
    Client, 
    GatewayIntentBits, 
    EmbedBuilder, 
    REST, 
    Routes, 
    SlashCommandBuilder,
    ModalBuilder,
    TextInputBuilder,
    TextInputStyle,
    ActionRowBuilder,
    StringSelectMenuBuilder,
    PermissionFlagsBits
} = require('discord.js');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ===========================================
// POSTGRESQL DATABASE (Railway)
// ===========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initDatabase() {
    const client = await pool.connect();
    try {
        // License keys stock (keys you add manually)
        await client.query(`
            CREATE TABLE IF NOT EXISTS license_stock (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(255) UNIQUE NOT NULL,
                product_type VARCHAR(50) NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                added_by VARCHAR(50),
                claimed BOOLEAN DEFAULT FALSE,
                claimed_by VARCHAR(50),
                claimed_at TIMESTAMP
            )
        `);
        
        // User licenses (assigned to users - tracking only, whitelist managed externally)
        await client.query(`
            CREATE TABLE IF NOT EXISTS user_licenses (
                id SERIAL PRIMARY KEY,
                discord_id VARCHAR(50) NOT NULL,
                discord_username VARCHAR(100),
                license_key VARCHAR(255) NOT NULL,
                product_type VARCHAR(50) NOT NULL,
                product_name VARCHAR(100),
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_lifetime BOOLEAN DEFAULT FALSE
            )
        `);
        
        // Pending purchases (OAuth sessions)
        await client.query(`
            CREATE TABLE IF NOT EXISTS pending_purchases (
                session_id VARCHAR(100) PRIMARY KEY,
                discord_id VARCHAR(50) NOT NULL,
                discord_username VARCHAR(100),
                email VARCHAR(255),
                product VARCHAR(50) NOT NULL,
                access_token TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        console.log('✅ Database tables initialized');
    } catch (error) {
        console.error('Database init error:', error);
    } finally {
        client.release();
    }
}

// ===========================================
// MIDDLEWARE
// ===========================================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===========================================
// DISCORD BOT SETUP
// ===========================================
const discordClient = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.DirectMessages
    ]
});

// Product configurations (no roles - using external redemption bot)
const PRODUCTS = {
    'regular-monthly': {
        name: 'SwimHub Regular (Monthly)',
        duration: 30,
        tier: 'regular'
    },
    'regular-lifetime': {
        name: 'SwimHub Regular (Lifetime)',
        duration: -1,
        tier: 'regular'
    },
    'master-monthly': {
        name: 'SwimHub Master (Monthly)',
        duration: 30,
        tier: 'master'
    },
    'master-lifetime': {
        name: 'SwimHub Master (Lifetime)',
        duration: -1,
        tier: 'master'
    },
    'nightly': {
        name: 'SwimHub Nightly',
        duration: -1,
        tier: 'nightly'
    }
};

// ===========================================
// DATABASE HELPER FUNCTIONS
// ===========================================

// Add multiple license keys
async function addMultipleLicenses(keys, productType, addedBy) {
    const client = await pool.connect();
    let added = 0;
    let duplicates = 0;
    
    try {
        for (const key of keys) {
            try {
                await client.query(
                    'INSERT INTO license_stock (license_key, product_type, added_by) VALUES ($1, $2, $3)',
                    [key.trim(), productType, addedBy]
                );
                added++;
            } catch (error) {
                if (error.code === '23505') duplicates++;
                else throw error;
            }
        }
        return { added, duplicates };
    } finally {
        client.release();
    }
}

// Get stock counts
async function getStockCounts() {
    const client = await pool.connect();
    try {
        const result = await client.query(`
            SELECT product_type, 
                   COUNT(*) FILTER (WHERE claimed = FALSE) as available,
                   COUNT(*) FILTER (WHERE claimed = TRUE) as claimed,
                   COUNT(*) as total
            FROM license_stock 
            GROUP BY product_type
        `);
        return result.rows;
    } finally {
        client.release();
    }
}

// Get available key from stock
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

// Claim a key from stock
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

// Assign license to user
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

// Get user's licenses
async function getUserLicenses(discordId) {
    const client = await pool.connect();
    try {
        const result = await client.query(
            'SELECT * FROM user_licenses WHERE discord_id = $1 ORDER BY assigned_at DESC',
            [discordId]
        );
        return result.rows;
    } finally {
        client.release();
    }
}

// Save pending purchase session
async function savePendingPurchase(sessionId, data) {
    const client = await pool.connect();
    try {
        await client.query(
            `INSERT INTO pending_purchases (session_id, discord_id, discord_username, email, product, access_token)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (session_id) DO UPDATE SET
             discord_id = $2, discord_username = $3, email = $4, product = $5, access_token = $6`,
            [sessionId, data.discordId, data.discordUsername, data.email, data.product, data.accessToken]
        );
    } finally {
        client.release();
    }
}

// Get pending purchase
async function getPendingPurchase(sessionId) {
    const client = await pool.connect();
    try {
        const result = await client.query(
            'SELECT * FROM pending_purchases WHERE session_id = $1',
            [sessionId]
        );
        return result.rows[0] || null;
    } finally {
        client.release();
    }
}

// Get pending purchase by email (fallback lookup)
async function getPendingPurchaseByEmail(email) {
    const client = await pool.connect();
    try {
        // Get most recent pending purchase for this email
        const result = await client.query(
            'SELECT * FROM pending_purchases WHERE email = $1 ORDER BY created_at DESC LIMIT 1',
            [email]
        );
        return result.rows[0] || null;
    } finally {
        client.release();
    }
}

// Delete pending purchase
async function deletePendingPurchase(sessionId) {
    const client = await pool.connect();
    try {
        await client.query('DELETE FROM pending_purchases WHERE session_id = $1', [sessionId]);
    } finally {
        client.release();
    }
}

// ===========================================
// DISCORD OAUTH2 ROUTES
// ===========================================

// Helper to ensure URL has https://
function getWebsiteUrl() {
    let url = process.env.WEBSITE_URL || '';
    if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }
    return url;
}

app.get('/auth/discord', (req, res) => {
    const { product } = req.query;
    
    if (!product || !PRODUCTS[product]) {
        return res.status(400).json({ error: 'Invalid product' });
    }
    
    const state = Buffer.from(JSON.stringify({ product, timestamp: Date.now() })).toString('base64');
    
    const params = new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        redirect_uri: `${getWebsiteUrl()}/auth/discord/callback`,
        response_type: 'code',
        scope: 'identify email guilds.join',
        state: state
    });
    
    res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

app.get('/auth/discord/callback', async (req, res) => {
    const { code, state } = req.query;
    
    if (!code) {
        return res.redirect('/purchase.html?error=auth_failed');
    }
    
    try {
        const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
        const { product } = stateData;
        
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: process.env.DISCORD_CLIENT_ID,
                client_secret: process.env.DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: `${getWebsiteUrl()}/auth/discord/callback`
            })
        });
        
        const tokens = await tokenResponse.json();
        
        if (!tokens.access_token) {
            throw new Error('Failed to get access token');
        }
        
        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokens.access_token}` }
        });
        
        const user = await userResponse.json();
        
        // Join user to server
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
        
        res.redirect(`/checkout.html?session=${sessionId}&product=${product}&user=${encodeURIComponent(user.username)}`);
        
    } catch (error) {
        console.error('OAuth error:', error);
        res.redirect('/purchase.html?error=auth_failed');
    }
});

app.get('/api/session/:sessionId', async (req, res) => {
    const session = await getPendingPurchase(req.params.sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    res.json({
        discordUsername: session.discord_username,
        product: session.product,
        productName: PRODUCTS[session.product]?.name
    });
});

app.get('/api/checkout-url/:sessionId', async (req, res) => {
    const session = await getPendingPurchase(req.params.sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    // Fungies offer IDs - configure in Railway env vars
    // These are the product/offer UUIDs from your Fungies dashboard
    const offerIds = {
        'regular-monthly': process.env.FUNGIES_OFFER_REGULAR_MONTHLY,
        'regular-lifetime': process.env.FUNGIES_OFFER_REGULAR_LIFETIME,
        'master-monthly': process.env.FUNGIES_OFFER_MASTER_MONTHLY,
        'master-lifetime': process.env.FUNGIES_OFFER_MASTER_LIFETIME,
        'nightly': process.env.FUNGIES_OFFER_NIGHTLY
    };
    
    // Fallback checkout URLs (static links) if API keys not configured
    const checkoutUrls = {
        'regular-monthly': process.env.FUNGIES_URL_REGULAR_MONTHLY,
        'regular-lifetime': process.env.FUNGIES_URL_REGULAR_LIFETIME,
        'master-monthly': process.env.FUNGIES_URL_MASTER_MONTHLY,
        'master-lifetime': process.env.FUNGIES_URL_MASTER_LIFETIME,
        'nightly': process.env.FUNGIES_URL_NIGHTLY
    };
    
    const offerId = offerIds[session.product];
    const baseUrl = checkoutUrls[session.product];
    
    // Try to create dynamic checkout with session ID via Fungies API
    if (offerId && process.env.FUNGIES_PUBLIC_KEY && process.env.FUNGIES_SECRET_KEY) {
        try {
            console.log('Creating Fungies checkout element for session:', req.params.sessionId);
            
            const fungiesResponse = await fetch('https://api.fungies.io/v0/elements/checkout/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-fngs-public-key': process.env.FUNGIES_PUBLIC_KEY,
                    'x-fngs-secret-key': process.env.FUNGIES_SECRET_KEY
                },
                body: JSON.stringify({
                    offersIds: [offerId],
                    name: `checkout-${req.params.sessionId}`,
                    customFields: [
                        {
                            id: 'sessionId',
                            value: req.params.sessionId
                        },
                        {
                            id: 'discordId', 
                            value: session.discord_id
                        }
                    ]
                })
            });
            
            const fungiesData = await fungiesResponse.json();
            console.log('Fungies API response:', JSON.stringify(fungiesData, null, 2));
            
            if (fungiesData.status === 'success' && fungiesData.data?.checkoutElement?.id) {
                const checkoutElementId = fungiesData.data.checkoutElement.id;
                const checkoutUrl = `https://app.fungies.io/checkout/${checkoutElementId}`;
                console.log('Created checkout URL:', checkoutUrl);
                return res.json({ checkoutUrl });
            }
        } catch (error) {
            console.error('Failed to create Fungies checkout element:', error);
            // Fall through to static URL fallback
        }
    }
    
    // Fallback: use static checkout URL with query params
    if (!baseUrl) {
        return res.status(400).json({ error: 'Product not configured' });
    }
    
    // Try passing session ID in various URL params that Fungies might support
    const successUrl = `${getWebsiteUrl()}/success.html`;
    const checkoutUrl = `${baseUrl}?client_reference_id=${req.params.sessionId}&prefilled_email=${encodeURIComponent(session.email || '')}&success_url=${encodeURIComponent(successUrl)}`;
    
    console.log('Using fallback checkout URL:', checkoutUrl);
    res.json({ checkoutUrl });
});

// ===========================================
// FUNGIES WEBHOOK
// ===========================================
app.post('/webhook/fungies', async (req, res) => {
    try {
        console.log('=== WEBHOOK RECEIVED ===');
        console.log('Headers:', JSON.stringify(req.headers, null, 2));
        console.log('Body:', JSON.stringify(req.body, null, 2));
        
        // Verify webhook signature (Fungies uses x-fngs-signature header)
        const signature = req.headers['x-fngs-signature'];
        if (process.env.FUNGIES_WEBHOOK_SECRET && signature) {
            const hmac = crypto.createHmac('sha256', process.env.FUNGIES_WEBHOOK_SECRET);
            const expectedSignature = `sha256_${hmac.update(JSON.stringify(req.body)).digest('hex')}`;
            
            if (signature !== expectedSignature) {
                console.error('Invalid webhook signature');
                console.error('Expected:', expectedSignature);
                console.error('Received:', signature);
                return res.status(401).json({ error: 'Invalid signature' });
            }
            console.log('✅ Signature verified');
        }
        
        const event = req.body;
        console.log('Event type:', event.type);
        
        // Fungies uses 'payment_success' event type
        if (event.type === 'payment_success') {
            const { items, order, customer, checkoutElement } = event.data;
            
            console.log('Customer:', customer);
            console.log('Order:', order);
            console.log('Items:', items);
            console.log('Checkout Element:', checkoutElement);
            
            // Get customer email to find pending session
            const customerEmail = customer?.email;
            
            // Try to find session by custom fields from various locations
            let session = null;
            let sessionId = null;
            
            // Method 1: Check checkout element custom fields (from API-created checkouts)
            if (checkoutElement?.customFields) {
                console.log('Checkout element custom fields:', checkoutElement.customFields);
                const sessionField = checkoutElement.customFields.find(f => f.id === 'sessionId');
                if (sessionField?.value) {
                    sessionId = sessionField.value;
                    console.log('Found session ID in checkout element:', sessionId);
                }
            }
            
            // Method 2: Check items custom fields
            if (!sessionId && items && items.length > 0) {
                for (const item of items) {
                    console.log('Item custom fields:', item.customFields);
                    // Custom fields might be an object or array
                    if (item.customFields?.sessionId) {
                        sessionId = item.customFields.sessionId;
                        console.log('Found session ID in item (object):', sessionId);
                        break;
                    }
                    if (Array.isArray(item.customFields)) {
                        const sessionField = item.customFields.find(f => f.id === 'sessionId');
                        if (sessionField?.value) {
                            sessionId = sessionField.value;
                            console.log('Found session ID in item (array):', sessionId);
                            break;
                        }
                    }
                }
            }
            
            // Method 3: Check order metadata
            if (!sessionId && order?.metadata?.sessionId) {
                sessionId = order.metadata.sessionId;
                console.log('Found session ID in order metadata:', sessionId);
            }
            
            // Method 4: Check client_reference_id (if passed via URL)
            if (!sessionId && order?.clientReferenceId) {
                sessionId = order.clientReferenceId;
                console.log('Found session ID in client reference:', sessionId);
            }
            
            // Get session by ID
            if (sessionId) {
                session = await getPendingPurchase(sessionId);
                console.log('Session lookup by ID result:', session ? 'Found' : 'Not found');
            }
            
            // Fallback: find by email (last resort)
            if (!session && customerEmail) {
                console.log('Falling back to email lookup:', customerEmail);
                session = await getPendingPurchaseByEmail(customerEmail);
            }
            
            if (!session) {
                console.error('Session not found for customer:', customerEmail, 'sessionId:', sessionId);
                // Notify admin about failed session lookup
                await notifyAdminSessionNotFound(customerEmail, sessionId, order);
                // Still return 200 to acknowledge receipt
                return res.status(200).json({ received: true, error: 'Session not found' });
            }
            
            console.log('Found session:', session);
            
            // Get a key from stock
            const licenseKey = await getAvailableKey(session.product);
            
            if (!licenseKey) {
                console.error('No keys in stock for:', session.product);
                await notifyOutOfStock(session.product, session.discord_id);
                return res.status(200).json({ received: true, error: 'Out of stock' });
            }
            
            // Claim the key
            await claimKey(licenseKey, session.discord_id);
            
            // Assign to user
            await assignLicenseToUser(
                session.discord_id,
                session.discord_username,
                licenseKey,
                session.product
            );
            
            // Send license via DM
            const dmSuccess = await sendLicenseDM(session.discord_id, licenseKey, PRODUCTS[session.product]);
            
            // Log purchase (always sent to you with all details + delivery status)
            await logPurchase(session.discord_id, session.discord_username, licenseKey, session.product, dmSuccess);
            
            // Clean up
            await deletePendingPurchase(session.session_id);
            
            console.log('✅ License delivered:', licenseKey, 'to', session.discord_username);
        }
        
        res.status(200).json({ received: true });
        
    } catch (error) {
        console.error('Webhook error:', error);
        // Still return 200 to prevent retries on our errors
        res.status(200).json({ received: true, error: error.message });
    }
});

// ===========================================
// DISCORD BOT FUNCTIONS
// ===========================================
async function sendLicenseDM(discordId, licenseKey, product) {
    try {
        const user = await discordClient.users.fetch(discordId);
        
        const embed = new EmbedBuilder()
            .setColor(0x7c3aed)
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
        
        // Always send purchase notification with all details
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
        // DM admin directly about out of stock
        const admin = await discordClient.users.fetch(process.env.ADMIN_USER_ID);
        const product = PRODUCTS[productType];
        
        const embed = new EmbedBuilder()
            .setColor(0xef4444)
            .setTitle('⚠️ OUT OF STOCK!')
            .setDescription(`Someone tried to purchase but we're out of keys!`)
            .addFields(
                { name: 'Product', value: product.name, inline: true },
                { name: 'User ID', value: discordId, inline: true }
            )
            .setTimestamp();
        
        await admin.send({ embeds: [embed] });
    } catch (error) {
        console.error('Failed to notify:', error);
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

// ===========================================
// DISCORD SLASH COMMANDS
// ===========================================
const commands = [
    // User commands
    new SlashCommandBuilder()
        .setName('license')
        .setDescription('View your SwimHub licenses'),
    
    // Admin commands
    new SlashCommandBuilder()
        .setName('addkey')
        .setDescription('Add license key(s) to stock')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
    
    new SlashCommandBuilder()
        .setName('stock')
        .setDescription('Check license key stock')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
    
    new SlashCommandBuilder()
        .setName('givekey')
        .setDescription('Give a license key to a user')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addUserOption(option =>
            option.setName('user')
                .setDescription('The user to give the key to')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('product')
                .setDescription('Product type')
                .setRequired(true)
                .addChoices(
                    { name: 'Regular Monthly', value: 'regular-monthly' },
                    { name: 'Regular Lifetime', value: 'regular-lifetime' },
                    { name: 'Master Monthly', value: 'master-monthly' },
                    { name: 'Master Lifetime', value: 'master-lifetime' },
                    { name: 'Nightly', value: 'nightly' }
                ))
].map(command => command.toJSON());

async function registerCommands() {
    const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_BOT_TOKEN);
    
    try {
        console.log('Registering slash commands...');
        await rest.put(
            Routes.applicationGuildCommands(process.env.DISCORD_CLIENT_ID, process.env.DISCORD_GUILD_ID),
            { body: commands }
        );
        console.log('✅ Slash commands registered!');
    } catch (error) {
        console.error('Failed to register commands:', error);
    }
}

// ===========================================
// INTERACTION HANDLERS
// ===========================================
discordClient.on('interactionCreate', async (interaction) => {
    // Handle modal submissions
    if (interaction.isModalSubmit()) {
        if (interaction.customId === 'addkeys_modal') {
            const productType = interaction.fields.getTextInputValue('product_type');
            const keysText = interaction.fields.getTextInputValue('license_keys');
            
            const keys = keysText.split(/[\n,]+/).map(k => k.trim()).filter(k => k.length > 0);
            
            if (keys.length === 0) {
                return interaction.reply({ content: '❌ No valid keys provided!', ephemeral: true });
            }
            
            if (!PRODUCTS[productType]) {
                return interaction.reply({ 
                    content: `❌ Invalid product type! Use: ${Object.keys(PRODUCTS).join(', ')}`, 
                    ephemeral: true 
                });
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const result = await addMultipleLicenses(keys, productType, interaction.user.id);
            
            const embed = new EmbedBuilder()
                .setColor(result.added > 0 ? 0x10b981 : 0xef4444)
                .setTitle('📦 Keys Added to Stock')
                .addFields(
                    { name: 'Product', value: PRODUCTS[productType].name, inline: true },
                    { name: '✅ Added', value: result.added.toString(), inline: true },
                    { name: '⚠️ Duplicates', value: result.duplicates.toString(), inline: true }
                )
                .setTimestamp();
            
            await interaction.editReply({ embeds: [embed] });
            
            // Log to admin channel
            try {
                const logChannel = await discordClient.channels.fetch(process.env.DISCORD_LOG_CHANNEL);
                await logChannel.send({
                    embeds: [new EmbedBuilder()
                        .setColor(0x7c3aed)
                        .setTitle('📦 Stock Updated')
                        .setDescription(`<@${interaction.user.id}> added ${result.added} keys to **${PRODUCTS[productType].name}**`)
                        .setTimestamp()
                    ]
                });
            } catch (e) {}
        }
        return;
    }
    
    // Handle select menu
    if (interaction.isStringSelectMenu()) {
        if (interaction.customId === 'addkeys_product_select') {
            const productType = interaction.values[0];
            
            const modal = new ModalBuilder()
                .setCustomId('addkeys_modal')
                .setTitle(`Add ${PRODUCTS[productType].name} Keys`);
            
            const productInput = new TextInputBuilder()
                .setCustomId('product_type')
                .setLabel('Product Type (do not change)')
                .setStyle(TextInputStyle.Short)
                .setValue(productType)
                .setRequired(true);
            
            const keysInput = new TextInputBuilder()
                .setCustomId('license_keys')
                .setLabel('License Keys (one per line)')
                .setStyle(TextInputStyle.Paragraph)
                .setPlaceholder('XXXXX-XXXXX-XXXXX\nYYYYY-YYYYY-YYYYY\nZZZZZ-ZZZZZ-ZZZZZ')
                .setRequired(true);
            
            modal.addComponents(
                new ActionRowBuilder().addComponents(productInput),
                new ActionRowBuilder().addComponents(keysInput)
            );
            
            await interaction.showModal(modal);
        }
        return;
    }
    
    // Handle slash commands
    if (!interaction.isChatInputCommand()) return;
    
    const { commandName } = interaction;
    
    // /license - View your licenses
    if (commandName === 'license') {
        const licenses = await getUserLicenses(interaction.user.id);
        
        if (licenses.length === 0) {
            return interaction.reply({
                content: '❌ You don\'t have any licenses. Purchase one at our website!',
                ephemeral: true
            });
        }
        
        const embed = new EmbedBuilder()
            .setColor(0x7c3aed)
            .setTitle('🔑 Your SwimHub Licenses')
            .setDescription('Here are your licenses:');
        
        licenses.forEach(license => {
            const expiry = license.is_lifetime ? '♾️ Lifetime' : new Date(license.expires_at).toLocaleDateString();
            embed.addFields({
                name: `🔑 ${license.product_name}`,
                value: `Key: \`${license.license_key}\`\nExpires: ${expiry}`,
                inline: false
            });
        });
        
        await interaction.reply({ embeds: [embed], ephemeral: true });
    }
    
    // /addkey - Add keys (shows product selector then modal)
    if (commandName === 'addkey') {
        const selectMenu = new StringSelectMenuBuilder()
            .setCustomId('addkeys_product_select')
            .setPlaceholder('Select product type')
            .addOptions(
                Object.entries(PRODUCTS).map(([key, product]) => ({
                    label: product.name,
                    value: key,
                    description: `Add keys for ${product.name}`
                }))
            );
        
        const row = new ActionRowBuilder().addComponents(selectMenu);
        
        await interaction.reply({
            content: '📦 **Add License Keys**\nSelect the product type:',
            components: [row],
            ephemeral: true
        });
    }
    
    // /stock - Check stock
    if (commandName === 'stock') {
        await interaction.deferReply({ ephemeral: true });
        
        const stock = await getStockCounts();
        
        const embed = new EmbedBuilder()
            .setColor(0x7c3aed)
            .setTitle('📊 License Key Stock')
            .setTimestamp();
        
        if (stock.length === 0) {
            embed.setDescription('No keys in stock! Use `/addkey` to add some.');
        } else {
            for (const [key, product] of Object.entries(PRODUCTS)) {
                const stockItem = stock.find(s => s.product_type === key);
                const available = stockItem ? parseInt(stockItem.available) : 0;
                const claimed = stockItem ? parseInt(stockItem.claimed) : 0;
                const total = stockItem ? parseInt(stockItem.total) : 0;
                
                const statusEmoji = available > 10 ? '🟢' : available > 0 ? '🟡' : '🔴';
                
                embed.addFields({
                    name: `${statusEmoji} ${product.name}`,
                    value: `Available: **${available}**\nClaimed: ${claimed}\nTotal: ${total}`,
                    inline: true
                });
            }
        }
        
        await interaction.editReply({ embeds: [embed] });
    }
    
    // /givekey - Give key to user
    if (commandName === 'givekey') {
        const targetUser = interaction.options.getUser('user');
        const productType = interaction.options.getString('product');
        
        await interaction.deferReply({ ephemeral: true });
        
        const licenseKey = await getAvailableKey(productType);
        
        if (!licenseKey) {
            return interaction.editReply({ content: `❌ No keys available for ${PRODUCTS[productType].name}!` });
        }
        
        await claimKey(licenseKey, targetUser.id);
        await assignLicenseToUser(targetUser.id, targetUser.username, licenseKey, productType);
        await sendLicenseDM(targetUser.id, licenseKey, PRODUCTS[productType]);
        
        await interaction.editReply({
            content: `✅ Gave **${PRODUCTS[productType].name}** to <@${targetUser.id}>\nKey: ||\`${licenseKey}\`||`
        });
    }
});

// ===========================================
// START SERVER
// ===========================================
discordClient.once('ready', async () => {
    console.log(`✅ Bot logged in as ${discordClient.user.tag}`);
    await registerCommands();
});

async function start() {
    await initDatabase();
    
    app.listen(PORT, () => {
        console.log(`✅ Server running on port ${PORT}`);
    });
    
    await discordClient.login(process.env.DISCORD_BOT_TOKEN);
}

start().catch(console.error);

// Cleanup old pending purchases every hour
setInterval(async () => {
    const client = await pool.connect();
    try {
        await client.query(
            "DELETE FROM pending_purchases WHERE created_at < NOW() - INTERVAL '1 hour'"
        );
    } finally {
        client.release();
    }
}, 60 * 60 * 1000);
