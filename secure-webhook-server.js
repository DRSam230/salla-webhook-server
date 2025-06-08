/**
 * Salla Official Webhook Server - SECURE VERSION
 * Implements ONLY methods documented at https://docs.salla.dev/
 * 
 * SECURITY: Uses environment variables for sensitive data
 * NO HARDCODED SECRETS - Safe for public GitHub repositories
 */

const express = require('express');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3002;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS for development
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Salla-Signature, X-Salla-Security-Strategy');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

// 🔒 SECURE: Salla App Configuration using Environment Variables
const SALLA_CONFIG = {
    APP_ID: process.env.SALLA_APP_ID || '930173362',
    CLIENT_ID: process.env.SALLA_CLIENT_ID || 'f6b4c9db-2968-4612-bf17-c34dc7aab749',
    CLIENT_SECRET: process.env.SALLA_CLIENT_SECRET || 'your-client-secret-here',
    WEBHOOK_SECRET: process.env.SALLA_WEBHOOK_SECRET || 'your-webhook-secret-here'
};

// Development log storage
const DEV_LOG = [];

function addDevLog(message, type = 'info', data = null) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        type: type,
        message: message,
        data: data
    };
    DEV_LOG.push(logEntry);
    console.log(`[${logEntry.timestamp}] [${type.toUpperCase()}] ${message}`, data || '');
    
    // Keep only last 100 entries
    if (DEV_LOG.length > 100) {
        DEV_LOG.shift();
    }
}

// Official Salla webhook signature verification (docs.salla.dev/421119m0)
function verifyWebhookSignature(payload, signature, secret) {
    try {
        // Official Salla signature verification as per docs.salla.dev
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payload, 'utf8')
            .digest('hex');
        
        return crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );
    } catch (error) {
        addDevLog('Official signature verification error', 'error', error.message);
        return false;
    }
}

// Store token securely
async function storeToken(merchantId, tokenData) {
    try {
        const tokenFile = path.join(__dirname, 'tokens', `merchant_${merchantId}.json`);
        
        // Ensure tokens directory exists
        await fs.mkdir(path.dirname(tokenFile), { recursive: true });
        
        const tokenRecord = {
            merchant_id: merchantId,
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token,
            expires_at: new Date(tokenData.expires * 1000).toISOString(),
            scope: tokenData.scope,
            token_type: tokenData.token_type,
            received_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };
        
        await fs.writeFile(tokenFile, JSON.stringify(tokenRecord, null, 2));
        addDevLog(`Token stored for merchant ${merchantId}`, 'success', {
            expires_at: tokenRecord.expires_at,
            scope: tokenRecord.scope
        });
        
        return tokenRecord;
    } catch (error) {
        addDevLog('Token storage error', 'error', error.message);
        throw error;
    }
}

// Get stored token
async function getStoredToken(merchantId) {
    try {
        const tokenFile = path.join(__dirname, 'tokens', `merchant_${merchantId}.json`);
        const tokenData = await fs.readFile(tokenFile, 'utf8');
        const tokenRecord = JSON.parse(tokenData);
        
        // Check if token is still valid
        const expiresAt = new Date(tokenRecord.expires_at);
        const now = new Date();
        
        if (now >= expiresAt) {
            addDevLog(`Token expired for merchant ${merchantId}`, 'warning');
            return null;
        }
        
        return tokenRecord;
    } catch (error) {
        if (error.code !== 'ENOENT') {
            addDevLog('Token retrieval error', 'error', error.message);
        }
        return null;
    }
}

// Official Salla webhook endpoint (docs.salla.dev/421119m0)
app.post('/salla/webhook', async (req, res) => {
    addDevLog('Official Salla webhook request received', 'info', {
        headers: req.headers,
        body: req.body
    });
    
    try {
        // Official Salla security verification (docs.salla.dev/421119m0)
        const signature = req.headers['x-salla-signature'];
        const securityStrategy = req.headers['x-salla-security-strategy'];
        
        addDevLog('Official security headers received', 'info', {
            strategy: securityStrategy,
            signature: signature ? 'Present' : 'Missing'
        });
        
        // Verify signature using official method if configured
        if (signature && SALLA_CONFIG.WEBHOOK_SECRET !== 'your-webhook-secret-here') {
            const rawBody = JSON.stringify(req.body);
            const isValid = verifyWebhookSignature(rawBody, signature, SALLA_CONFIG.WEBHOOK_SECRET);
            
            if (!isValid) {
                addDevLog('Official signature verification failed', 'error');
                return res.status(401).json({ error: 'Invalid signature' });
            }
            addDevLog('Official signature verification successful', 'success');
        }
        
        const { event, merchant, data, created_at } = req.body;
        
        addDevLog(`Processing webhook event: ${event}`, 'info', {
            merchant: merchant,
            created_at: created_at
        });
        
        // Handle different Salla events
        switch (event) {
            case 'app.store.authorize':
                await handleStoreAuthorize(merchant, data, created_at);
                break;
                
            case 'app.installed':
                await handleAppInstalled(merchant, data, created_at);
                break;
                
            case 'app.updated':
                await handleAppUpdated(merchant, data, created_at);
                break;
                
            case 'app.uninstalled':
                await handleAppUninstalled(merchant, data, created_at);
                break;
                
            default:
                addDevLog(`Unhandled event type: ${event}`, 'warning');
        }
        
        // Always respond with 200 to acknowledge receipt
        res.status(200).json({ 
            success: true, 
            event: event,
            merchant: merchant,
            processed_at: new Date().toISOString()
        });
        
    } catch (error) {
        addDevLog('Webhook processing error', 'error', error.message);
        res.status(500).json({ error: 'Webhook processing failed' });
    }
});

// Handle app.store.authorize event (most important for Easy Mode)
async function handleStoreAuthorize(merchantId, tokenData, createdAt) {
    addDevLog('Processing app.store.authorize event', 'info', {
        merchant: merchantId,
        scope: tokenData.scope,
        expires: new Date(tokenData.expires * 1000).toISOString()
    });
    
    try {
        const tokenRecord = await storeToken(merchantId, tokenData);
        
        addDevLog('Store authorization completed', 'success', {
            merchant: merchantId,
            token_length: tokenData.access_token.length,
            expires_in_days: Math.round((tokenData.expires * 1000 - Date.now()) / (1000 * 60 * 60 * 24))
        });
        
        return tokenRecord;
    } catch (error) {
        addDevLog('Store authorization failed', 'error', error.message);
        throw error;
    }
}

// Handle app installation
async function handleAppInstalled(merchantId, appData, createdAt) {
    addDevLog('App installed', 'success', {
        merchant: merchantId,
        app_name: appData.app_name,
        store_type: appData.store_type,
        scopes: appData.app_scopes
    });
}

// Handle app updates
async function handleAppUpdated(merchantId, appData, createdAt) {
    addDevLog('App updated', 'info', {
        merchant: merchantId,
        app_name: appData.app_name,
        update_date: appData.update_date
    });
}

// Handle app uninstallation
async function handleAppUninstalled(merchantId, appData, createdAt) {
    addDevLog('App uninstalled', 'warning', {
        merchant: merchantId,
        app_name: appData.app_name,
        uninstallation_date: appData.uninstallation_date
    });
    
    // Clean up stored tokens and data
    try {
        const tokenFile = path.join(__dirname, 'tokens', `merchant_${merchantId}.json`);
        await fs.unlink(tokenFile);
        addDevLog(`Tokens cleaned up for merchant ${merchantId}`, 'info');
    } catch (error) {
        // File might not exist, which is fine
    }
}

// API endpoint to get token for a merchant (for Excel Add-in)
app.get('/api/token/:merchantId', async (req, res) => {
    const { merchantId } = req.params;
    
    try {
        const tokenRecord = await getStoredToken(merchantId);
        
        if (!tokenRecord) {
            return res.status(404).json({ 
                error: 'No valid token found',
                message: 'Merchant needs to install/reinstall the app'
            });
        }
        
        // Return token info (without exposing the actual token for security)
        res.json({
            merchant_id: tokenRecord.merchant_id,
            expires_at: tokenRecord.expires_at,
            scope: tokenRecord.scope,
            token_type: tokenRecord.token_type,
            received_at: tokenRecord.received_at,
            is_valid: new Date() < new Date(tokenRecord.expires_at)
        });
        
    } catch (error) {
        addDevLog('Token retrieval API error', 'error', error.message);
        res.status(500).json({ error: 'Failed to retrieve token' });
    }
});

// API endpoint for Excel Add-in to get actual token (secure this in production)
app.post('/api/excel/token', async (req, res) => {
    const { merchantId, clientSecret } = req.body;
    
    // Verify client secret (basic security)
    if (clientSecret !== SALLA_CONFIG.CLIENT_SECRET) {
        return res.status(401).json({ error: 'Invalid client secret' });
    }
    
    try {
        const tokenRecord = await getStoredToken(merchantId);
        
        if (!tokenRecord) {
            return res.status(404).json({ 
                error: 'No valid token found',
                message: 'Merchant needs to install/reinstall the app'
            });
        }
        
        // Return the actual token for Excel Add-in use
        res.json({
            access_token: tokenRecord.access_token,
            expires_at: tokenRecord.expires_at,
            scope: tokenRecord.scope
        });
        
        addDevLog(`Token provided to Excel Add-in for merchant ${merchantId}`, 'info');
        
    } catch (error) {
        addDevLog('Excel token API error', 'error', error.message);
        res.status(500).json({ error: 'Failed to retrieve token' });
    }
});

// Development endpoints
app.get('/api/dev/logs', (req, res) => {
    res.json({
        logs: DEV_LOG.slice(-50), // Last 50 entries
        total_entries: DEV_LOG.length
    });
});

app.get('/api/dev/status', (req, res) => {
    res.json({
        server: 'Salla Official Webhook Server (Secure)',
        status: 'running',
        app_id: SALLA_CONFIG.APP_ID,
        client_id: SALLA_CONFIG.CLIENT_ID,
        webhook_secret_configured: SALLA_CONFIG.WEBHOOK_SECRET !== 'your-webhook-secret-here',
        client_secret_configured: SALLA_CONFIG.CLIENT_SECRET !== 'your-client-secret-here',
        uptime: process.uptime(),
        memory_usage: process.memoryUsage(),
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0-secure'
    });
});

// Serve static files (for testing)
app.use(express.static('.'));

// Start server
app.listen(PORT, () => {
    addDevLog(`Salla Webhook Server started on port ${PORT}`, 'success', {
        app_id: SALLA_CONFIG.APP_ID,
        client_id: SALLA_CONFIG.CLIENT_ID,
        webhook_secret_configured: SALLA_CONFIG.WEBHOOK_SECRET !== 'your-webhook-secret-here',
        client_secret_configured: SALLA_CONFIG.CLIENT_SECRET !== 'your-client-secret-here',
        environment: process.env.NODE_ENV || 'development'
    });
    
    console.log(`
🔒 Salla Official Webhook Server (SECURE VERSION)
📡 Webhook endpoint: http://localhost:${PORT}/salla/webhook
🔧 Development logs: http://localhost:${PORT}/api/dev/logs
📊 Server status: http://localhost:${PORT}/api/dev/status
🏥 Health check: http://localhost:${PORT}/health

🔐 Security Configuration:
   App ID: ${SALLA_CONFIG.APP_ID}
   Client ID: ${SALLA_CONFIG.CLIENT_ID}
   Client Secret: ${SALLA_CONFIG.CLIENT_SECRET !== 'your-client-secret-here' ? 'Configured via ENV' : 'Not configured'}
   Webhook Secret: ${SALLA_CONFIG.WEBHOOK_SECRET !== 'your-webhook-secret-here' ? 'Configured via ENV' : 'Not configured'}

⚠️  SECURITY NOTICE:
   - Sensitive data loaded from environment variables
   - Safe for public GitHub repositories
   - Configure secrets in Render.com dashboard

🎯 Next Steps:
1. Upload this secure version to GitHub
2. Configure environment variables in Render.com
3. Deploy and test webhook functionality
    `);
});

module.exports = app;
