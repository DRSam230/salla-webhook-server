/**
 * Salla Official Webhook Server
 * Implements ONLY methods documented at https://docs.salla.dev/
 *
 * Official Documentation References:
 * - Authorization: https://docs.salla.dev/421118m0
 * - Webhooks: https://docs.salla.dev/421119m0
 * - API Endpoints: https://docs.salla.dev/426392m0
 *
 * Uses ONLY official Salla methods:
 * - Easy Mode OAuth with app.store.authorize event
 * - Official webhook signature verification
 * - Standard Salla API endpoints
 * - Official installation URL format
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

// Salla App Configuration
const SALLA_CONFIG = {
    APP_ID: '930173362',
    CLIENT_ID: 'f6b4c9db-2968-4612-bf17-c34dc7aab749',
    CLIENT_SECRET: '74c4469b3ab16c51659a2c3b1405166f',
    WEBHOOK_SECRET: process.env.SALLA_WEBHOOK_SECRET || 'your-webhook-secret-from-partners-portal'
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
// Implements the exact method documented in Security Strategies section
function verifyWebhookSignature(payload, signature, secret) {
    try {
        // Official Salla signature verification as per docs.salla.dev
        // Creates SHA256 hash of request body using secret
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payload, 'utf8')
            .digest('hex');

        // Use timing-safe equality as recommended in official docs
        return crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );
    } catch (error) {
        addDevLog('Official signature verification error', 'error', error.message);
        return false;
    }
}

// Store token securely (in production, use a proper database)
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
// Implements the exact webhook handling as documented
app.post('/salla/webhook', async (req, res) => {
    addDevLog('Official Salla webhook request received', 'info', {
        headers: req.headers,
        body: req.body
    });

    try {
        // Official Salla security verification (docs.salla.dev/421119m0)
        // Check for official headers: X-Salla-Security-Strategy and X-Salla-Signature
        const signature = req.headers['x-salla-signature'];
        const securityStrategy = req.headers['x-salla-security-strategy'];

        addDevLog('Official security headers received', 'info', {
            strategy: securityStrategy,
            signature: signature ? 'Present' : 'Missing'
        });

        // Verify signature using official method if configured
        if (signature && SALLA_CONFIG.WEBHOOK_SECRET !== 'your-webhook-secret-from-partners-portal') {
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
        // Store the access token
        const tokenRecord = await storeToken(merchantId, tokenData);
        
        addDevLog('Store authorization completed', 'success', {
            merchant: merchantId,
            token_length: tokenData.access_token.length,
            expires_in_days: Math.round((tokenData.expires * 1000 - Date.now()) / (1000 * 60 * 60 * 24))
        });
        
        // Here you can add additional logic:
        // - Send notification to admin
        // - Initialize store data sync
        // - Set up recurring tasks
        // - Update Excel Add-in configuration
        
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
    
    // Log installation for analytics
    // Initialize merchant-specific configurations
}

// Handle app updates
async function handleAppUpdated(merchantId, appData, createdAt) {
    addDevLog('App updated', 'info', {
        merchant: merchantId,
        app_name: appData.app_name,
        update_date: appData.update_date
    });
    
    // Note: After app update, Salla will send a new app.store.authorize event
    // with updated tokens, so no manual token refresh needed
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
        server: 'Salla Super Easy Mode Webhook Server',
        status: 'running',
        app_id: SALLA_CONFIG.APP_ID,
        client_id: SALLA_CONFIG.CLIENT_ID,
        webhook_secret_configured: SALLA_CONFIG.WEBHOOK_SECRET !== 'your-webhook-secret-from-partners-portal',
        uptime: process.uptime(),
        memory_usage: process.memoryUsage(),
        timestamp: new Date().toISOString()
    });
});

// Get all stored tokens (for frontend connection checking)
app.get('/api/dev/tokens', async (req, res) => {
    try {
        const tokensDir = path.join(__dirname, 'tokens');

        // Check if tokens directory exists
        try {
            await fs.access(tokensDir);
        } catch (error) {
            return res.json({ tokens: [] });
        }

        const files = await fs.readdir(tokensDir);
        const tokenFiles = files.filter(file => file.startsWith('merchant_') && file.endsWith('.json'));

        const tokens = [];
        for (const file of tokenFiles) {
            try {
                const tokenData = await fs.readFile(path.join(tokensDir, file), 'utf8');
                const tokenRecord = JSON.parse(tokenData);

                // Check if token is still valid
                const expiresAt = new Date(tokenRecord.expires_at);
                const now = new Date();
                const isValid = now < expiresAt;

                tokens.push({
                    merchant_id: tokenRecord.merchant_id,
                    expires_at: tokenRecord.expires_at,
                    scope: tokenRecord.scope,
                    received_at: tokenRecord.received_at,
                    is_valid: isValid,
                    access_token: tokenRecord.access_token, // Include for frontend use
                    store_name: tokenRecord.store_name || tokenRecord.merchant_id
                });
            } catch (error) {
                addDevLog(`Error reading token file ${file}`, 'error', error.message);
            }
        }

        res.json({
            tokens: tokens.sort((a, b) => new Date(b.received_at) - new Date(a.received_at)),
            total: tokens.length
        });

    } catch (error) {
        addDevLog('Error listing tokens', 'error', error.message);
        res.status(500).json({ error: 'Failed to list tokens' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString(), version: '1.0.0-secure' });
});

// Homepage endpoint - redirect to app
app.get('/', (req, res) => {
    res.redirect('/app');
});

// Server status page
app.get('/status', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Salla Webhook Server Status</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .status { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .endpoint { background: #f8f9fa; padding: 10px; border-left: 4px solid #007bff; margin: 10px 0; font-family: monospace; }
        .config { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Salla Excel Data Connector</h1>
        <h2>Webhook Server Status</h2>

        <div class="status">
            ✅ <strong>Server Running</strong> - Ready to receive Salla webhooks
        </div>

        <h3>📡 Available Endpoints:</h3>
        <div class="endpoint"><strong>App Frontend:</strong> GET /app</div>
        <div class="endpoint"><strong>Webhook:</strong> POST /salla/webhook</div>
        <div class="endpoint"><strong>Health:</strong> GET /health</div>
        <div class="endpoint"><strong>Status:</strong> GET /api/dev/status</div>
        <div class="endpoint"><strong>Logs:</strong> GET /api/dev/logs</div>
        <div class="endpoint"><strong>Tokens:</strong> GET /api/dev/tokens</div>

        <h3>⚙️ Configuration:</h3>
        <div class="config">
            <strong>App ID:</strong> ${SALLA_CONFIG.APP_ID}<br>
            <strong>Client ID:</strong> ${SALLA_CONFIG.CLIENT_ID}<br>
            <strong>Webhook Secret:</strong> ${SALLA_CONFIG.WEBHOOK_SECRET !== 'your-webhook-secret-from-partners-portal' ? '✅ Configured' : '❌ Not configured'}<br>
            <strong>OAuth Mode:</strong> Easy Mode (Webhook-based)
        </div>

        <h3>🔗 Quick Links:</h3>
        <p>
            <a href="/app">🎯 Open Salla App</a> |
            <a href="/health" target="_blank">🏥 Health Check</a> |
            <a href="/api/dev/status" target="_blank">📊 Server Status</a> |
            <a href="/api/dev/logs" target="_blank">📋 Development Logs</a> |
            <a href="/api/dev/tokens" target="_blank">🔑 Stored Tokens</a>
        </p>

        <p><small>Server Time: ${new Date().toISOString()}</small></p>
    </div>
</body>
</html>
    `);
});

// Main app frontend
app.get('/app', async (req, res) => {
    try {
        // Read the frontend file
        const frontendPath = path.join(__dirname, 'salla-app-frontend.html');
        const frontendContent = await fs.readFile(frontendPath, 'utf8');

        // Update the frontend to use the current server URL
        const updatedContent = frontendContent.replace(
            /https:\/\/salla-webhook-server\.onrender\.com/g,
            req.protocol + '://' + req.get('host')
        );

        res.send(updatedContent);
    } catch (error) {
        res.status(500).send(`
<!DOCTYPE html>
<html>
<head>
    <title>Salla App - Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Salla Excel Data Connector</h1>
        <div class="error">
            <h3>❌ Frontend Not Found</h3>
            <p>The frontend file is not available. Please ensure salla-app-frontend.html is in the server directory.</p>
            <p><strong>Error:</strong> ${error.message}</p>
        </div>
        <p><a href="/status">← Back to Server Status</a></p>
    </div>
</body>
</html>
        `);
    }
});

// Excel Add-in interface
app.get('/excel-addin.html', async (req, res) => {
    try {
        const addinPath = path.join(__dirname, 'excel-addin.html');
        const addinContent = await fs.readFile(addinPath, 'utf8');

        // Update URLs to use current server
        const updatedContent = addinContent.replace(
            /https:\/\/salla-webhook-server\.onrender\.com/g,
            req.protocol + '://' + req.get('host')
        );

        res.send(updatedContent);
    } catch (error) {
        res.status(404).send('Excel Add-in interface not found');
    }
});

// Serve static files (for testing)
app.use(express.static('.'));

// Start server
app.listen(PORT, () => {
    addDevLog(`Salla Webhook Server started on port ${PORT}`, 'success', {
        app_id: SALLA_CONFIG.APP_ID,
        client_id: SALLA_CONFIG.CLIENT_ID,
        webhook_secret_configured: SALLA_CONFIG.WEBHOOK_SECRET !== 'your-webhook-secret-from-partners-portal'
    });
    
    console.log(`
🚀 Salla Super Easy Mode Webhook Server

🎯 Main App Frontend: http://localhost:${PORT}/app
📡 Webhook endpoint: http://localhost:${PORT}/salla/webhook
🔧 Development logs: http://localhost:${PORT}/api/dev/logs
📊 Server status: http://localhost:${PORT}/api/dev/status
🏥 Health check: http://localhost:${PORT}/health

📋 Configuration:
   App ID: ${SALLA_CONFIG.APP_ID}
   Client ID: ${SALLA_CONFIG.CLIENT_ID}
   Webhook Secret: ${SALLA_CONFIG.WEBHOOK_SECRET !== 'your-webhook-secret-from-partners-portal' ? 'Configured' : 'Not configured'}

🎯 Next Steps:
1. Open the app frontend: http://localhost:${PORT}/app
2. Configure webhook URL in Salla Partners Portal
3. Set OAuth mode to "Easy Mode"
4. Install your app in a store
5. Watch automatic token reception!
    `);
});

module.exports = app;
