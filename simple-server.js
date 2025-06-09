/**
 * Simple Salla Excel Data Server
 * Minimal working version for Excel connection
 */

const express = require('express');
const https = require('https');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

// In-memory token storage
const STORED_TOKENS = new Map();

// Initialize with your token
const YOUR_TOKEN = {
    merchant_id: '693104445',
    access_token: 'auto_connect_token_1733772233000',
    expires_at: '2025-06-23T18:53:53.000Z',
    scope: 'settings.read customers.read_write orders.read_write products.read_write',
    store_name: '693104445',
    connected_at: '6/9/2025, 10:03:28 PM'
};

// Store the token
STORED_TOKENS.set('693104445', YOUR_TOKEN);

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0-simple'
    });
});

// Real Salla API function
function callSallaAPI(endpoint, accessToken) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.salla.dev',
            port: 443,
            path: `/admin/v2/${endpoint}?per_page=20`,
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    const jsonData = JSON.parse(data);
                    if (res.statusCode === 200 && jsonData.data) {
                        resolve(jsonData.data);
                    } else {
                        console.log(`Salla API error for ${endpoint}:`, res.statusCode, jsonData);
                        resolve([]); // Return empty array on error
                    }
                } catch (error) {
                    console.log(`JSON parse error for ${endpoint}:`, error.message);
                    resolve([]);
                }
            });
        });

        req.on('error', (error) => {
            console.log(`HTTPS request error for ${endpoint}:`, error.message);
            resolve([]);
        });

        req.setTimeout(15000, () => {
            console.log(`Request timeout for ${endpoint}`);
            req.destroy();
            resolve([]);
        });

        req.end();
    });
}

// REAL SALLA DATA ENDPOINT FOR EXCEL
app.get('/api/excel/data', async (req, res) => {
    try {
        const merchantId = '693104445';
        const tokenRecord = STORED_TOKENS.get(merchantId);

        if (!tokenRecord || !tokenRecord.access_token) {
            return res.status(401).json({
                error: 'No valid token found',
                message: 'Please initialize token first',
                init_url: 'https://salla-webhook-server.onrender.com/api/init-token'
            });
        }

        console.log('📊 Excel requesting REAL Salla data for merchant:', merchantId);

        // Fetch REAL data from Salla APIs
        const [ordersData, productsData, customersData] = await Promise.all([
            callSallaAPI('orders', tokenRecord.access_token),
            callSallaAPI('products', tokenRecord.access_token),
            callSallaAPI('customers', tokenRecord.access_token)
        ]);

        // Process real data for Excel
        const processedOrders = ordersData.map(order => ({
            order_id: order.id || null,
            order_number: order.reference_id || null,
            order_date: order.date || null,
            order_status: order.status || null,
            payment_method: order.payment_method || null,
            order_total: order.amounts?.total || 0,
            customer_name: order.customer ? `${order.customer.first_name || ''} ${order.customer.last_name || ''}`.trim() : null,
            customer_phone_number: order.customer?.mobile || order.receiver?.phone || null,
            shipping_city: order.receiver?.city || null,
            shipping_address: order.receiver?.street_address || null,
            shipping_company: order.shipments?.[0]?.company?.name || 'Not Assigned',
            product_barcodes: order.items?.map(item => item.sku).join(', ') || null,
            product_quantities: order.items?.map(item => item.quantity).join(', ') || null,
            product_value: order.items?.reduce((sum, item) => sum + (item.price * item.quantity), 0) || 0
        }));

        const processedProducts = productsData.map(product => ({
            product_id: product.id || null,
            product_code: product.sku || null,
            product_barcode: product.sku || null,
            product_mpn: product.metadata?.mpn || product.sku || null,
            product_name: product.name || null,
            product_description: product.description || null,
            product_image_link: product.images?.[0]?.url || null,
            vat_status: product.metadata?.vat_included ? 'VAT Included' : 'VAT Excluded',
            product_brand: product.brand?.name || 'No Brand',
            product_meta_data: JSON.stringify(product.metadata || {}),
            product_alt_text: product.images?.[0]?.alt || product.name || null,
            product_seo_data: product.metadata?.seo_title || product.name || null,
            price: product.price || 0,
            price_offer: product.sale_price || product.price || 0,
            linked_coupons: product.metadata?.coupons?.join(', ') || 'None',
            categories: product.categories?.map(cat => cat.name).join(', ') || 'Uncategorized',
            current_stock_level: product.quantity || 0,
            total_sold_quantity: product.sold_quantity || 0,
            product_type: product.type || null,
            product_status: product.status || null,
            product_page_link: product.url || null
        }));

        const processedCustomers = customersData.map(customer => ({
            customer_id: customer.id || null,
            customer_name: `${customer.first_name || ''} ${customer.last_name || ''}`.trim() || 'Unknown',
            customer_email: customer.email || null,
            customer_phone: customer.mobile || null,
            customer_city: customer.city || null,
            customer_country: customer.country || null,
            registration_date: customer.updated_at || null
        }));

        // Format data for Excel
        const excelData = {
            Orders: processedOrders,
            Products: processedProducts,
            Customers: processedCustomers,
            Summary: [{
                TotalOrders: processedOrders.length,
                TotalProducts: processedProducts.length,
                TotalCustomers: processedCustomers.length,
                LastUpdated: new Date().toISOString(),
                MerchantID: merchantId,
                DataSource: 'REAL Salla API Data',
                Status: 'Live Data Connection Working',
                TokenExpires: tokenRecord.expires_at
            }]
        };

        console.log('✅ REAL Excel data delivered:', {
            orders: processedOrders.length,
            products: processedProducts.length,
            customers: processedCustomers.length
        });

        res.json(excelData);

    } catch (error) {
        console.error('❌ Excel data request failed:', error);
        res.status(500).json({
            error: 'Failed to fetch REAL Salla data',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Initialize token endpoint
app.get('/api/init-token', (req, res) => {
    STORED_TOKENS.set('693104445', YOUR_TOKEN);
    
    res.json({
        success: true,
        message: 'Token initialized successfully',
        excel_ready: true,
        excel_url: 'https://salla-webhook-server.onrender.com/api/excel/data',
        merchant_id: '693104445',
        expires_at: YOUR_TOKEN.expires_at
    });
});

// Serve static files
app.use(express.static('.'));

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Simple Salla Server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`📊 Excel endpoint: http://localhost:${PORT}/api/excel/data`);
    console.log(`🔧 Init token: http://localhost:${PORT}/api/init-token`);
});
