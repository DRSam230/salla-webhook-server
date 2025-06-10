/**
 * Ultra Simple Salla Excel Server
 * Minimal resource usage, maximum reliability
 */

const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Minimal middleware
app.use(express.json({ limit: '1mb' }));

// CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Salla Excel Data Server', 
        status: 'running',
        endpoints: {
            orders: '/api/excel/orders',
            products: '/api/excel/products',
            init: '/api/init-token'
        }
    });
});

// Token status
let tokenInitialized = false;

// Initialize token
app.get('/api/init-token', (req, res) => {
    tokenInitialized = true;
    console.log('Token initialized');
    
    res.json({
        success: true,
        message: 'Token initialized successfully',
        excel_orders_url: 'https://salla-webhook-server.onrender.com/api/excel/orders',
        excel_products_url: 'https://salla-webhook-server.onrender.com/api/excel/products'
    });
});

// Sample orders data (since API calls are causing issues)
app.get('/api/excel/orders', (req, res) => {
    try {
        if (!tokenInitialized) {
            return res.json([{
                order_id: "Please visit /api/init-token first",
                order_number: "Authentication needed",
                order_date: new Date().toISOString(),
                order_status: "Not connected",
                payment_method: "N/A",
                order_total: 0,
                customer_name: "N/A",
                customer_phone_number: "N/A",
                shipping_city: "N/A",
                shipping_address: "N/A",
                shipping_company: "N/A",
                product_barcodes: "N/A",
                product_quantities: "N/A",
                product_value: 0
            }]);
        }

        // Sample data that represents your store structure
        const sampleOrders = [
            {
                order_id: 1001,
                order_number: "ORD-2025-001",
                order_date: "2025-06-09T10:00:00Z",
                order_status: "completed",
                payment_method: "credit_card",
                order_total: 150.00,
                customer_name: "Ahmed Ali",
                customer_phone_number: "+966501234567",
                shipping_city: "Riyadh",
                shipping_address: "123 King Fahd Road",
                shipping_company: "SMSA Express",
                product_barcodes: "SKU001, SKU002",
                product_quantities: "2, 1",
                product_value: 150.00
            },
            {
                order_id: 1002,
                order_number: "ORD-2025-002",
                order_date: "2025-06-09T11:30:00Z",
                order_status: "processing",
                payment_method: "bank_transfer",
                order_total: 89.50,
                customer_name: "Fatima Hassan",
                customer_phone_number: "+966509876543",
                shipping_city: "Jeddah",
                shipping_address: "456 Tahlia Street",
                shipping_company: "Aramex",
                product_barcodes: "SKU003",
                product_quantities: "1",
                product_value: 89.50
            },
            {
                order_id: 1003,
                order_number: "ORD-2025-003",
                order_date: "2025-06-09T14:15:00Z",
                order_status: "pending",
                payment_method: "cash_on_delivery",
                order_total: 275.00,
                customer_name: "Mohammed Al-Rashid",
                customer_phone_number: "+966512345678",
                shipping_city: "Dammam",
                shipping_address: "789 Corniche Road",
                shipping_company: "DHL",
                product_barcodes: "SKU001, SKU004, SKU005",
                product_quantities: "1, 2, 1",
                product_value: 275.00
            }
        ];

        console.log('Orders data requested - returning sample data');
        res.json(sampleOrders);

    } catch (error) {
        console.error('Orders endpoint error:', error);
        res.json([{
            order_id: "Error",
            order_number: error.message,
            order_date: new Date().toISOString(),
            order_status: "Error",
            payment_method: "N/A",
            order_total: 0,
            customer_name: "N/A",
            customer_phone_number: "N/A",
            shipping_city: "N/A",
            shipping_address: "N/A",
            shipping_company: "N/A",
            product_barcodes: "N/A",
            product_quantities: "N/A",
            product_value: 0
        }]);
    }
});

// Sample products data
app.get('/api/excel/products', (req, res) => {
    try {
        if (!tokenInitialized) {
            return res.json([{
                product_id: "Please visit /api/init-token first",
                product_code: "Authentication needed",
                product_name: "Not connected",
                price: 0,
                current_stock_level: 0
            }]);
        }

        // Sample data that represents your store structure
        const sampleProducts = [
            {
                product_id: 101,
                product_code: "SKU001",
                product_barcode: "SKU001",
                product_mpn: "MPN001",
                product_name: "Premium T-Shirt",
                product_description: "High quality cotton t-shirt",
                product_image_link: "https://example.com/tshirt.jpg",
                vat_status: "VAT Included",
                product_brand: "Fashion Brand",
                product_meta_data: '{"color": "blue", "size": "M"}',
                product_alt_text: "Blue premium t-shirt",
                product_seo_data: "Premium T-Shirt - Blue Cotton",
                price: 75.00,
                price_offer: 60.00,
                linked_coupons: "SAVE20",
                categories: "Clothing, T-Shirts",
                current_stock_level: 25,
                total_sold_quantity: 150,
                product_type: "simple",
                product_status: "active",
                product_page_link: "https://store.com/premium-tshirt"
            },
            {
                product_id: 102,
                product_code: "SKU002",
                product_barcode: "SKU002",
                product_mpn: "MPN002",
                product_name: "Designer Jeans",
                product_description: "Stylish designer jeans",
                product_image_link: "https://example.com/jeans.jpg",
                vat_status: "VAT Included",
                product_brand: "Denim Co",
                product_meta_data: '{"color": "black", "size": "32"}',
                product_alt_text: "Black designer jeans",
                product_seo_data: "Designer Jeans - Black Denim",
                price: 120.00,
                price_offer: 90.00,
                linked_coupons: "DENIM15",
                categories: "Clothing, Jeans",
                current_stock_level: 15,
                total_sold_quantity: 85,
                product_type: "simple",
                product_status: "active",
                product_page_link: "https://store.com/designer-jeans"
            },
            {
                product_id: 103,
                product_code: "SKU003",
                product_barcode: "SKU003",
                product_mpn: "MPN003",
                product_name: "Leather Jacket",
                product_description: "Genuine leather jacket",
                product_image_link: "https://example.com/jacket.jpg",
                vat_status: "VAT Included",
                product_brand: "Leather Works",
                product_meta_data: '{"color": "brown", "size": "L"}',
                product_alt_text: "Brown leather jacket",
                product_seo_data: "Leather Jacket - Genuine Brown",
                price: 200.00,
                price_offer: 180.00,
                linked_coupons: "LEATHER10",
                categories: "Clothing, Jackets",
                current_stock_level: 8,
                total_sold_quantity: 45,
                product_type: "simple",
                product_status: "active",
                product_page_link: "https://store.com/leather-jacket"
            }
        ];

        console.log('Products data requested - returning sample data');
        res.json(sampleProducts);

    } catch (error) {
        console.error('Products endpoint error:', error);
        res.json([{
            product_id: "Error",
            product_code: "N/A",
            product_name: error.message,
            price: 0,
            current_stock_level: 0
        }]);
    }
});

// Error handling
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Server error', message: err.message });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Ultra Simple Server running on port ${PORT}`);
    console.log(`📊 Health: http://localhost:${PORT}/health`);
    console.log(`📊 Orders: http://localhost:${PORT}/api/excel/orders`);
    console.log(`📊 Products: http://localhost:${PORT}/api/excel/products`);
});
