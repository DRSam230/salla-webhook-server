// SALLA COMPLETE API COLLECTION - ALL AVAILABLE ENDPOINTS
// Master Power Query File for Complete Salla Store Data Access
// Based on comprehensive review of https://docs.salla.dev/
// Generated: 2025-06-08

let
    // Configuration (Your Store)
    MerchantId = "693104445", // Replace with your actual merchant ID
    ClientSecret = "74c4469b3ab16c51659a2c3b1405166f",
    WebhookUrl = "https://salla-webhook-server.onrender.com/api/excel/token",

    // Step 1: Get Access Token
    TokenRequest = [
        merchantId = MerchantId,
        clientSecret = ClientSecret
    ],

    TokenResponse = Web.Contents(
        WebhookUrl,
        [
            Headers = [#"Content-Type" = "application/json"],
            Content = Json.FromValue(TokenRequest)
        ]
    ),

    TokenData = Json.Document(TokenResponse),
    AccessToken = TokenData[access_token],

    // FUNCTION: Generic API Call Function
    CallSallaAPI = (endpoint as text, optional pageLimit as number) =>
        let
            MaxPages = if pageLimit = null then 5 else pageLimit,
            
            GetPage = (pageNum as number) =>
                let
                    Response = Web.Contents(
                        "https://api.salla.dev/admin/v2/" & endpoint & 
                        (if Text.Contains(endpoint, "?") then "&" else "?") & 
                        "page=" & Number.ToText(pageNum) & "&per_page=50",
                        [
                            Headers = [
                                #"Authorization" = "Bearer " & AccessToken,
                                #"Accept" = "application/json"
                            ]
                        ]
                    ),
                    JsonData = Json.Document(Response)
                in
                    JsonData,

            FirstPage = GetPage(1),
            TotalPages = if FirstPage[pagination]? <> null then 
                Number.Min(FirstPage[pagination][totalPages], MaxPages) else 1,
            
            PageNumbers = List.Numbers(1, TotalPages),
            AllPages = List.Transform(PageNumbers, each GetPage(_)),
            AllData = List.Combine(List.Transform(AllPages, each 
                if _[data]? <> null then _[data] else {}))
        in
            AllData,

    // CORE BUSINESS DATA COLLECTION
    
    // 1. ORDERS - Complete order data with all details
    OrdersData = CallSallaAPI("orders?expanded=true", 10),
    OrdersTable = Table.FromList(OrdersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    OrdersExpanded = Table.ExpandRecordColumn(OrdersTable, "Column1", 
        {"id", "reference_id", "date", "status", "payment_method", "currency", "amounts", 
         "customer", "receiver", "source", "total_weight", "urls", "tags"}, 
        {"order_id", "order_number", "order_date", "order_status", "payment_method", 
         "currency", "amounts", "customer", "receiver", "source", "total_weight", "urls", "tags"}),

    // 2. PRODUCTS - Complete product catalog
    ProductsData = CallSallaAPI("products", 20),
    ProductsTable = Table.FromList(ProductsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    ProductsExpanded = Table.ExpandRecordColumn(ProductsTable, "Column1", 
        {"id", "sku", "name", "description", "price", "sale_price", "quantity", "sold_quantity", 
         "images", "brand", "categories", "status", "type", "url", "metadata"}, 
        {"product_id", "product_sku", "product_name", "product_description", "price", "sale_price", 
         "stock_quantity", "sold_quantity", "images", "brand", "categories", "status", "type", "url", "metadata"}),

    // 3. CUSTOMERS - Complete customer database
    CustomersData = CallSallaAPI("customers", 20),
    CustomersTable = Table.FromList(CustomersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    CustomersExpanded = Table.ExpandRecordColumn(CustomersTable, "Column1", 
        {"id", "first_name", "last_name", "email", "mobile", "mobile_code", "city", 
         "country", "gender", "birthday", "avatar", "updated_at", "groups"}, 
        {"customer_id", "first_name", "last_name", "email", "mobile", "mobile_code", 
         "city", "country", "gender", "birthday", "avatar", "updated_at", "groups"}),

    // 4. CATEGORIES - Product categorization
    CategoriesData = CallSallaAPI("categories", 10),
    CategoriesTable = Table.FromList(CategoriesData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    CategoriesExpanded = Table.ExpandRecordColumn(CategoriesTable, "Column1", 
        {"id", "name", "image", "parent_id", "sort_order", "status", "metadata", "urls"}, 
        {"category_id", "category_name", "category_image", "parent_id", "sort_order", "status", "metadata", "urls"}),

    // 5. BRANDS - Brand management
    BrandsData = CallSallaAPI("brands", 10),
    BrandsTable = Table.FromList(BrandsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    BrandsExpanded = Table.ExpandRecordColumn(BrandsTable, "Column1", 
        {"id", "name", "description", "logo", "banner", "metadata"}, 
        {"brand_id", "brand_name", "brand_description", "brand_logo", "brand_banner", "brand_metadata"}),

    // 6. SHIPMENTS - Shipping and fulfillment
    ShipmentsData = CallSallaAPI("shipments", 10),
    ShipmentsTable = Table.FromList(ShipmentsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    ShipmentsExpanded = if List.Count(ShipmentsData) > 0 then
        Table.ExpandRecordColumn(ShipmentsTable, "Column1", 
            {"id", "tracking_number", "status", "company", "created_at"}, 
            {"shipment_id", "tracking_number", "shipment_status", "shipping_company", "created_at"})
        else Table.FromRecords({}),

    // 7. TRANSACTIONS - Payment records
    TransactionsData = CallSallaAPI("transactions", 10),
    TransactionsTable = Table.FromList(TransactionsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    TransactionsExpanded = if List.Count(TransactionsData) > 0 then
        Table.ExpandRecordColumn(TransactionsTable, "Column1", 
            {"id", "amount", "currency", "status", "payment_method", "created_at"}, 
            {"transaction_id", "amount", "currency", "transaction_status", "payment_method", "created_at"})
        else Table.FromRecords({}),

    // 8. SPECIAL OFFERS - Promotional campaigns
    SpecialOffersData = CallSallaAPI("special-offers", 5),
    SpecialOffersTable = Table.FromList(SpecialOffersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    SpecialOffersExpanded = if List.Count(SpecialOffersData) > 0 then
        Table.ExpandRecordColumn(SpecialOffersTable, "Column1", 
            {"id", "name", "type", "status", "start_date", "end_date"}, 
            {"offer_id", "offer_name", "offer_type", "offer_status", "start_date", "end_date"})
        else Table.FromRecords({}),

    // 9. COUPONS - Discount codes
    CouponsData = CallSallaAPI("coupons", 5),
    CouponsTable = Table.FromList(CouponsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    CouponsExpanded = if List.Count(CouponsData) > 0 then
        Table.ExpandRecordColumn(CouponsTable, "Column1", 
            {"id", "code", "type", "value", "status", "start_date", "end_date"}, 
            {"coupon_id", "coupon_code", "coupon_type", "coupon_value", "coupon_status", "start_date", "end_date"})
        else Table.FromRecords({}),

    // 10. REVIEWS - Customer feedback
    ReviewsData = CallSallaAPI("reviews", 5),
    ReviewsTable = Table.FromList(ReviewsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    ReviewsExpanded = if List.Count(ReviewsData) > 0 then
        Table.ExpandRecordColumn(ReviewsTable, "Column1", 
            {"id", "rating", "comment", "customer", "product", "created_at"}, 
            {"review_id", "rating", "comment", "customer", "product", "created_at"})
        else Table.FromRecords({}),

    // COMBINE ALL DATA INTO COMPREHENSIVE REPORT
    CombinedData = Table.FromRecords({
        [
            DataType = "Summary",
            TotalOrders = Table.RowCount(OrdersExpanded),
            TotalProducts = Table.RowCount(ProductsExpanded),
            TotalCustomers = Table.RowCount(CustomersExpanded),
            TotalCategories = Table.RowCount(CategoriesExpanded),
            TotalBrands = Table.RowCount(BrandsExpanded),
            TotalShipments = Table.RowCount(ShipmentsExpanded),
            TotalTransactions = Table.RowCount(TransactionsExpanded),
            TotalOffers = Table.RowCount(SpecialOffersExpanded),
            TotalCoupons = Table.RowCount(CouponsExpanded),
            TotalReviews = Table.RowCount(ReviewsExpanded),
            DataSource = "Salla API - Complete Collection",
            RetrievedAt = DateTime.LocalNow()
        ]
    })

in
    CombinedData
