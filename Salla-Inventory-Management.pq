// SALLA INVENTORY MANAGEMENT SYSTEM - COMPLETE STOCK CONTROL
// Advanced inventory tracking, stock alerts, and product performance
// All your requested product fields with complete business logic

let
    // ==================== CONFIGURATION ====================
    MerchantId = "693104445",
    ClientSecret = "74c4469b3ab16c51659a2c3b1405166f",
    WebhookUrl = "https://salla-webhook-server.onrender.com/api/excel/token",
    
    // ==================== AUTHENTICATION ====================
    GetAccessToken = () =>
        let
            TokenRequest = [merchantId = MerchantId, clientSecret = ClientSecret],
            TokenResponse = try Web.Contents(WebhookUrl, [
                Headers = [#"Content-Type" = "application/json"],
                Content = Json.FromValue(TokenRequest),
                Timeout = #duration(0, 0, 0, 30)
            ]) otherwise null,
            TokenData = if TokenResponse <> null then try Json.Document(TokenResponse) otherwise null else null,
            AccessToken = if TokenData <> null and TokenData[access_token]? <> null then TokenData[access_token] 
                else error "Inventory Management: Authentication failed. Please check your Salla app connection."
        in AccessToken,
    
    AccessToken = GetAccessToken(),
    
    // ==================== API FUNCTIONS ====================
    CallSallaAPI = (endpoint as text, optional maxPages as number) =>
        let
            MaxPagesToFetch = if maxPages = null then 25 else maxPages,
            GetPage = (pageNum as number) =>
                let
                    Url = "https://api.salla.dev/admin/v2/" & endpoint & 
                          (if Text.Contains(endpoint, "?") then "&" else "?") & 
                          "page=" & Number.ToText(pageNum) & "&per_page=50",
                    Response = try Web.Contents(Url, [
                        Headers = [
                            #"Authorization" = "Bearer " & AccessToken,
                            #"Accept" = "application/json"
                        ],
                        Timeout = #duration(0, 0, 1, 30)
                    ]) otherwise null,
                    JsonData = if Response <> null then try Json.Document(Response) otherwise null else null
                in JsonData,
            
            FirstPage = GetPage(1),
            TotalPages = if FirstPage <> null and FirstPage[pagination]? <> null then 
                Number.Min(FirstPage[pagination][totalPages], MaxPagesToFetch) else 1,
            PageNumbers = List.Numbers(1, TotalPages),
            AllPages = List.Transform(PageNumbers, each GetPage(_)),
            ValidPages = List.Select(AllPages, each _ <> null),
            AllData = List.Combine(List.Transform(ValidPages, each if _[data]? <> null then _[data] else {}))
        in AllData,
    
    // ==================== INVENTORY MANAGEMENT FUNCTIONS ====================
    
    // 1. COMPREHENSIVE PRODUCT INVENTORY
    GetProductInventory = () =>
        let
            ProductsData = CallSallaAPI("products", 30),
            CategoriesData = CallSallaAPI("categories", 10),
            BrandsData = CallSallaAPI("brands", 10),
            
            ProductsTable = if List.Count(ProductsData) > 0 then
                let
                    BaseTable = Table.FromList(ProductsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                    ExpandedTable = Table.ExpandRecordColumn(BaseTable, "Column1", 
                        {"id", "sku", "name", "description", "price", "sale_price", "quantity", "sold_quantity", 
                         "images", "brand", "categories", "status", "type", "url", "metadata", "weight", "dimensions"}, 
                        {"product_id", "product_code", "product_name", "product_description", "price", "price_offer", 
                         "current_stock_level", "total_sold_quantity", "images", "brand", "categories", "product_status", 
                         "product_type", "product_page_link", "product_meta_data", "weight", "dimensions"}),
                    
                    // Extract ALL requested product fields
                    ProcessedTable = Table.AddColumn(
                        Table.AddColumn(
                            Table.AddColumn(
                                Table.AddColumn(
                                    Table.AddColumn(
                                        Table.AddColumn(
                                            Table.AddColumn(
                                                Table.AddColumn(
                                                    Table.AddColumn(
                                                        Table.AddColumn(
                                                            Table.AddColumn(ExpandedTable, "product_barcode", each 
                                                                if [product_code] <> null then [product_code] else "No Barcode"),
                                                            "product_mpn", each 
                                                                if [product_meta_data] <> null and [product_meta_data][mpn]? <> null then [product_meta_data][mpn] 
                                                                else if [product_code] <> null then [product_code] else "No MPN"),
                                                        "product_image_link", each 
                                                            if [images] <> null and List.Count([images]) > 0 and [images]{0}[url]? <> null then [images]{0}[url] else null),
                                                    "vat_status", each 
                                                        if [product_meta_data] <> null and [product_meta_data][vat_included]? <> null then 
                                                            (if [product_meta_data][vat_included] then "VAT Included" else "VAT Excluded") else "Unknown"),
                                                "product_brand", each 
                                                    if [brand] <> null and [brand][name]? <> null then [brand][name] else "No Brand"),
                                            "product_alt_text", each 
                                                if [images] <> null and List.Count([images]) > 0 and [images]{0}[alt]? <> null then [images]{0}[alt] 
                                                else if [product_name] <> null then [product_name] else "No Alt Text"),
                                        "product_seo_data", each 
                                            if [product_meta_data] <> null and [product_meta_data][seo_title]? <> null then [product_meta_data][seo_title] 
                                            else if [product_name] <> null then [product_name] else null),
                                    "linked_coupons", each 
                                        if [product_meta_data] <> null and [product_meta_data][coupons]? <> null then 
                                            Text.Combine(List.Transform([product_meta_data][coupons], each Text.From(_)), ", ") else "None"),
                                "categories", each 
                                    if [categories] <> null and List.Count([categories]) > 0 then 
                                        Text.Combine(List.Transform([categories], each if _[name]? <> null then _[name] else ""), ", ") else "Uncategorized"),
                            "stock_alert_level", each 
                                if [current_stock_level] <> null then 
                                    (if [current_stock_level] = 0 then "🔴 Out of Stock"
                                     else if [current_stock_level] < 5 then "🟡 Critical Low"
                                     else if [current_stock_level] < 20 then "🟠 Low Stock"
                                     else "🟢 In Stock") else "❓ Unknown"),
                        "inventory_value", each 
                            if [current_stock_level] <> null and [price] <> null then [current_stock_level] * [price] else 0),
                    
                    // Add advanced inventory analytics
                    EnhancedTable = Table.AddColumn(
                        Table.AddColumn(
                            Table.AddColumn(
                                Table.AddColumn(
                                    Table.AddColumn(ProcessedTable, "sales_velocity", each 
                                        if [total_sold_quantity] <> null and [total_sold_quantity] > 0 then 
                                            (if [total_sold_quantity] > 100 then "Fast Moving"
                                             else if [total_sold_quantity] > 20 then "Medium Moving"
                                             else "Slow Moving") else "No Sales"),
                                    "reorder_recommendation", each 
                                        if [current_stock_level] <> null and [total_sold_quantity] <> null then 
                                            (if [current_stock_level] < ([total_sold_quantity] / 10) then "Reorder Now"
                                             else if [current_stock_level] < ([total_sold_quantity] / 5) then "Reorder Soon"
                                             else "Stock OK") else "Review Needed"),
                                "profit_margin", each 
                                    if [price] <> null and [price_offer] <> null and [price] > 0 then 
                                        (([price] - [price_offer]) / [price]) * 100 else 0),
                            "performance_score", each 
                                let 
                                    stockScore = if [current_stock_level] <> null and [current_stock_level] > 0 then 25 else 0,
                                    salesScore = if [total_sold_quantity] <> null then Number.Min([total_sold_quantity], 50) else 0,
                                    priceScore = if [price] <> null and [price] > 0 then 25 else 0
                                in stockScore + salesScore + priceScore),
                        "requires_attention", each 
                            ([current_stock_level] <> null and [current_stock_level] < 5) or
                            ([total_sold_quantity] <> null and [total_sold_quantity] = 0 and [current_stock_level] <> null and [current_stock_level] > 50)),
                    
                    FinalTable = Table.SelectColumns(EnhancedTable, {
                        "product_id", "product_code", "product_barcode", "product_mpn", "product_name", "product_description",
                        "product_image_link", "vat_status", "product_brand", "product_meta_data", "product_alt_text",
                        "product_seo_data", "price", "price_offer", "linked_coupons", "categories", "current_stock_level",
                        "total_sold_quantity", "product_type", "product_status", "product_page_link", "stock_alert_level",
                        "inventory_value", "sales_velocity", "reorder_recommendation", "profit_margin", "performance_score", "requires_attention"
                    })
                in FinalTable
            else Table.FromRecords({[
                product_id = null, product_code = "No products found", product_barcode = null, product_mpn = null,
                product_name = "No data", product_description = null, product_image_link = null, vat_status = null,
                product_brand = null, product_meta_data = null, product_alt_text = null, product_seo_data = null,
                price = 0, price_offer = 0, linked_coupons = null, categories = null, current_stock_level = 0,
                total_sold_quantity = 0, product_type = null, product_status = null, product_page_link = null,
                stock_alert_level = "No data", inventory_value = 0, sales_velocity = null, reorder_recommendation = null,
                profit_margin = 0, performance_score = 0, requires_attention = false
            ]})
        in ProductsTable,
    
    // 2. INVENTORY ANALYTICS & ALERTS
    GetInventoryAnalytics = () =>
        let
            ProductInventory = GetProductInventory(),
            
            // Calculate inventory metrics
            TotalProducts = Table.RowCount(ProductInventory),
            OutOfStockProducts = Table.RowCount(Table.SelectRows(ProductInventory, each Text.Contains([stock_alert_level], "Out of Stock"))),
            LowStockProducts = Table.RowCount(Table.SelectRows(ProductInventory, each Text.Contains([stock_alert_level], "Low"))),
            OverstockedProducts = Table.RowCount(Table.SelectRows(ProductInventory, each [requires_attention] = true and [current_stock_level] > 50)),
            
            TotalInventoryValue = List.Sum(Table.Column(ProductInventory, "inventory_value")),
            FastMovingProducts = Table.RowCount(Table.SelectRows(ProductInventory, each [sales_velocity] = "Fast Moving")),
            SlowMovingProducts = Table.RowCount(Table.SelectRows(ProductInventory, each [sales_velocity] = "Slow Moving")),
            
            AnalyticsTable = Table.FromRecords({
                [Metric = "Total Products", Value = TotalProducts, Category = "Inventory", Status = "📦"],
                [Metric = "Out of Stock Products", Value = OutOfStockProducts, Category = "Alerts", Status = if OutOfStockProducts > 0 then "🔴" else "✅"],
                [Metric = "Low Stock Products", Value = LowStockProducts, Category = "Alerts", Status = if LowStockProducts > 0 then "🟡" else "✅"],
                [Metric = "Overstocked Products", Value = OverstockedProducts, Category = "Alerts", Status = if OverstockedProducts > 0 then "🟠" else "✅"],
                [Metric = "Total Inventory Value", Value = TotalInventoryValue, Category = "Financial", Status = "💰"],
                [Metric = "Fast Moving Products", Value = FastMovingProducts, Category = "Performance", Status = "🚀"],
                [Metric = "Slow Moving Products", Value = SlowMovingProducts, Category = "Performance", Status = if SlowMovingProducts > 0 then "🐌" else "✅"]
            })
        in AnalyticsTable,
    
    // 3. REORDER RECOMMENDATIONS
    GetReorderRecommendations = () =>
        let
            ProductInventory = GetProductInventory(),
            ReorderProducts = Table.SelectRows(ProductInventory, each [reorder_recommendation] = "Reorder Now" or [reorder_recommendation] = "Reorder Soon"),
            
            ReorderTable = Table.SelectColumns(ReorderProducts, {
                "product_id", "product_name", "product_code", "current_stock_level", "total_sold_quantity",
                "reorder_recommendation", "sales_velocity", "product_brand", "categories"
            })
        in ReorderTable
    
in
    // ==================== INVENTORY MANAGEMENT DASHBOARD ====================
    [
        ProductInventory = GetProductInventory(),
        InventoryAnalytics = GetInventoryAnalytics(),
        ReorderRecommendations = GetReorderRecommendations(),
        InventorySummary = Table.FromRecords({[
            System = "Salla Inventory Management System",
            GeneratedAt = DateTime.LocalNow(),
            MerchantID = MerchantId,
            TotalProductsManaged = Table.RowCount(GetProductInventory()),
            Status = "✅ Complete Inventory Management Ready",
            Features = "Stock Tracking, Alerts, Reorder Recommendations, Performance Analytics"
        ]})
    ]
