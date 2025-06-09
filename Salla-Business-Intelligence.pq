// SALLA BUSINESS INTELLIGENCE DASHBOARD - ADVANCED ANALYTICS
// Complete business analytics with KPIs, trends, and insights
// Import this file for executive-level reporting and analysis

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
                else error "Authentication failed. Please check your Salla app connection."
        in AccessToken,
    
    AccessToken = GetAccessToken(),
    
    // ==================== ENHANCED API CALL FUNCTION ====================
    CallSallaAPI = (endpoint as text, optional maxPages as number) =>
        let
            MaxPagesToFetch = if maxPages = null then 10 else maxPages,
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
                        Timeout = #duration(0, 0, 1, 0)
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
    
    // ==================== BUSINESS INTELLIGENCE FUNCTIONS ====================
    
    // 1. SALES ANALYTICS
    GetSalesAnalytics = () =>
        let
            OrdersData = CallSallaAPI("orders", 20),
            SalesTable = if List.Count(OrdersData) > 0 then
                let
                    BaseTable = Table.FromList(OrdersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                    ExpandedTable = Table.ExpandRecordColumn(BaseTable, "Column1", 
                        {"id", "reference_id", "date", "status", "amounts", "payment_method", "customer"}, 
                        {"order_id", "order_number", "order_date", "order_status", "amounts", "payment_method", "customer"}),
                    
                    // Calculate sales metrics
                    ProcessedTable = Table.AddColumn(
                        Table.AddColumn(
                            Table.AddColumn(
                                Table.AddColumn(ExpandedTable, "order_total", each 
                                    if [amounts] <> null and [amounts][total]? <> null then [amounts][total] else 0),
                                "order_month", each 
                                    if [order_date] <> null then Date.ToText(DateTime.Date(DateTime.FromText([order_date])), "yyyy-MM") else null),
                            "order_year", each 
                                if [order_date] <> null then Date.Year(DateTime.Date(DateTime.FromText([order_date]))) else null),
                        "is_completed", each 
                            if [order_status] <> null then ([order_status] = "completed" or [order_status] = "delivered") else false),
                    
                    // Filter completed orders for revenue calculation
                    CompletedOrders = Table.SelectRows(ProcessedTable, each [is_completed] = true),
                    
                    FinalTable = Table.SelectColumns(CompletedOrders, {
                        "order_id", "order_number", "order_date", "order_total", "order_month", "order_year", "payment_method"
                    })
                in FinalTable
            else Table.FromRecords({[order_id = null, order_number = "No sales data", order_date = null, 
                order_total = 0, order_month = null, order_year = null, payment_method = null]})
        in SalesTable,
    
    // 2. PRODUCT PERFORMANCE
    GetProductPerformance = () =>
        let
            ProductsData = CallSallaAPI("products", 25),
            ProductTable = if List.Count(ProductsData) > 0 then
                let
                    BaseTable = Table.FromList(ProductsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                    ExpandedTable = Table.ExpandRecordColumn(BaseTable, "Column1", 
                        {"id", "sku", "name", "price", "sale_price", "quantity", "sold_quantity", "brand", "categories"}, 
                        {"product_id", "product_sku", "product_name", "price", "sale_price", "stock_quantity", "sold_quantity", "brand", "categories"}),
                    
                    // Calculate performance metrics
                    ProcessedTable = Table.AddColumn(
                        Table.AddColumn(
                            Table.AddColumn(
                                Table.AddColumn(
                                    Table.AddColumn(ExpandedTable, "revenue_generated", each 
                                        if [sold_quantity] <> null and [price] <> null then [sold_quantity] * [price] else 0),
                                    "stock_status", each 
                                        if [stock_quantity] <> null then 
                                            (if [stock_quantity] = 0 then "Out of Stock" 
                                             else if [stock_quantity] < 10 then "Low Stock" 
                                             else "In Stock") else "Unknown"),
                                "performance_rating", each 
                                    if [sold_quantity] <> null then 
                                        (if [sold_quantity] > 100 then "High Performer"
                                         else if [sold_quantity] > 20 then "Good Performer"
                                         else if [sold_quantity] > 0 then "Low Performer"
                                         else "No Sales") else "No Data"),
                            "brand_name", each 
                                if [brand] <> null and [brand][name]? <> null then [brand][name] else "No Brand"),
                        "category_name", each 
                            if [categories] <> null and List.Count([categories]) > 0 and [categories]{0}[name]? <> null then [categories]{0}[name] else "Uncategorized"),
                    
                    FinalTable = Table.SelectColumns(ProcessedTable, {
                        "product_id", "product_sku", "product_name", "price", "stock_quantity", "sold_quantity",
                        "revenue_generated", "stock_status", "performance_rating", "brand_name", "category_name"
                    })
                in FinalTable
            else Table.FromRecords({[product_id = null, product_sku = "No products", product_name = "No data", 
                price = 0, stock_quantity = 0, sold_quantity = 0, revenue_generated = 0, 
                stock_status = "No data", performance_rating = "No data", brand_name = null, category_name = null]})
        in ProductTable,
    
    // 3. CUSTOMER INSIGHTS
    GetCustomerInsights = () =>
        let
            CustomersData = CallSallaAPI("customers", 15),
            OrdersData = CallSallaAPI("orders", 15),
            
            CustomerTable = if List.Count(CustomersData) > 0 then
                let
                    BaseCustomers = Table.FromList(CustomersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                    ExpandedCustomers = Table.ExpandRecordColumn(BaseCustomers, "Column1", 
                        {"id", "first_name", "last_name", "email", "city", "country", "updated_at"}, 
                        {"customer_id", "first_name", "last_name", "email", "city", "country", "last_activity"}),
                    
                    // Add customer analytics
                    ProcessedCustomers = Table.AddColumn(
                        Table.AddColumn(ExpandedCustomers, "customer_name", each 
                            if [first_name] <> null and [last_name] <> null then 
                                ([first_name] & " " & [last_name]) else "Unknown"),
                        "customer_location", each 
                            if [city] <> null and [country] <> null then 
                                ([city] & ", " & [country]) else 
                                (if [country] <> null then [country] else "Unknown")),
                    
                    FinalCustomers = Table.SelectColumns(ProcessedCustomers, {
                        "customer_id", "customer_name", "email", "customer_location", "last_activity"
                    })
                in FinalCustomers
            else Table.FromRecords({[customer_id = null, customer_name = "No customers", email = null, 
                customer_location = null, last_activity = null]})
        in CustomerTable,
    
    // 4. KEY PERFORMANCE INDICATORS (KPIs)
    GetKPIs = () =>
        let
            SalesData = GetSalesAnalytics(),
            ProductData = GetProductPerformance(),
            CustomerData = GetCustomerInsights(),
            
            // Calculate KPIs
            TotalRevenue = List.Sum(Table.Column(SalesData, "order_total")),
            TotalOrders = Table.RowCount(SalesData),
            TotalProducts = Table.RowCount(ProductData),
            TotalCustomers = Table.RowCount(CustomerData),
            AverageOrderValue = if TotalOrders > 0 then TotalRevenue / TotalOrders else 0,
            
            // Product insights
            OutOfStockProducts = Table.RowCount(Table.SelectRows(ProductData, each [stock_status] = "Out of Stock")),
            LowStockProducts = Table.RowCount(Table.SelectRows(ProductData, each [stock_status] = "Low Stock")),
            HighPerformers = Table.RowCount(Table.SelectRows(ProductData, each [performance_rating] = "High Performer")),
            
            KPITable = Table.FromRecords({
                [KPI = "Total Revenue", Value = TotalRevenue, Category = "Sales", Status = "✅"],
                [KPI = "Total Orders", Value = TotalOrders, Category = "Sales", Status = "✅"],
                [KPI = "Average Order Value", Value = AverageOrderValue, Category = "Sales", Status = "✅"],
                [KPI = "Total Products", Value = TotalProducts, Category = "Inventory", Status = "✅"],
                [KPI = "Out of Stock Products", Value = OutOfStockProducts, Category = "Inventory", Status = if OutOfStockProducts > 0 then "⚠️" else "✅"],
                [KPI = "Low Stock Products", Value = LowStockProducts, Category = "Inventory", Status = if LowStockProducts > 0 then "⚠️" else "✅"],
                [KPI = "High Performing Products", Value = HighPerformers, Category = "Performance", Status = "✅"],
                [KPI = "Total Customers", Value = TotalCustomers, Category = "Customers", Status = "✅"]
            })
        in KPITable
    
in
    // ==================== BUSINESS INTELLIGENCE DASHBOARD ====================
    [
        KPIs = GetKPIs(),
        SalesAnalytics = GetSalesAnalytics(),
        ProductPerformance = GetProductPerformance(),
        CustomerInsights = GetCustomerInsights(),
        DashboardSummary = Table.FromRecords({[
            Report = "Salla Business Intelligence Dashboard",
            GeneratedAt = DateTime.LocalNow(),
            MerchantID = MerchantId,
            DataSource = "Salla API v2",
            Status = "✅ Complete Analytics Ready",
            RecommendedActions = "Review KPIs, Monitor Low Stock, Analyze High Performers"
        ]})
    ]
