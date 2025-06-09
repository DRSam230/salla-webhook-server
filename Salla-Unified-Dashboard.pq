// SALLA UNIFIED DASHBOARD - COMPLETE BUSINESS OVERVIEW
// Single file that provides executive dashboard with all key metrics
// Perfect for management reporting and business intelligence

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
                else error "Dashboard: Authentication failed. Please check your Salla app connection."
        in AccessToken,
    
    AccessToken = GetAccessToken(),
    
    // ==================== UNIFIED API FUNCTION ====================
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
    
    // ==================== DASHBOARD FUNCTIONS ====================
    
    // 1. EXECUTIVE SUMMARY
    GetExecutiveSummary = () =>
        let
            OrdersData = CallSallaAPI("orders", 15),
            ProductsData = CallSallaAPI("products", 20),
            CustomersData = CallSallaAPI("customers", 10),
            
            // Calculate key metrics
            TotalOrders = List.Count(OrdersData),
            TotalProducts = List.Count(ProductsData),
            TotalCustomers = List.Count(CustomersData),
            
            // Revenue calculation
            OrdersWithAmounts = List.Select(OrdersData, each _[amounts]? <> null and _[amounts][total]? <> null),
            TotalRevenue = List.Sum(List.Transform(OrdersWithAmounts, each _[amounts][total])),
            AverageOrderValue = if TotalOrders > 0 then TotalRevenue / TotalOrders else 0,
            
            // Product metrics
            ProductsWithStock = List.Select(ProductsData, each _[quantity]? <> null),
            TotalInventoryItems = List.Sum(List.Transform(ProductsWithStock, each _[quantity])),
            OutOfStockCount = List.Count(List.Select(ProductsData, each _[quantity]? <> null and _[quantity] = 0)),
            
            // Order status analysis
            PendingOrders = List.Count(List.Select(OrdersData, each _[status]? <> null and _[status] = "pending")),
            CompletedOrders = List.Count(List.Select(OrdersData, each _[status]? <> null and (_[status] = "completed" or _[status] = "delivered"))),
            
            SummaryTable = Table.FromRecords({
                [KPI = "Total Revenue", Value = TotalRevenue, Format = "Currency", Trend = "📈", Priority = "High"],
                [KPI = "Total Orders", Value = TotalOrders, Format = "Number", Trend = "📊", Priority = "High"],
                [KPI = "Average Order Value", Value = AverageOrderValue, Format = "Currency", Trend = "💰", Priority = "Medium"],
                [KPI = "Total Products", Value = TotalProducts, Format = "Number", Trend = "📦", Priority = "Medium"],
                [KPI = "Total Customers", Value = TotalCustomers, Format = "Number", Trend = "👥", Priority = "Medium"],
                [KPI = "Inventory Items", Value = TotalInventoryItems, Format = "Number", Trend = "📋", Priority = "Low"],
                [KPI = "Out of Stock Products", Value = OutOfStockCount, Format = "Number", Trend = if OutOfStockCount > 0 then "⚠️" else "✅", Priority = if OutOfStockCount > 0 then "High" else "Low"],
                [KPI = "Pending Orders", Value = PendingOrders, Format = "Number", Trend = if PendingOrders > 0 then "⏳" else "✅", Priority = if PendingOrders > 5 then "High" else "Medium"],
                [KPI = "Completed Orders", Value = CompletedOrders, Format = "Number", Trend = "✅", Priority = "Low"]
            })
        in SummaryTable,
    
    // 2. SALES PERFORMANCE
    GetSalesPerformance = () =>
        let
            OrdersData = CallSallaAPI("orders", 20),
            
            SalesTable = if List.Count(OrdersData) > 0 then
                let
                    OrdersWithDetails = List.Select(OrdersData, each 
                        _[amounts]? <> null and _[amounts][total]? <> null and _[date]? <> null),
                    
                    SalesRecords = List.Transform(OrdersWithDetails, each [
                        order_id = _[id],
                        order_date = _[date],
                        order_total = _[amounts][total],
                        order_status = _[status],
                        payment_method = _[payment_method],
                        order_month = Date.ToText(DateTime.Date(DateTime.FromText(_[date])), "yyyy-MM")
                    ]),
                    
                    SalesBaseTable = Table.FromRecords(SalesRecords),
                    
                    // Add performance indicators
                    EnhancedSales = Table.AddColumn(
                        Table.AddColumn(SalesBaseTable, "revenue_category", each 
                            if [order_total] > 1000 then "High Value"
                            else if [order_total] > 500 then "Medium Value"
                            else "Standard Value"),
                        "days_since_order", each 
                            Duration.Days(DateTime.LocalNow() - DateTime.FromText([order_date])))
                in EnhancedSales
            else Table.FromRecords({[
                order_id = null, order_date = null, order_total = 0, order_status = "No data",
                payment_method = null, order_month = null, revenue_category = null, days_since_order = null
            ]})
        in SalesTable,
    
    // 3. INVENTORY ALERTS
    GetInventoryAlerts = () =>
        let
            ProductsData = CallSallaAPI("products", 25),
            
            AlertsTable = if List.Count(ProductsData) > 0 then
                let
                    ProductsWithStock = List.Select(ProductsData, each _[quantity]? <> null),
                    
                    AlertRecords = List.Transform(ProductsWithStock, each [
                        product_id = _[id],
                        product_name = _[name],
                        product_sku = _[sku],
                        current_stock = _[quantity],
                        sold_quantity = if _[sold_quantity]? <> null then _[sold_quantity] else 0,
                        alert_level = if _[quantity] = 0 then "🔴 Out of Stock"
                                     else if _[quantity] < 5 then "🟡 Critical Low"
                                     else if _[quantity] < 20 then "🟠 Low Stock"
                                     else "🟢 In Stock",
                        requires_action = _[quantity] < 10
                    ]),
                    
                    AlertsBaseTable = Table.FromRecords(AlertRecords),
                    CriticalAlerts = Table.SelectRows(AlertsBaseTable, each [requires_action] = true)
                in CriticalAlerts
            else Table.FromRecords({[
                product_id = null, product_name = "No products", product_sku = null,
                current_stock = 0, sold_quantity = 0, alert_level = "No data", requires_action = false
            ]})
        in AlertsTable,
    
    // 4. CUSTOMER INSIGHTS
    GetCustomerInsights = () =>
        let
            CustomersData = CallSallaAPI("customers", 15),
            OrdersData = CallSallaAPI("orders", 15),
            
            CustomerTable = if List.Count(CustomersData) > 0 then
                let
                    CustomerRecords = List.Transform(CustomersData, each [
                        customer_id = _[id],
                        customer_name = if _[first_name]? <> null and _[last_name]? <> null then 
                            (_[first_name] & " " & _[last_name]) else "Unknown",
                        customer_email = _[email],
                        customer_city = _[city],
                        customer_country = _[country],
                        registration_date = _[updated_at]
                    ]),
                    
                    CustomerBaseTable = Table.FromRecords(CustomerRecords)
                in CustomerBaseTable
            else Table.FromRecords({[
                customer_id = null, customer_name = "No customers", customer_email = null,
                customer_city = null, customer_country = null, registration_date = null
            ]})
        in CustomerTable,
    
    // 5. BUSINESS HEALTH SCORE
    GetBusinessHealthScore = () =>
        let
            ExecutiveSummary = GetExecutiveSummary(),
            InventoryAlerts = GetInventoryAlerts(),
            
            // Calculate health metrics
            TotalRevenue = List.First(Table.SelectRows(ExecutiveSummary, each [KPI] = "Total Revenue")[Value]),
            OutOfStockCount = List.First(Table.SelectRows(ExecutiveSummary, each [KPI] = "Out of Stock Products")[Value]),
            PendingOrders = List.First(Table.SelectRows(ExecutiveSummary, each [KPI] = "Pending Orders")[Value]),
            CriticalAlerts = Table.RowCount(InventoryAlerts),
            
            // Score calculation (0-100)
            RevenueScore = Number.Min(if TotalRevenue > 10000 then 30 else (TotalRevenue / 10000) * 30, 30),
            InventoryScore = Number.Max(30 - (OutOfStockCount * 5), 0),
            OrderScore = Number.Max(25 - (PendingOrders * 2), 0),
            AlertScore = Number.Max(15 - (CriticalAlerts * 3), 0),
            
            TotalScore = RevenueScore + InventoryScore + OrderScore + AlertScore,
            HealthStatus = if TotalScore >= 80 then "🟢 Excellent"
                          else if TotalScore >= 60 then "🟡 Good"
                          else if TotalScore >= 40 then "🟠 Needs Attention"
                          else "🔴 Critical",
            
            HealthTable = Table.FromRecords({[
                Metric = "Business Health Score",
                Score = TotalScore,
                Status = HealthStatus,
                Revenue_Component = RevenueScore,
                Inventory_Component = InventoryScore,
                Orders_Component = OrderScore,
                Alerts_Component = AlertScore,
                Recommendations = if TotalScore < 60 then "Review inventory levels and pending orders" else "Business performing well"
            ]})
        in HealthTable
    
in
    // ==================== UNIFIED DASHBOARD OUTPUT ====================
    [
        ExecutiveSummary = GetExecutiveSummary(),
        SalesPerformance = GetSalesPerformance(),
        InventoryAlerts = GetInventoryAlerts(),
        CustomerInsights = GetCustomerInsights(),
        BusinessHealthScore = GetBusinessHealthScore(),
        DashboardInfo = Table.FromRecords({[
            Dashboard = "Salla Unified Business Dashboard",
            GeneratedAt = DateTime.LocalNow(),
            MerchantID = MerchantId,
            DataSources = "Orders, Products, Customers, Inventory",
            Status = "✅ Complete Dashboard Ready",
            RefreshRecommendation = "Refresh every 4 hours for optimal insights"
        ]})
    ]
