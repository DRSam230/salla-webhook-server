// SALLA ORDER MANAGEMENT SYSTEM - COMPLETE ORDER PROCESSING
// Comprehensive order tracking, fulfillment, and customer management
// All your requested order fields with complete business logic

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
                else error "Order Management: Authentication failed. Please check your Salla app connection."
        in AccessToken,
    
    AccessToken = GetAccessToken(),
    
    // ==================== ENHANCED API FUNCTIONS ====================
    CallSallaAPI = (endpoint as text, optional maxPages as number) =>
        let
            MaxPagesToFetch = if maxPages = null then 15 else maxPages,
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
    
    // ==================== ORDER MANAGEMENT FUNCTIONS ====================
    
    // 1. COMPREHENSIVE ORDER DETAILS
    GetOrderDetails = () =>
        let
            OrdersData = CallSallaAPI("orders", 20),
            OrdersTable = if List.Count(OrdersData) > 0 then
                let
                    BaseTable = Table.FromList(OrdersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                    ExpandedTable = Table.ExpandRecordColumn(BaseTable, "Column1", 
                        {"id", "reference_id", "date", "status", "payment_method", "currency", "amounts", 
                         "customer", "receiver", "source", "total_weight", "urls", "tags", "items", "shipments"}, 
                        {"order_id", "order_number", "order_date", "order_status", "payment_method", 
                         "currency", "amounts", "customer", "receiver", "source", "total_weight", "urls", "tags", "items", "shipments"}),
                    
                    // Extract ALL requested order fields
                    ProcessedTable = Table.AddColumn(
                        Table.AddColumn(
                            Table.AddColumn(
                                Table.AddColumn(
                                    Table.AddColumn(
                                        Table.AddColumn(
                                            Table.AddColumn(
                                                Table.AddColumn(
                                                    Table.AddColumn(
                                                        Table.AddColumn(ExpandedTable, "order_total", each 
                                                            if [amounts] <> null and [amounts][total]? <> null then [amounts][total] else 0),
                                                        "customer_name", each 
                                                            if [customer] <> null and [customer][first_name]? <> null and [customer][last_name]? <> null then 
                                                                ([customer][first_name] & " " & [customer][last_name]) 
                                                            else if [customer] <> null and [customer][name]? <> null then [customer][name] else "Unknown Customer"),
                                                    "customer_phone_number", each 
                                                        if [customer] <> null and [customer][mobile]? <> null then [customer][mobile] 
                                                        else if [receiver] <> null and [receiver][phone]? <> null then [receiver][phone] else null),
                                                "shipping_city", each 
                                                    if [receiver] <> null and [receiver][city]? <> null then [receiver][city] else null),
                                            "shipping_address", each 
                                                if [receiver] <> null and [receiver][street_address]? <> null then [receiver][street_address] else null),
                                        "shipping_company", each 
                                            if [shipments] <> null and List.Count([shipments]) > 0 and [shipments]{0}[company]? <> null and [shipments]{0}[company][name]? <> null then 
                                                [shipments]{0}[company][name] else "Not Assigned"),
                                    "product_barcodes", each 
                                        if [items] <> null and List.Count([items]) > 0 then 
                                            Text.Combine(List.Transform([items], each if _[sku]? <> null then _[sku] else ""), ", ") else null),
                                "product_quantities", each 
                                    if [items] <> null and List.Count([items]) > 0 then 
                                        Text.Combine(List.Transform([items], each if _[quantity]? <> null then Text.From(_[quantity]) else "0"), ", ") else null),
                            "product_value", each 
                                if [items] <> null and List.Count([items]) > 0 then 
                                    List.Sum(List.Transform([items], each if _[price]? <> null and _[quantity]? <> null then _[price] * _[quantity] else 0)) else 0),
                        "order_priority", each 
                            if [order_status] = "pending" then "High"
                            else if [order_status] = "processing" then "Medium"
                            else if [order_status] = "shipped" then "Low"
                            else "Normal"),
                    
                    // Add business logic fields
                    EnhancedTable = Table.AddColumn(
                        Table.AddColumn(
                            Table.AddColumn(
                                Table.AddColumn(ProcessedTable, "days_since_order", each 
                                    if [order_date] <> null then 
                                        Duration.Days(DateTime.LocalNow() - DateTime.FromText([order_date])) else null),
                                "fulfillment_status", each 
                                    if [order_status] = "completed" or [order_status] = "delivered" then "✅ Fulfilled"
                                    else if [order_status] = "shipped" then "🚚 In Transit"
                                    else if [order_status] = "processing" then "📦 Processing"
                                    else if [order_status] = "pending" then "⏳ Pending"
                                    else "❓ Unknown"),
                            "revenue_impact", each 
                                if [order_total] <> null then 
                                    (if [order_total] > 1000 then "High Value"
                                     else if [order_total] > 500 then "Medium Value"
                                     else if [order_total] > 100 then "Standard Value"
                                     else "Low Value") else "No Value"),
                        "requires_attention", each 
                            ([days_since_order] <> null and [days_since_order] > 7 and [order_status] = "pending") or
                            ([order_status] = "processing" and [days_since_order] <> null and [days_since_order] > 3)),
                    
                    FinalTable = Table.SelectColumns(EnhancedTable, {
                        "order_id", "order_number", "order_date", "order_status", "payment_method", "order_total",
                        "customer_name", "customer_phone_number", "shipping_city", "shipping_address", "shipping_company",
                        "product_barcodes", "product_quantities", "product_value", "fulfillment_status", 
                        "revenue_impact", "order_priority", "days_since_order", "requires_attention"
                    })
                in FinalTable
            else Table.FromRecords({[
                order_id = null, order_number = "No orders found", order_date = null, order_status = "No data",
                payment_method = null, order_total = 0, customer_name = null, customer_phone_number = null,
                shipping_city = null, shipping_address = null, shipping_company = null, product_barcodes = null,
                product_quantities = null, product_value = 0, fulfillment_status = "No data", revenue_impact = null,
                order_priority = null, days_since_order = null, requires_attention = false
            ]})
        in OrdersTable,
    
    // 2. ORDER ANALYTICS & INSIGHTS
    GetOrderAnalytics = () =>
        let
            OrderDetails = GetOrderDetails(),
            
            // Calculate order analytics
            TotalOrders = Table.RowCount(OrderDetails),
            PendingOrders = Table.RowCount(Table.SelectRows(OrderDetails, each [order_status] = "pending")),
            ProcessingOrders = Table.RowCount(Table.SelectRows(OrderDetails, each [order_status] = "processing")),
            CompletedOrders = Table.RowCount(Table.SelectRows(OrderDetails, each [order_status] = "completed")),
            OrdersRequiringAttention = Table.RowCount(Table.SelectRows(OrderDetails, each [requires_attention] = true)),
            
            TotalRevenue = List.Sum(Table.Column(OrderDetails, "order_total")),
            AverageOrderValue = if TotalOrders > 0 then TotalRevenue / TotalOrders else 0,
            
            AnalyticsTable = Table.FromRecords({
                [Metric = "Total Orders", Value = TotalOrders, Category = "Volume", Status = "✅"],
                [Metric = "Pending Orders", Value = PendingOrders, Category = "Status", Status = if PendingOrders > 0 then "⏳" else "✅"],
                [Metric = "Processing Orders", Value = ProcessingOrders, Category = "Status", Status = if ProcessingOrders > 0 then "📦" else "✅"],
                [Metric = "Completed Orders", Value = CompletedOrders, Category = "Status", Status = "✅"],
                [Metric = "Orders Requiring Attention", Value = OrdersRequiringAttention, Category = "Alerts", Status = if OrdersRequiringAttention > 0 then "🚨" else "✅"],
                [Metric = "Total Revenue", Value = TotalRevenue, Category = "Financial", Status = "💰"],
                [Metric = "Average Order Value", Value = AverageOrderValue, Category = "Financial", Status = "📊"]
            })
        in AnalyticsTable,
    
    // 3. CUSTOMER ORDER HISTORY
    GetCustomerOrderHistory = () =>
        let
            OrderDetails = GetOrderDetails(),
            
            CustomerSummary = Table.Group(OrderDetails, {"customer_name"}, {
                {"total_orders", each Table.RowCount(_), Int64.Type},
                {"total_spent", each List.Sum([order_total]), type number},
                {"last_order_date", each List.Max([order_date]), type text},
                {"average_order_value", each List.Average([order_total]), type number},
                {"customer_status", each 
                    let totalSpent = List.Sum([order_total])
                    in if totalSpent > 5000 then "VIP Customer"
                       else if totalSpent > 2000 then "Premium Customer"
                       else if totalSpent > 500 then "Regular Customer"
                       else "New Customer", type text}
            }),
            
            EnhancedCustomerSummary = Table.AddColumn(CustomerSummary, "customer_lifetime_value", each 
                if [total_orders] > 0 then [total_spent] / [total_orders] else 0)
        in EnhancedCustomerSummary
    
in
    // ==================== ORDER MANAGEMENT DASHBOARD ====================
    [
        OrderDetails = GetOrderDetails(),
        OrderAnalytics = GetOrderAnalytics(),
        CustomerOrderHistory = GetCustomerOrderHistory(),
        ManagementSummary = Table.FromRecords({[
            System = "Salla Order Management System",
            GeneratedAt = DateTime.LocalNow(),
            MerchantID = MerchantId,
            TotalOrdersProcessed = Table.RowCount(GetOrderDetails()),
            Status = "✅ Complete Order Management Ready",
            Features = "Order Tracking, Customer History, Analytics, Alerts"
        ]})
    ]
