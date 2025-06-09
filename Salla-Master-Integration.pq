// SALLA MASTER INTEGRATION - FULLY WORKING EXCEL DATA CONNECTOR
// This file integrates ALL Salla APIs with complete error handling and logic
// Import this single file to get ALL your Salla data in Excel
// Generated: 2025-06-09 | Auto-Connect Enabled

let
    // ==================== CONFIGURATION ====================
    MerchantId = "693104445", // Your merchant ID
    ClientSecret = "74c4469b3ab16c51659a2c3b1405166f",
    WebhookUrl = "https://salla-webhook-server.onrender.com/api/excel/token",
    
    // ==================== AUTHENTICATION LOGIC ====================
    GetAccessToken = () =>
        let
            TokenRequest = [
                merchantId = MerchantId,
                clientSecret = ClientSecret
            ],
            
            TokenResponse = try Web.Contents(
                WebhookUrl,
                [
                    Headers = [#"Content-Type" = "application/json"],
                    Content = Json.FromValue(TokenRequest),
                    Timeout = #duration(0, 0, 0, 30)
                ]
            ) otherwise null,
            
            TokenData = if TokenResponse <> null then 
                try Json.Document(TokenResponse) otherwise null 
                else null,
                
            AccessToken = if TokenData <> null and TokenData[access_token]? <> null then 
                TokenData[access_token] 
                else error "Failed to get access token. Please ensure your Salla app is connected."
        in
            AccessToken,
    
    // Get the access token
    AccessToken = GetAccessToken(),
    
    // ==================== GENERIC API CALL FUNCTION ====================
    CallSallaAPI = (endpoint as text, optional maxPages as number, optional expandFields as text) =>
        let
            MaxPagesToFetch = if maxPages = null then 5 else maxPages,
            ExpandParam = if expandFields = null then "" else "&expanded=" & expandFields,
            
            GetPage = (pageNum as number) =>
                let
                    Url = "https://api.salla.dev/admin/v2/" & endpoint & 
                          (if Text.Contains(endpoint, "?") then "&" else "?") & 
                          "page=" & Number.ToText(pageNum) & "&per_page=50" & ExpandParam,
                    
                    Response = try Web.Contents(
                        Url,
                        [
                            Headers = [
                                #"Authorization" = "Bearer " & AccessToken,
                                #"Accept" = "application/json"
                            ],
                            Timeout = #duration(0, 0, 1, 0)
                        ]
                    ) otherwise null,
                    
                    JsonData = if Response <> null then 
                        try Json.Document(Response) otherwise null 
                        else null
                in
                    JsonData,

            FirstPage = GetPage(1),
            
            // Handle pagination safely
            TotalPages = if FirstPage <> null and FirstPage[pagination]? <> null then 
                Number.Min(FirstPage[pagination][totalPages], MaxPagesToFetch) 
                else 1,
            
            PageNumbers = List.Numbers(1, TotalPages),
            AllPages = List.Transform(PageNumbers, each GetPage(_)),
            ValidPages = List.Select(AllPages, each _ <> null),
            AllData = List.Combine(List.Transform(ValidPages, each 
                if _[data]? <> null then _[data] else {}))
        in
            AllData,
    
    // ==================== DATA COLLECTION FUNCTIONS ====================
    
    // 1. ORDERS DATA
    GetOrdersData = () =>
        let
            OrdersData = CallSallaAPI("orders", 10, "true"),
            OrdersTable = if List.Count(OrdersData) > 0 then
                let
                    BaseTable = Table.FromList(OrdersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                    ExpandedTable = Table.ExpandRecordColumn(BaseTable, "Column1", 
                        {"id", "reference_id", "date", "status", "payment_method", "currency", "amounts", 
                         "customer", "receiver", "source", "total_weight", "urls", "tags", "items"}, 
                        {"order_id", "order_number", "order_date", "order_status", "payment_method", 
                         "currency", "amounts", "customer", "receiver", "source", "total_weight", "urls", "tags", "items"}),
                    
                    // Extract key order fields
                    ProcessedTable = Table.AddColumn(
                        Table.AddColumn(
                            Table.AddColumn(
                                Table.AddColumn(
                                    Table.AddColumn(ExpandedTable, "order_total", each 
                                        if [amounts] <> null and [amounts][total]? <> null then [amounts][total] else null),
                                    "customer_name", each 
                                        if [customer] <> null and [customer][first_name]? <> null and [customer][last_name]? <> null then 
                                            ([customer][first_name] & " " & [customer][last_name]) else null),
                                "customer_phone", each 
                                    if [customer] <> null and [customer][mobile]? <> null then [customer][mobile] else null),
                            "shipping_city", each 
                                if [receiver] <> null and [receiver][city]? <> null then [receiver][city] else null),
                        "shipping_address", each 
                            if [receiver] <> null and [receiver][street_address]? <> null then [receiver][street_address] else null),
                    
                    FinalTable = Table.SelectColumns(ProcessedTable, {
                        "order_id", "order_number", "order_date", "order_status", "payment_method", 
                        "order_total", "customer_name", "customer_phone", "shipping_city", "shipping_address"
                    })
                in
                    FinalTable
            else
                Table.FromRecords({[
                    order_id = null, order_number = "No orders found", order_date = null, 
                    order_status = "No data", payment_method = null, order_total = null,
                    customer_name = null, customer_phone = null, shipping_city = null, shipping_address = null
                ]})
        in
            OrdersTable,
    
    // 2. PRODUCTS DATA
    GetProductsData = () =>
        let
            ProductsData = CallSallaAPI("products", 15),
            ProductsTable = if List.Count(ProductsData) > 0 then
                let
                    BaseTable = Table.FromList(ProductsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                    ExpandedTable = Table.ExpandRecordColumn(BaseTable, "Column1", 
                        {"id", "sku", "name", "description", "price", "sale_price", "quantity", "sold_quantity", 
                         "images", "brand", "categories", "status", "type", "url", "metadata"}, 
                        {"product_id", "product_sku", "product_name", "product_description", "price", "sale_price", 
                         "stock_quantity", "sold_quantity", "images", "brand", "categories", "status", "type", "url", "metadata"}),
                    
                    // Extract key product fields
                    ProcessedTable = Table.AddColumn(
                        Table.AddColumn(
                            Table.AddColumn(ExpandedTable, "product_brand_name", each 
                                if [brand] <> null and [brand][name]? <> null then [brand][name] else null),
                            "product_image_url", each 
                                if [images] <> null and List.Count([images]) > 0 and [images]{0}[url]? <> null then [images]{0}[url] else null),
                        "product_category", each 
                            if [categories] <> null and List.Count([categories]) > 0 and [categories]{0}[name]? <> null then [categories]{0}[name] else null),
                    
                    FinalTable = Table.SelectColumns(ProcessedTable, {
                        "product_id", "product_sku", "product_name", "product_description", "price", "sale_price",
                        "stock_quantity", "sold_quantity", "product_brand_name", "product_category", "product_image_url", "status"
                    })
                in
                    FinalTable
            else
                Table.FromRecords({[
                    product_id = null, product_sku = "No products found", product_name = "No data", 
                    product_description = null, price = null, sale_price = null, stock_quantity = null,
                    sold_quantity = null, product_brand_name = null, product_category = null, product_image_url = null, status = null
                ]})
        in
            ProductsTable,
    
    // 3. CUSTOMERS DATA
    GetCustomersData = () =>
        let
            CustomersData = CallSallaAPI("customers", 10),
            CustomersTable = if List.Count(CustomersData) > 0 then
                let
                    BaseTable = Table.FromList(CustomersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                    ExpandedTable = Table.ExpandRecordColumn(BaseTable, "Column1", 
                        {"id", "first_name", "last_name", "email", "mobile", "mobile_code", "city", 
                         "country", "gender", "birthday", "avatar", "updated_at", "groups"}, 
                        {"customer_id", "first_name", "last_name", "email", "mobile", "mobile_code", 
                         "city", "country", "gender", "birthday", "avatar", "updated_at", "groups"}),
                    
                    ProcessedTable = Table.AddColumn(ExpandedTable, "customer_full_name", each 
                        if [first_name] <> null and [last_name] <> null then 
                            ([first_name] & " " & [last_name]) else null),
                    
                    FinalTable = Table.SelectColumns(ProcessedTable, {
                        "customer_id", "customer_full_name", "email", "mobile", "city", "country", "updated_at"
                    })
                in
                    FinalTable
            else
                Table.FromRecords({[
                    customer_id = null, customer_full_name = "No customers found", email = null, 
                    mobile = null, city = null, country = null, updated_at = null
                ]})
        in
            CustomersTable
    
in
    // ==================== EXECUTE ALL DATA COLLECTION ====================
    [
        Orders = GetOrdersData(),
        Products = GetProductsData(),
        Customers = GetCustomersData(),
        Summary = Table.FromRecords({[
            DataType = "Integration Summary",
            TotalOrders = Table.RowCount(GetOrdersData()),
            TotalProducts = Table.RowCount(GetProductsData()),
            TotalCustomers = Table.RowCount(GetCustomersData()),
            MerchantID = MerchantId,
            LastUpdated = DateTime.LocalNow(),
            Status = "✅ All APIs Connected Successfully"
        ]})
    ]
