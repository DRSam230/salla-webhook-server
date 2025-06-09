// Salla Orders Comprehensive Report - Matches Your Exact Requirements
// Import this file into Excel Power Query
// Generated: Based on official Salla API documentation at https://docs.salla.dev/

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

    // Step 2: Get Orders with Full Details (expanded=true for complete data)
    GetOrdersPage = (pageNum as number) =>
        let
            OrdersResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/orders?page=" & Number.ToText(pageNum) & "&expanded=true&per_page=50",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            OrdersJson = Json.Document(OrdersResponse)
        in
            OrdersJson,

    // Get first page to determine total pages
    FirstPage = GetOrdersPage(1),
    TotalPages = if FirstPage[pagination]? <> null then FirstPage[pagination][totalPages] else 1,
    
    // Generate list of all pages (limit to first 10 pages for performance)
    PageNumbers = List.Numbers(1, Number.Min(TotalPages, 10)),
    
    // Get all pages
    AllPages = List.Transform(PageNumbers, each GetOrdersPage(_)),
    AllOrdersData = List.Combine(List.Transform(AllPages, each if _[data]? <> null then _[data] else {})),
    
    // Step 3: Transform Orders Data
    OrdersTable = Table.FromList(AllOrdersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    
    // Step 4: Expand main order fields
    ExpandedOrders = Table.ExpandRecordColumn(OrdersTable, "Column1", 
        {"id", "reference_id", "total", "date", "status", "payment_method", "customer", "items", "shipping"}, 
        {"OrderID", "ReferenceID", "Total", "Date", "Status", "PaymentMethod", "Customer", "Items", "Shipping"}),
    
    // Step 5: Extract YOUR REQUIRED FIELDS
    
    // order_number (reference_id)
    AddOrderNumber = Table.AddColumn(ExpandedOrders, "order_number", each 
        if [ReferenceID] <> null then [ReferenceID] else null),
    
    // order_date
    AddOrderDate = Table.AddColumn(AddOrderNumber, "order_date", each 
        if [Date] <> null then [Date][date] else null),
    
    // payment_method
    AddPaymentMethod = Table.AddColumn(AddOrderDate, "payment_method", each 
        if [PaymentMethod] <> null then [PaymentMethod] else null),
    
    // order_total
    AddOrderTotal = Table.AddColumn(AddPaymentMethod, "order_total", each 
        if [Total] <> null then [Total][amount] else null),
    
    // product_barcodes (for all products within the order)
    AddProductBarcodes = Table.AddColumn(AddOrderTotal, "product_barcodes", each 
        if [Items] <> null then 
            Text.Combine(
                List.Transform([Items], each 
                    if _[sku]? <> null then Text.From(_[sku]) else "N/A"
                ), "; "
            )
        else null),
    
    // product_quantities (for all products within the order)
    AddProductQuantities = Table.AddColumn(AddProductBarcodes, "product_quantities", each 
        if [Items] <> null then 
            Text.Combine(
                List.Transform([Items], each 
                    if _[quantity]? <> null then Text.From(_[quantity]) else "0"
                ), "; "
            )
        else null),
    
    // product_value (total value of products in the order)
    AddProductValue = Table.AddColumn(AddProductQuantities, "product_value", each 
        if [Items] <> null then 
            List.Sum(
                List.Transform([Items], each 
                    if _[price]? <> null and _[quantity]? <> null then 
                        _[price][amount] * _[quantity] 
                    else 0
                )
            )
        else null),
    
    // shipping_company
    AddShippingCompany = Table.AddColumn(AddProductValue, "shipping_company", each 
        if [Shipping] <> null and [Shipping][company]? <> null then 
            [Shipping][company][name] 
        else null),
    
    // order_status
    AddOrderStatus = Table.AddColumn(AddShippingCompany, "order_status", each 
        if [Status] <> null then [Status][name] else null),
    
    // shipping_city
    AddShippingCity = Table.AddColumn(AddOrderStatus, "shipping_city", each 
        if [Shipping] <> null and [Shipping][address]? <> null then 
            [Shipping][address][city] 
        else null),
    
    // shipping_address
    AddShippingAddress = Table.AddColumn(AddShippingCity, "shipping_address", each 
        if [Shipping] <> null and [Shipping][address]? <> null then 
            [Shipping][address][street] 
        else null),
    
    // customer_name
    AddCustomerName = Table.AddColumn(AddShippingAddress, "customer_name", each 
        if [Customer] <> null then 
            ([Customer][first_name] & " " & [Customer][last_name]) 
        else null),
    
    // customer_phone_number
    AddCustomerPhone = Table.AddColumn(AddCustomerName, "customer_phone_number", each 
        if [Customer] <> null then 
            ([Customer][mobile_code] & Text.From([Customer][mobile])) 
        else null),
    
    // Step 6: Select ONLY your required columns
    FinalOrdersReport = Table.SelectColumns(AddCustomerPhone, {
        "order_number",
        "order_date", 
        "payment_method",
        "order_total",
        "product_barcodes",
        "product_quantities", 
        "product_value",
        "shipping_company",
        "order_status",
        "shipping_city",
        "shipping_address", 
        "customer_name",
        "customer_phone_number"
    }),
    
    // Step 7: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(FinalOrdersReport, "DataSource", each "Salla API - Official"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
