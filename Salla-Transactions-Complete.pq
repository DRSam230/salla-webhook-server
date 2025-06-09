// Salla Transactions Complete Report - ALL PAYMENT DATA
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

    // Step 2: Get Transactions with Full Details
    GetTransactionsPage = (pageNum as number) =>
        let
            TransactionsResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/transactions?page=" & Number.ToText(pageNum) & "&per_page=50",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            TransactionsJson = Json.Document(TransactionsResponse)
        in
            TransactionsJson,

    // Get first page to determine total pages
    FirstPage = GetTransactionsPage(1),
    TotalPages = if FirstPage[pagination]? <> null then FirstPage[pagination][totalPages] else 1,
    
    // Generate list of all pages (limit to first 10 pages for performance)
    PageNumbers = List.Numbers(1, Number.Min(TotalPages, 10)),
    
    // Get all pages
    AllPages = List.Transform(PageNumbers, each GetTransactionsPage(_)),
    AllTransactionsData = List.Combine(List.Transform(AllPages, each if _[data]? <> null then _[data] else {})),
    
    // Step 3: Transform Transactions Data
    TransactionsTable = Table.FromList(AllTransactionsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    
    // Step 4: Expand main transaction fields (if data exists)
    TransactionsExpanded = if Table.RowCount(TransactionsTable) > 0 then
        Table.ExpandRecordColumn(TransactionsTable, "Column1", 
            {"id", "amount", "currency", "status", "payment_method", "order", "created_at", "updated_at", "reference_id"}, 
            {"TransactionID", "Amount", "Currency", "Status", "PaymentMethod", "Order", "CreatedAt", "UpdatedAt", "ReferenceID"})
    else
        Table.FromRecords({}),
    
    // Step 5: Extract comprehensive transaction fields (if data exists)
    FinalTransactionsReport = if Table.RowCount(TransactionsExpanded) > 0 then
        let
            // transaction_id
            AddTransactionID = Table.AddColumn(TransactionsExpanded, "transaction_id", each 
                if [TransactionID] <> null then [TransactionID] else null),
            
            // transaction_reference_id
            AddTransactionReferenceID = Table.AddColumn(AddTransactionID, "transaction_reference_id", each 
                if [ReferenceID] <> null then [ReferenceID] else null),
            
            // transaction_amount
            AddTransactionAmount = Table.AddColumn(AddTransactionReferenceID, "transaction_amount", each 
                if [Amount] <> null then [Amount] else null),
            
            // transaction_currency
            AddTransactionCurrency = Table.AddColumn(AddTransactionAmount, "transaction_currency", each 
                if [Currency] <> null then [Currency] else null),
            
            // transaction_status
            AddTransactionStatus = Table.AddColumn(AddTransactionCurrency, "transaction_status", each 
                if [Status] <> null then [Status] else null),
            
            // payment_method
            AddPaymentMethod = Table.AddColumn(AddTransactionStatus, "payment_method", each 
                if [PaymentMethod] <> null then [PaymentMethod] else null),
            
            // order_id
            AddOrderID = Table.AddColumn(AddPaymentMethod, "order_id", each 
                if [Order] <> null and [Order][id]? <> null then [Order][id] else null),
            
            // order_reference_id
            AddOrderReferenceID = Table.AddColumn(AddOrderID, "order_reference_id", each 
                if [Order] <> null and [Order][reference_id]? <> null then [Order][reference_id] else null),
            
            // transaction_created_date
            AddTransactionCreatedDate = Table.AddColumn(AddOrderReferenceID, "transaction_created_date", each 
                if [CreatedAt] <> null then [CreatedAt] else null),
            
            // transaction_updated_date
            AddTransactionUpdatedDate = Table.AddColumn(AddTransactionCreatedDate, "transaction_updated_date", each 
                if [UpdatedAt] <> null then [UpdatedAt] else null),
            
            // Select final columns
            SelectedColumns = Table.SelectColumns(AddTransactionUpdatedDate, {
                "transaction_id",
                "transaction_reference_id",
                "transaction_amount",
                "transaction_currency",
                "transaction_status",
                "payment_method",
                "order_id",
                "order_reference_id",
                "transaction_created_date",
                "transaction_updated_date"
            })
        in
            SelectedColumns
    else
        Table.FromRecords({[
            transaction_id = null,
            transaction_reference_id = "No transactions found",
            transaction_amount = null,
            transaction_currency = null,
            transaction_status = "No data",
            payment_method = null,
            order_id = null,
            order_reference_id = null,
            transaction_created_date = null,
            transaction_updated_date = null
        ]}),
    
    // Step 6: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(FinalTransactionsReport, "DataSource", each "Salla API - Transactions"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
