// Salla Reviews Complete Report - ALL CUSTOMER FEEDBACK DATA
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

    // Step 2: Get Reviews with Full Details
    GetReviewsPage = (pageNum as number) =>
        let
            ReviewsResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/reviews?page=" & Number.ToText(pageNum) & "&per_page=50",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            ReviewsJson = Json.Document(ReviewsResponse)
        in
            ReviewsJson,

    // Get first page to determine total pages
    FirstPage = GetReviewsPage(1),
    TotalPages = if FirstPage[pagination]? <> null then FirstPage[pagination][totalPages] else 1,
    
    // Generate list of all pages (limit to first 10 pages for performance)
    PageNumbers = List.Numbers(1, Number.Min(TotalPages, 10)),
    
    // Get all pages
    AllPages = List.Transform(PageNumbers, each GetReviewsPage(_)),
    AllReviewsData = List.Combine(List.Transform(AllPages, each if _[data]? <> null then _[data] else {})),
    
    // Step 3: Transform Reviews Data
    ReviewsTable = Table.FromList(AllReviewsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    
    // Step 4: Expand main review fields (if data exists)
    ReviewsExpanded = if Table.RowCount(ReviewsTable) > 0 then
        Table.ExpandRecordColumn(ReviewsTable, "Column1", 
            {"id", "rating", "comment", "status", "customer", "product", "order", "created_at", "updated_at"}, 
            {"ReviewID", "Rating", "Comment", "Status", "Customer", "Product", "Order", "CreatedAt", "UpdatedAt"})
    else
        Table.FromRecords({}),
    
    // Step 5: Extract comprehensive review fields (if data exists)
    FinalReviewsReport = if Table.RowCount(ReviewsExpanded) > 0 then
        let
            // review_id
            AddReviewID = Table.AddColumn(ReviewsExpanded, "review_id", each 
                if [ReviewID] <> null then [ReviewID] else null),
            
            // review_rating
            AddReviewRating = Table.AddColumn(AddReviewID, "review_rating", each 
                if [Rating] <> null then [Rating] else null),
            
            // review_comment
            AddReviewComment = Table.AddColumn(AddReviewRating, "review_comment", each 
                if [Comment] <> null then [Comment] else null),
            
            // review_status
            AddReviewStatus = Table.AddColumn(AddReviewComment, "review_status", each 
                if [Status] <> null then [Status] else null),
            
            // customer_id
            AddCustomerID = Table.AddColumn(AddReviewStatus, "customer_id", each 
                if [Customer] <> null and [Customer][id]? <> null then [Customer][id] else null),
            
            // customer_name
            AddCustomerName = Table.AddColumn(AddCustomerID, "customer_name", each 
                if [Customer] <> null and [Customer][first_name]? <> null and [Customer][last_name]? <> null then 
                    ([Customer][first_name] & " " & [Customer][last_name])
                else if [Customer] <> null and [Customer][name]? <> null then [Customer][name]
                else null),
            
            // product_id
            AddProductID = Table.AddColumn(AddCustomerName, "product_id", each 
                if [Product] <> null and [Product][id]? <> null then [Product][id] else null),
            
            // product_name
            AddProductName = Table.AddColumn(AddProductID, "product_name", each 
                if [Product] <> null and [Product][name]? <> null then [Product][name] else null),
            
            // product_sku
            AddProductSKU = Table.AddColumn(AddProductName, "product_sku", each 
                if [Product] <> null and [Product][sku]? <> null then [Product][sku] else null),
            
            // order_id
            AddOrderID = Table.AddColumn(AddProductSKU, "order_id", each 
                if [Order] <> null and [Order][id]? <> null then [Order][id] else null),
            
            // order_reference_id
            AddOrderReferenceID = Table.AddColumn(AddOrderID, "order_reference_id", each 
                if [Order] <> null and [Order][reference_id]? <> null then [Order][reference_id] else null),
            
            // review_created_date
            AddReviewCreatedDate = Table.AddColumn(AddOrderReferenceID, "review_created_date", each 
                if [CreatedAt] <> null then [CreatedAt] else null),
            
            // review_updated_date
            AddReviewUpdatedDate = Table.AddColumn(AddReviewCreatedDate, "review_updated_date", each 
                if [UpdatedAt] <> null then [UpdatedAt] else null),
            
            // Select final columns
            SelectedColumns = Table.SelectColumns(AddReviewUpdatedDate, {
                "review_id",
                "review_rating",
                "review_comment",
                "review_status",
                "customer_id",
                "customer_name",
                "product_id",
                "product_name",
                "product_sku",
                "order_id",
                "order_reference_id",
                "review_created_date",
                "review_updated_date"
            })
        in
            SelectedColumns
    else
        Table.FromRecords({[
            review_id = null,
            review_rating = null,
            review_comment = "No reviews found",
            review_status = "No data",
            customer_id = null,
            customer_name = null,
            product_id = null,
            product_name = null,
            product_sku = null,
            order_id = null,
            order_reference_id = null,
            review_created_date = null,
            review_updated_date = null
        ]}),
    
    // Step 6: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(FinalReviewsReport, "DataSource", each "Salla API - Reviews"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
