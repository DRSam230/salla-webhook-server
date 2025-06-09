// Salla Categories Report - Matches Your Exact Requirements
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

    // Step 2: Get Categories with Full Details
    GetCategoriesPage = (pageNum as number) =>
        let
            CategoriesResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/categories?page=" & Number.ToText(pageNum) & "&per_page=50",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            CategoriesJson = Json.Document(CategoriesResponse)
        in
            CategoriesJson,

    // Get first page to determine total pages
    FirstPage = GetCategoriesPage(1),
    TotalPages = if FirstPage[pagination]? <> null then FirstPage[pagination][totalPages] else 1,
    
    // Generate list of all pages
    PageNumbers = List.Numbers(1, TotalPages),
    
    // Get all pages
    AllPages = List.Transform(PageNumbers, each GetCategoriesPage(_)),
    AllCategoriesData = List.Combine(List.Transform(AllPages, each if _[data]? <> null then _[data] else {})),
    
    // Step 3: Transform Categories Data
    CategoriesTable = Table.FromList(AllCategoriesData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    
    // Step 4: Expand main category fields
    ExpandedCategories = Table.ExpandRecordColumn(CategoriesTable, "Column1", 
        {"id", "name", "parent_id", "description", "image", "urls", "metadata", "status", "sort_order"}, 
        {"CategoryID", "Name", "ParentID", "Description", "Image", "URLs", "Metadata", "Status", "SortOrder"}),
    
    // Step 5: Extract YOUR REQUIRED FIELDS
    
    // category_name
    AddCategoryName = Table.AddColumn(ExpandedCategories, "category_name", each 
        if [Name] <> null then [Name] else null),
    
    // category_id
    AddCategoryID = Table.AddColumn(AddCategoryName, "category_id", each 
        if [CategoryID] <> null then [CategoryID] else null),
    
    // parent_category (if applicable)
    AddParentCategory = Table.AddColumn(AddCategoryID, "parent_category", each 
        if [ParentID] <> null and [ParentID] <> 0 then [ParentID] else null),
    
    // category_image_link
    AddCategoryImageLink = Table.AddColumn(AddParentCategory, "category_image_link", each 
        if [Image] <> null then [Image] else null),
    
    // category_description
    AddCategoryDescription = Table.AddColumn(AddCategoryImageLink, "category_description", each 
        if [Description] <> null then [Description] else null),
    
    // category_seo_data (meta title, meta description, etc.)
    AddCategorySEOData = Table.AddColumn(AddCategoryDescription, "category_seo_data", each 
        if [Metadata] <> null then 
            Json.FromValue([Metadata])
        else null),
    
    // category_page_link
    AddCategoryPageLink = Table.AddColumn(AddCategorySEOData, "category_page_link", each 
        if [URLs] <> null and [URLs][customer]? <> null then [URLs][customer] else null),
    
    // category_status
    AddCategoryStatus = Table.AddColumn(AddCategoryPageLink, "category_status", each 
        if [Status] <> null then [Status] else null),
    
    // category_sort_order
    AddCategorySortOrder = Table.AddColumn(AddCategoryStatus, "category_sort_order", each 
        if [SortOrder] <> null then [SortOrder] else null),
    
    // Step 6: Select ONLY your required columns
    FinalCategoriesReport = Table.SelectColumns(AddCategorySortOrder, {
        "category_name",
        "category_id",
        "parent_category",
        "category_image_link",
        "category_description",
        "category_seo_data",
        "category_page_link",
        "category_status",
        "category_sort_order"
    }),
    
    // Step 7: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(FinalCategoriesReport, "DataSource", each "Salla API - Official"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
