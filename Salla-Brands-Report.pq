// Salla Brands Report - Matches Your Exact Requirements
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

    // Step 2: Get Brands with Full Details
    GetBrandsPage = (pageNum as number) =>
        let
            BrandsResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/brands?page=" & Number.ToText(pageNum) & "&per_page=50",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            BrandsJson = Json.Document(BrandsResponse)
        in
            BrandsJson,

    // Get first page to determine total pages
    FirstPage = GetBrandsPage(1),
    TotalPages = if FirstPage[pagination]? <> null then FirstPage[pagination][totalPages] else 1,
    
    // Generate list of all pages
    PageNumbers = List.Numbers(1, TotalPages),
    
    // Get all pages
    AllPages = List.Transform(PageNumbers, each GetBrandsPage(_)),
    AllBrandsData = List.Combine(List.Transform(AllPages, each if _[data]? <> null then _[data] else {})),
    
    // Step 3: Transform Brands Data
    BrandsTable = Table.FromList(AllBrandsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    
    // Step 4: Expand main brand fields
    ExpandedBrands = Table.ExpandRecordColumn(BrandsTable, "Column1", 
        {"id", "name", "description", "image", "urls", "metadata", "status"}, 
        {"BrandID", "Name", "Description", "Image", "URLs", "Metadata", "Status"}),
    
    // Step 5: Extract YOUR REQUIRED FIELDS
    
    // brand_name
    AddBrandName = Table.AddColumn(ExpandedBrands, "brand_name", each 
        if [Name] <> null then [Name] else null),
    
    // brand_id
    AddBrandID = Table.AddColumn(AddBrandName, "brand_id", each 
        if [BrandID] <> null then [BrandID] else null),
    
    // brand_image_link
    AddBrandImageLink = Table.AddColumn(AddBrandID, "brand_image_link", each 
        if [Image] <> null then [Image] else null),
    
    // brand_description
    AddBrandDescription = Table.AddColumn(AddBrandImageLink, "brand_description", each 
        if [Description] <> null then [Description] else null),
    
    // brand_seo_data
    AddBrandSEOData = Table.AddColumn(AddBrandDescription, "brand_seo_data", each 
        if [Metadata] <> null then 
            Json.FromValue([Metadata])
        else null),
    
    // brand_page_link
    AddBrandPageLink = Table.AddColumn(AddBrandSEOData, "brand_page_link", each 
        if [URLs] <> null and [URLs][customer]? <> null then [URLs][customer] else null),
    
    // brand_status
    AddBrandStatus = Table.AddColumn(AddBrandPageLink, "brand_status", each 
        if [Status] <> null then [Status] else null),
    
    // Step 6: Select ONLY your required columns
    FinalBrandsReport = Table.SelectColumns(AddBrandStatus, {
        "brand_name",
        "brand_id",
        "brand_image_link",
        "brand_description",
        "brand_seo_data",
        "brand_page_link",
        "brand_status"
    }),
    
    // Step 7: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(FinalBrandsReport, "DataSource", each "Salla API - Official"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
