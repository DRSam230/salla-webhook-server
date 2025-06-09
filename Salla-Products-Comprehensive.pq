// Salla Products Comprehensive Report - Matches Your Exact Requirements
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

    // Step 2: Get Products with Full Details
    GetProductsPage = (pageNum as number) =>
        let
            ProductsResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/products?page=" & Number.ToText(pageNum) & "&per_page=50",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            ProductsJson = Json.Document(ProductsResponse)
        in
            ProductsJson,

    // Get first page to determine total pages
    FirstPage = GetProductsPage(1),
    TotalPages = if FirstPage[pagination]? <> null then FirstPage[pagination][totalPages] else 1,
    
    // Generate list of all pages (limit to first 20 pages for performance)
    PageNumbers = List.Numbers(1, Number.Min(TotalPages, 20)),
    
    // Get all pages
    AllPages = List.Transform(PageNumbers, each GetProductsPage(_)),
    AllProductsData = List.Combine(List.Transform(AllPages, each if _[data]? <> null then _[data] else {})),
    
    // Step 3: Transform Products Data
    ProductsTable = Table.FromList(AllProductsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    
    // Step 4: Expand main product fields
    ExpandedProducts = Table.ExpandRecordColumn(ProductsTable, "Column1", 
        {"id", "sku", "mpn", "gtin", "name", "description", "price", "sale_price", "images", "brand", "categories", "quantity", "sold_quantity", "type", "status", "url", "metadata", "skus", "with_tax", "tags"}, 
        {"ProductID", "SKU", "MPN", "GTIN", "Name", "Description", "Price", "SalePrice", "Images", "Brand", "Categories", "Quantity", "SoldQuantity", "Type", "Status", "URL", "Metadata", "SKUs", "WithTax", "Tags"}),
    
    // Step 5: Extract YOUR REQUIRED FIELDS
    
    // product_code (SKU)
    AddProductCode = Table.AddColumn(ExpandedProducts, "product_code", each 
        if [SKU] <> null then [SKU] else null),
    
    // product_barcode (from SKUs variants)
    AddProductBarcode = Table.AddColumn(AddProductCode, "product_barcode", each 
        if [SKUs] <> null and List.Count([SKUs]) > 0 then 
            let
                FirstSKU = List.First([SKUs])
            in
                if FirstSKU[barcode]? <> null then FirstSKU[barcode] else null
        else null),
    
    // product_mpn (Manufacturer Part Number)
    AddProductMPN = Table.AddColumn(AddProductBarcode, "product_mpn", each 
        if [MPN] <> null then [MPN] else null),
    
    // product_image_link (primary image)
    AddProductImageLink = Table.AddColumn(AddProductMPN, "product_image_link", each 
        if [Images] <> null and List.Count([Images]) > 0 then 
            let
                MainImage = List.First(List.Select([Images], each _[main] = true))
            in
                if MainImage <> null then MainImage[url] 
                else List.First([Images])[url]
        else null),
    
    // product_description
    AddProductDescription = Table.AddColumn(AddProductImageLink, "product_description", each 
        if [Description] <> null then [Description] else null),
    
    // vat_status/rate
    AddVATStatus = Table.AddColumn(AddProductDescription, "vat_status", each 
        if [WithTax] <> null then 
            if [WithTax] = true then "Taxed" else "Tax-Free"
        else "Unknown"),
    
    // product_brand
    AddProductBrand = Table.AddColumn(AddVATStatus, "product_brand", each 
        if [Brand] <> null and [Brand][name]? <> null then [Brand][name] else null),
    
    // product_meta_data
    AddProductMetaData = Table.AddColumn(AddProductBrand, "product_meta_data", each 
        if [Metadata] <> null then 
            Json.FromValue([Metadata])
        else null),
    
    // product_alt_text (from images)
    AddProductAltText = Table.AddColumn(AddProductMetaData, "product_alt_text", each 
        if [Images] <> null and List.Count([Images]) > 0 then 
            let
                FirstImage = List.First([Images])
            in
                if FirstImage[alt]? <> null then FirstImage[alt] else null
        else null),
    
    // product_seo_data (from metadata)
    AddProductSEOData = Table.AddColumn(AddProductAltText, "product_seo_data", each 
        if [Metadata] <> null then 
            let
                SEOData = [
                    meta_title = if [Metadata][title]? <> null then [Metadata][title] else null,
                    meta_description = if [Metadata][description]? <> null then [Metadata][description] else null,
                    meta_url = if [Metadata][url]? <> null then [Metadata][url] else null
                ]
            in
                Json.FromValue(SEOData)
        else null),
    
    // price_offer (sale price, if applicable)
    AddPriceOffer = Table.AddColumn(AddProductSEOData, "price_offer", each 
        if [SalePrice] <> null and [SalePrice][amount]? <> null then [SalePrice][amount] else null),
    
    // linked_coupons (not directly available in API - placeholder)
    AddLinkedCoupons = Table.AddColumn(AddPriceOffer, "linked_coupons", each null),
    
    // categories (list of categories the product belongs to)
    AddCategories = Table.AddColumn(AddLinkedCoupons, "categories", each 
        if [Categories] <> null then 
            Text.Combine(
                List.Transform([Categories], each 
                    if _[name]? <> null then _[name] else "Unnamed"
                ), "; "
            )
        else null),
    
    // current_stock_level
    AddCurrentStockLevel = Table.AddColumn(AddCategories, "current_stock_level", each 
        if [Quantity] <> null then [Quantity] else null),
    
    // total_sold_quantity
    AddTotalSoldQuantity = Table.AddColumn(AddCurrentStockLevel, "total_sold_quantity", each 
        if [SoldQuantity] <> null then [SoldQuantity] else null),
    
    // product_type
    AddProductType = Table.AddColumn(AddTotalSoldQuantity, "product_type", each 
        if [Type] <> null then [Type] else null),
    
    // product_status (e.g., active, draft, out of stock)
    AddProductStatus = Table.AddColumn(AddProductType, "product_status", each 
        if [Status] <> null then [Status] else null),
    
    // product_page_link
    AddProductPageLink = Table.AddColumn(AddProductStatus, "product_page_link", each 
        if [URL] <> null then [URL] else null),
    
    // Step 6: Select ONLY your required columns
    FinalProductsReport = Table.SelectColumns(AddProductPageLink, {
        "product_code",
        "product_barcode",
        "product_mpn",
        "product_image_link",
        "product_description",
        "vat_status",
        "product_brand",
        "product_meta_data",
        "product_alt_text",
        "product_seo_data",
        "price_offer",
        "linked_coupons",
        "categories",
        "current_stock_level",
        "total_sold_quantity",
        "product_type",
        "product_status",
        "product_page_link"
    }),
    
    // Step 7: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(FinalProductsReport, "DataSource", each "Salla API - Official"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
