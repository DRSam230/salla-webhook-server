// Salla Store SEO Data Report - Matches Your Exact Requirements
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

    // Step 2: Get Store SEO Settings
    SEOResponse = Web.Contents(
        "https://api.salla.dev/admin/v2/seo",
        [
            Headers = [
                #"Authorization" = "Bearer " & AccessToken,
                #"Accept" = "application/json"
            ]
        ]
    ),

    SEOJson = Json.Document(SEOResponse),
    SEOData = SEOJson[data],
    
    // Step 3: Get Store Information
    StoreResponse = Web.Contents(
        "https://api.salla.dev/admin/v2/store",
        [
            Headers = [
                #"Authorization" = "Bearer " & AccessToken,
                #"Accept" = "application/json"
            ]
        ]
    ),

    StoreJson = Json.Document(StoreResponse),
    StoreData = StoreJson[data],
    
    // Step 4: Transform SEO Data into table format
    SEOTable = Table.FromRecords({
        [
            seo_setting_type = "Store Meta Title",
            seo_setting_value = if SEOData[meta_title]? <> null then SEOData[meta_title] else null,
            seo_setting_description = "Main meta title for the store"
        ],
        [
            seo_setting_type = "Store Meta Description", 
            seo_setting_value = if SEOData[meta_description]? <> null then SEOData[meta_description] else null,
            seo_setting_description = "Main meta description for the store"
        ],
        [
            seo_setting_type = "Store Meta Keywords",
            seo_setting_value = if SEOData[meta_keywords]? <> null then SEOData[meta_keywords] else null,
            seo_setting_description = "Meta keywords for the store"
        ],
        [
            seo_setting_type = "Store Name",
            seo_setting_value = if StoreData[name]? <> null then StoreData[name] else null,
            seo_setting_description = "Official store name"
        ],
        [
            seo_setting_type = "Store Domain",
            seo_setting_value = if StoreData[domain]? <> null then StoreData[domain] else null,
            seo_setting_description = "Store domain URL"
        ],
        [
            seo_setting_type = "Store Description",
            seo_setting_value = if StoreData[description]? <> null then StoreData[description] else null,
            seo_setting_description = "Store description"
        ],
        [
            seo_setting_type = "Store Logo",
            seo_setting_value = if StoreData[logo]? <> null then StoreData[logo] else null,
            seo_setting_description = "Store logo URL"
        ],
        [
            seo_setting_type = "Store Favicon",
            seo_setting_value = if StoreData[favicon]? <> null then StoreData[favicon] else null,
            seo_setting_description = "Store favicon URL"
        ],
        [
            seo_setting_type = "Google Analytics ID",
            seo_setting_value = if SEOData[google_analytics_id]? <> null then SEOData[google_analytics_id] else null,
            seo_setting_description = "Google Analytics tracking ID"
        ],
        [
            seo_setting_type = "Google Tag Manager ID",
            seo_setting_value = if SEOData[google_tag_manager_id]? <> null then SEOData[google_tag_manager_id] else null,
            seo_setting_description = "Google Tag Manager ID"
        ],
        [
            seo_setting_type = "Facebook Pixel ID",
            seo_setting_value = if SEOData[facebook_pixel_id]? <> null then SEOData[facebook_pixel_id] else null,
            seo_setting_description = "Facebook Pixel tracking ID"
        ],
        [
            seo_setting_type = "Snapchat Pixel ID",
            seo_setting_value = if SEOData[snapchat_pixel_id]? <> null then SEOData[snapchat_pixel_id] else null,
            seo_setting_description = "Snapchat Pixel tracking ID"
        ],
        [
            seo_setting_type = "Twitter Pixel ID",
            seo_setting_value = if SEOData[twitter_pixel_id]? <> null then SEOData[twitter_pixel_id] else null,
            seo_setting_description = "Twitter Pixel tracking ID"
        ],
        [
            seo_setting_type = "TikTok Pixel ID",
            seo_setting_value = if SEOData[tiktok_pixel_id]? <> null then SEOData[tiktok_pixel_id] else null,
            seo_setting_description = "TikTok Pixel tracking ID"
        ],
        [
            seo_setting_type = "Store Currency",
            seo_setting_value = if StoreData[currency]? <> null then StoreData[currency] else null,
            seo_setting_description = "Store default currency"
        ],
        [
            seo_setting_type = "Store Language",
            seo_setting_value = if StoreData[language]? <> null then StoreData[language] else null,
            seo_setting_description = "Store default language"
        ],
        [
            seo_setting_type = "Store Timezone",
            seo_setting_value = if StoreData[timezone]? <> null then StoreData[timezone] else null,
            seo_setting_description = "Store timezone setting"
        ],
        [
            seo_setting_type = "Store Status",
            seo_setting_value = if StoreData[status]? <> null then StoreData[status] else null,
            seo_setting_description = "Store operational status"
        ],
        [
            seo_setting_type = "Store Plan",
            seo_setting_value = if StoreData[plan]? <> null then StoreData[plan] else null,
            seo_setting_description = "Store subscription plan"
        ],
        [
            seo_setting_type = "Store Created Date",
            seo_setting_value = if StoreData[created_at]? <> null then StoreData[created_at] else null,
            seo_setting_description = "Store creation date"
        ]
    }),
    
    // Step 5: Add comprehensive SEO analysis
    AddSEOAnalysis = Table.AddColumn(SEOTable, "seo_analysis", each 
        if [seo_setting_value] <> null and [seo_setting_value] <> "" then "Configured"
        else "Not Configured"),
    
    AddSEOPriority = Table.AddColumn(AddSEOAnalysis, "seo_priority", each 
        if Text.Contains([seo_setting_type], "Meta Title") or Text.Contains([seo_setting_type], "Meta Description") then "High"
        else if Text.Contains([seo_setting_type], "Analytics") or Text.Contains([seo_setting_type], "Pixel") then "Medium"
        else "Low"),
    
    AddSEOCategory = Table.AddColumn(AddSEOPriority, "seo_category", each 
        if Text.Contains([seo_setting_type], "Meta") then "Meta Tags"
        else if Text.Contains([seo_setting_type], "Pixel") or Text.Contains([seo_setting_type], "Analytics") then "Tracking"
        else if Text.Contains([seo_setting_type], "Store") then "Store Settings"
        else "Other"),
    
    // Step 6: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(AddSEOCategory, "DataSource", each "Salla API - Official"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
