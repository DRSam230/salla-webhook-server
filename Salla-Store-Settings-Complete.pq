// Salla Store Settings Complete Report - ALL STORE CONFIGURATION DATA
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

    // Step 2: Get Store Information
    GetStoreInfo = () =>
        let
            StoreResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/store",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            StoreJson = Json.Document(StoreResponse)
        in
            StoreJson,

    // Step 3: Get SEO Settings
    GetSEOSettings = () =>
        let
            SEOResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/seo",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            SEOJson = Json.Document(SEOResponse)
        in
            SEOJson,

    // Step 4: Get Settings List
    GetSettings = () =>
        let
            SettingsResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/settings",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            SettingsJson = Json.Document(SettingsResponse)
        in
            SettingsJson,

    // Get all data
    StoreData = GetStoreInfo(),
    SEOData = GetSEOSettings(),
    SettingsData = GetSettings(),

    // Step 5: Create comprehensive store settings table
    StoreSettingsTable = Table.FromRecords({
        [
            setting_category = "Store Information",
            setting_name = "Store ID",
            setting_value = if StoreData[data]? <> null and StoreData[data][id]? <> null then Text.From(StoreData[data][id]) else null,
            setting_description = "Unique store identifier"
        ],
        [
            setting_category = "Store Information",
            setting_name = "Store Name",
            setting_value = if StoreData[data]? <> null and StoreData[data][name]? <> null then StoreData[data][name] else null,
            setting_description = "Official store name"
        ],
        [
            setting_category = "Store Information",
            setting_name = "Store Domain",
            setting_value = if StoreData[data]? <> null and StoreData[data][domain]? <> null then StoreData[data][domain] else null,
            setting_description = "Store domain URL"
        ],
        [
            setting_category = "Store Information",
            setting_name = "Store Description",
            setting_value = if StoreData[data]? <> null and StoreData[data][description]? <> null then StoreData[data][description] else null,
            setting_description = "Store description"
        ],
        [
            setting_category = "Store Information",
            setting_name = "Store Logo",
            setting_value = if StoreData[data]? <> null and StoreData[data][logo]? <> null then StoreData[data][logo] else null,
            setting_description = "Store logo URL"
        ],
        [
            setting_category = "Store Information",
            setting_name = "Store Favicon",
            setting_value = if StoreData[data]? <> null and StoreData[data][favicon]? <> null then StoreData[data][favicon] else null,
            setting_description = "Store favicon URL"
        ],
        [
            setting_category = "Store Information",
            setting_name = "Store Status",
            setting_value = if StoreData[data]? <> null and StoreData[data][status]? <> null then StoreData[data][status] else null,
            setting_description = "Store operational status"
        ],
        [
            setting_category = "Store Information",
            setting_name = "Store Plan",
            setting_value = if StoreData[data]? <> null and StoreData[data][plan]? <> null then StoreData[data][plan] else null,
            setting_description = "Store subscription plan"
        ],
        [
            setting_category = "Localization",
            setting_name = "Store Currency",
            setting_value = if StoreData[data]? <> null and StoreData[data][currency]? <> null then StoreData[data][currency] else null,
            setting_description = "Store default currency"
        ],
        [
            setting_category = "Localization",
            setting_name = "Store Language",
            setting_value = if StoreData[data]? <> null and StoreData[data][language]? <> null then StoreData[data][language] else null,
            setting_description = "Store default language"
        ],
        [
            setting_category = "Localization",
            setting_name = "Store Timezone",
            setting_value = if StoreData[data]? <> null and StoreData[data][timezone]? <> null then StoreData[data][timezone] else null,
            setting_description = "Store timezone setting"
        ],
        [
            setting_category = "SEO Settings",
            setting_name = "Meta Title",
            setting_value = if SEOData[data]? <> null and SEOData[data][meta_title]? <> null then SEOData[data][meta_title] else null,
            setting_description = "Store meta title for SEO"
        ],
        [
            setting_category = "SEO Settings",
            setting_name = "Meta Description",
            setting_value = if SEOData[data]? <> null and SEOData[data][meta_description]? <> null then SEOData[data][meta_description] else null,
            setting_description = "Store meta description for SEO"
        ],
        [
            setting_category = "SEO Settings",
            setting_name = "Meta Keywords",
            setting_value = if SEOData[data]? <> null and SEOData[data][meta_keywords]? <> null then SEOData[data][meta_keywords] else null,
            setting_description = "Store meta keywords for SEO"
        ],
        [
            setting_category = "Analytics",
            setting_name = "Google Analytics ID",
            setting_value = if SEOData[data]? <> null and SEOData[data][google_analytics_id]? <> null then SEOData[data][google_analytics_id] else null,
            setting_description = "Google Analytics tracking ID"
        ],
        [
            setting_category = "Analytics",
            setting_name = "Google Tag Manager ID",
            setting_value = if SEOData[data]? <> null and SEOData[data][google_tag_manager_id]? <> null then SEOData[data][google_tag_manager_id] else null,
            setting_description = "Google Tag Manager ID"
        ],
        [
            setting_category = "Analytics",
            setting_name = "Facebook Pixel ID",
            setting_value = if SEOData[data]? <> null and SEOData[data][facebook_pixel_id]? <> null then SEOData[data][facebook_pixel_id] else null,
            setting_description = "Facebook Pixel tracking ID"
        ],
        [
            setting_category = "Analytics",
            setting_name = "Snapchat Pixel ID",
            setting_value = if SEOData[data]? <> null and SEOData[data][snapchat_pixel_id]? <> null then SEOData[data][snapchat_pixel_id] else null,
            setting_description = "Snapchat Pixel tracking ID"
        ],
        [
            setting_category = "Analytics",
            setting_name = "Twitter Pixel ID",
            setting_value = if SEOData[data]? <> null and SEOData[data][twitter_pixel_id]? <> null then SEOData[data][twitter_pixel_id] else null,
            setting_description = "Twitter Pixel tracking ID"
        ],
        [
            setting_category = "Analytics",
            setting_name = "TikTok Pixel ID",
            setting_value = if SEOData[data]? <> null and SEOData[data][tiktok_pixel_id]? <> null then SEOData[data][tiktok_pixel_id] else null,
            setting_description = "TikTok Pixel tracking ID"
        ],
        [
            setting_category = "System",
            setting_name = "Store Created Date",
            setting_value = if StoreData[data]? <> null and StoreData[data][created_at]? <> null then StoreData[data][created_at] else null,
            setting_description = "Store creation date"
        ]
    }),

    // Step 6: Add analysis columns
    AddSettingAnalysis = Table.AddColumn(StoreSettingsTable, "setting_configured", each 
        if [setting_value] <> null and [setting_value] <> "" then "Yes" else "No"),
    
    AddSettingPriority = Table.AddColumn(AddSettingAnalysis, "setting_priority", each 
        if Text.Contains([setting_name], "Meta") or Text.Contains([setting_name], "SEO") then "High"
        else if Text.Contains([setting_name], "Analytics") or Text.Contains([setting_name], "Pixel") then "Medium"
        else "Low"),
    
    // Step 7: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(AddSettingPriority, "DataSource", each "Salla API - Store Settings"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
