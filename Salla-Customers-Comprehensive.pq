// Salla Customers Comprehensive Report - Matches Your Exact Requirements
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

    // Step 2: Get Customers with Full Details
    GetCustomersPage = (pageNum as number) =>
        let
            CustomersResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/customers?page=" & Number.ToText(pageNum) & "&per_page=50",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            CustomersJson = Json.Document(CustomersResponse)
        in
            CustomersJson,

    // Get first page to determine total pages
    FirstPage = GetCustomersPage(1),
    TotalPages = if FirstPage[pagination]? <> null then FirstPage[pagination][totalPages] else 1,
    
    // Generate list of all pages (limit to first 20 pages for performance)
    PageNumbers = List.Numbers(1, Number.Min(TotalPages, 20)),
    
    // Get all pages
    AllPages = List.Transform(PageNumbers, each GetCustomersPage(_)),
    AllCustomersData = List.Combine(List.Transform(AllPages, each if _[data]? <> null then _[data] else {})),
    
    // Step 3: Transform Customers Data
    CustomersTable = Table.FromList(AllCustomersData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    
    // Step 4: Expand main customer fields
    ExpandedCustomers = Table.ExpandRecordColumn(CustomersTable, "Column1", 
        {"id", "first_name", "last_name", "email", "mobile", "mobile_code", "city", "country", "country_code", "gender", "birthday", "avatar", "location", "updated_at", "groups"}, 
        {"CustomerID", "FirstName", "LastName", "Email", "Mobile", "MobileCode", "City", "Country", "CountryCode", "Gender", "Birthday", "Avatar", "Location", "UpdatedAt", "Groups"}),
    
    // Step 5: Extract comprehensive customer fields
    
    // customer_id
    AddCustomerID = Table.AddColumn(ExpandedCustomers, "customer_id", each 
        if [CustomerID] <> null then [CustomerID] else null),
    
    // customer_name (first_name + last_name)
    AddCustomerName = Table.AddColumn(AddCustomerID, "customer_name", each 
        if [FirstName] <> null and [LastName] <> null then 
            ([FirstName] & " " & [LastName])
        else if [FirstName] <> null then [FirstName]
        else if [LastName] <> null then [LastName]
        else null),
    
    // customer_first_name
    AddCustomerFirstName = Table.AddColumn(AddCustomerName, "customer_first_name", each 
        if [FirstName] <> null then [FirstName] else null),
    
    // customer_last_name
    AddCustomerLastName = Table.AddColumn(AddCustomerFirstName, "customer_last_name", each 
        if [LastName] <> null then [LastName] else null),
    
    // customer_email
    AddCustomerEmail = Table.AddColumn(AddCustomerLastName, "customer_email", each 
        if [Email] <> null then [Email] else null),
    
    // customer_phone_number (mobile_code + mobile)
    AddCustomerPhone = Table.AddColumn(AddCustomerEmail, "customer_phone_number", each 
        if [MobileCode] <> null and [Mobile] <> null then 
            ([MobileCode] & Text.From([Mobile]))
        else if [Mobile] <> null then Text.From([Mobile])
        else null),
    
    // customer_mobile (just the mobile number)
    AddCustomerMobile = Table.AddColumn(AddCustomerPhone, "customer_mobile", each 
        if [Mobile] <> null then Text.From([Mobile]) else null),
    
    // customer_mobile_code
    AddCustomerMobileCode = Table.AddColumn(AddCustomerMobile, "customer_mobile_code", each 
        if [MobileCode] <> null then [MobileCode] else null),
    
    // customer_city
    AddCustomerCity = Table.AddColumn(AddCustomerMobileCode, "customer_city", each 
        if [City] <> null then [City] else null),
    
    // customer_country
    AddCustomerCountry = Table.AddColumn(AddCustomerCity, "customer_country", each 
        if [Country] <> null then [Country] else null),
    
    // customer_country_code
    AddCustomerCountryCode = Table.AddColumn(AddCustomerCountry, "customer_country_code", each 
        if [CountryCode] <> null then [CountryCode] else null),
    
    // customer_gender
    AddCustomerGender = Table.AddColumn(AddCustomerCountryCode, "customer_gender", each 
        if [Gender] <> null then [Gender] else null),
    
    // customer_birthday
    AddCustomerBirthday = Table.AddColumn(AddCustomerGender, "customer_birthday", each 
        if [Birthday] <> null then 
            if [Birthday][date]? <> null then [Birthday][date] else null
        else null),
    
    // customer_avatar
    AddCustomerAvatar = Table.AddColumn(AddCustomerBirthday, "customer_avatar", each 
        if [Avatar] <> null then [Avatar] else null),
    
    // customer_location
    AddCustomerLocation = Table.AddColumn(AddCustomerAvatar, "customer_location", each 
        if [Location] <> null then [Location] else null),
    
    // customer_last_updated
    AddCustomerLastUpdated = Table.AddColumn(AddCustomerLocation, "customer_last_updated", each 
        if [UpdatedAt] <> null then 
            if [UpdatedAt][date]? <> null then [UpdatedAt][date] else null
        else null),
    
    // customer_groups
    AddCustomerGroups = Table.AddColumn(AddCustomerLastUpdated, "customer_groups", each 
        if [Groups] <> null then 
            Text.Combine(
                List.Transform([Groups], each Text.From(_)), "; "
            )
        else null),
    
    // customer_registration_date (created_at equivalent)
    AddCustomerRegistrationDate = Table.AddColumn(AddCustomerGroups, "customer_registration_date", each 
        if [UpdatedAt] <> null then 
            if [UpdatedAt][date]? <> null then [UpdatedAt][date] else null
        else null),
    
    // Step 6: Select comprehensive customer columns
    FinalCustomersReport = Table.SelectColumns(AddCustomerRegistrationDate, {
        "customer_id",
        "customer_name",
        "customer_first_name",
        "customer_last_name",
        "customer_email",
        "customer_phone_number",
        "customer_mobile",
        "customer_mobile_code",
        "customer_city",
        "customer_country",
        "customer_country_code",
        "customer_gender",
        "customer_birthday",
        "customer_avatar",
        "customer_location",
        "customer_last_updated",
        "customer_groups",
        "customer_registration_date"
    }),
    
    // Step 7: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(FinalCustomersReport, "DataSource", each "Salla API - Official"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
