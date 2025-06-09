// Salla Power Query Data Connector
// Connect Excel to Salla e-commerce platform using Power Query
// No add-in installation required!

let
    // Salla API Configuration
    SallaConfig = [
        BaseUrl = "https://api.salla.dev/admin/v2/",
        WebhookUrl = "https://salla-webhook-server.onrender.com/api/excel/token",
        ClientSecret = "74c4469b3ab16c51659a2c3b1405166f"
    ],
    
    // Function to get access token from webhook server
    GetAccessToken = (merchantId as text) as text =>
        let
            TokenRequest = [
                merchantId = merchantId,
                clientSecret = SallaConfig[ClientSecret]
            ],
            
            Response = try Web.Contents(
                SallaConfig[WebhookUrl],
                [
                    Headers = [
                        #"Content-Type" = "application/json"
                    ],
                    Content = Json.FromValue(TokenRequest)
                ]
            ) otherwise null,
            
            JsonResponse = if Response <> null then Json.Document(Response) else null,
            AccessToken = if JsonResponse <> null then JsonResponse[access_token] else null
        in
            AccessToken,
    
    // Function to make Salla API calls
    CallSallaAPI = (endpoint as text, accessToken as text, optional parameters as record) as table =>
        let
            DefaultParams = [per_page = 50, page = 1],
            FinalParams = if parameters <> null then Record.Combine({DefaultParams, parameters}) else DefaultParams,
            
            QueryString = Uri.BuildQueryString(FinalParams),
            FullUrl = SallaConfig[BaseUrl] & endpoint & "?" & QueryString,
            
            Response = try Web.Contents(
                FullUrl,
                [
                    Headers = [
                        Authorization = "Bearer " & accessToken,
                        Accept = "application/json"
                    ]
                ]
            ) otherwise null,
            
            JsonResponse = if Response <> null then Json.Document(Response) else null,
            DataTable = if JsonResponse <> null and JsonResponse[data] <> null 
                       then Table.FromList(JsonResponse[data], Splitter.SplitByNothing(), null, null, ExtraValues.Error)
                       else #table({}, {})
        in
            DataTable,
    
    // Function to expand nested records in table
    ExpandAllColumns = (sourceTable as table) as table =>
        let
            ColumnNames = Table.ColumnNames(sourceTable),
            ExpandedTable = List.Accumulate(
                ColumnNames,
                sourceTable,
                (currentTable, columnName) =>
                    let
                        ColumnType = Table.Schema(currentTable)[Name = columnName][TypeName]{0}?
                    in
                        if ColumnType = "Record" then
                            let
                                SampleRecord = Table.Column(currentTable, columnName){0}?,
                                RecordFields = if SampleRecord <> null then Record.FieldNames(SampleRecord) else {},
                                ExpandedTable = if List.Count(RecordFields) > 0 
                                              then Table.ExpandRecordColumn(currentTable, columnName, RecordFields, 
                                                   List.Transform(RecordFields, each columnName & "." & _))
                                              else currentTable
                            in
                                ExpandedTable
                        else if ColumnType = "List" then
                            let
                                SampleList = Table.Column(currentTable, columnName){0}?,
                                ExpandedTable = if SampleList <> null and List.Count(SampleList) > 0
                                              then Table.ExpandListColumn(currentTable, columnName)
                                              else currentTable
                            in
                                ExpandedTable
                        else
                            currentTable
            )
        in
            ExpandedTable,
    
    // Main function to get Salla data
    GetSallaData = (dataType as text, merchantId as text, optional parameters as record) as table =>
        let
            AccessToken = GetAccessToken(merchantId),
            
            Result = if AccessToken <> null then
                let
                    RawData = CallSallaAPI(dataType, AccessToken, parameters),
                    ExpandedData = if Table.RowCount(RawData) > 0 then
                        let
                            FirstExpansion = Table.ExpandRecordColumn(RawData, "Column1", 
                                Record.FieldNames(RawData[Column1]{0})),
                            FinalData = ExpandAllColumns(FirstExpansion)
                        in
                            FinalData
                    else
                        RawData
                in
                    FinalData
            else
                #table({"Error"}, {{"Failed to get access token. Please check merchant ID and webhook configuration."}}),
            
            // Add metadata
            FinalResult = Table.AddColumn(Result, "DataSource", each "Salla API"),
            MetadataResult = Table.AddColumn(FinalResult, "RetrievedAt", each DateTime.LocalNow())
        in
            MetadataResult,
    
    // Predefined functions for common data types
    GetOrders = (merchantId as text, optional parameters as record) as table =>
        GetSallaData("orders", merchantId, parameters),
    
    GetProducts = (merchantId as text, optional parameters as record) as table =>
        GetSallaData("products", merchantId, parameters),
    
    GetCustomers = (merchantId as text, optional parameters as record) as table =>
        GetSallaData("customers", merchantId, parameters),
    
    GetCategories = (merchantId as text, optional parameters as record) as table =>
        GetSallaData("categories", merchantId, parameters),
    
    GetBrands = (merchantId as text, optional parameters as record) as table =>
        GetSallaData("brands", merchantId, parameters),
    
    // Demo function with sample merchant ID
    DemoOrders = () as table =>
        let
            SampleMerchantId = "1234567890", // Replace with actual merchant ID
            OrdersData = GetOrders(SampleMerchantId, [per_page = 10])
        in
            OrdersData,
    
    // Main connector interface
    SallaConnector = [
        // Data retrieval functions
        Orders = GetOrders,
        Products = GetProducts,
        Customers = GetCustomers,
        Categories = GetCategories,
        Brands = GetBrands,
        
        // Generic data function
        GetData = GetSallaData,
        
        // Demo function
        Demo = DemoOrders,
        
        // Configuration
        Config = SallaConfig,
        
        // Helper functions
        TestConnection = (merchantId as text) as text =>
            let
                Token = GetAccessToken(merchantId),
                Status = if Token <> null then "Connected successfully!" else "Connection failed - check merchant ID"
            in
                Status
    ]

in
    SallaConnector
