// Salla Power Query Connector - Simple Version
// Step-by-step approach to avoid syntax errors

let
    // Step 1: Get Access Token from Webhook Server
    GetAccessToken = (merchantId as text) =>
        let
            // Create request body
            RequestBody = [
                merchantId = merchantId,
                clientSecret = "74c4469b3ab16c51659a2c3b1405166f"
            ],
            
            // Make API call to webhook server
            Response = Web.Contents(
                "https://salla-webhook-server.onrender.com/api/excel/token",
                [
                    Headers = [
                        #"Content-Type" = "application/json"
                    ],
                    Content = Json.FromValue(RequestBody)
                ]
            ),
            
            // Parse JSON response
            JsonData = Json.Document(Response),
            AccessToken = JsonData[access_token]
        in
            AccessToken,
    
    // Step 2: Get Salla Data using Access Token
    GetSallaData = (endpoint as text, accessToken as text) =>
        let
            // Build API URL
            ApiUrl = "https://api.salla.dev/admin/v2/" & endpoint & "?per_page=50",
            
            // Make API call to Salla
            Response = Web.Contents(
                ApiUrl,
                [
                    Headers = [
                        Authorization = "Bearer " & accessToken,
                        Accept = "application/json"
                    ]
                ]
            ),
            
            // Parse JSON response
            JsonData = Json.Document(Response),
            DataList = JsonData[data],
            
            // Convert to table
            DataTable = Table.FromList(DataList, Splitter.SplitByNothing(), null, null, ExtraValues.Error)
        in
            DataTable,
    
    // Step 3: Main function to get orders
    GetOrders = (merchantId as text) =>
        let
            Token = GetAccessToken(merchantId),
            OrdersTable = GetSallaData("orders", Token),
            
            // Expand the data column
            ExpandedTable = if Table.RowCount(OrdersTable) > 0 then
                Table.ExpandRecordColumn(
                    OrdersTable, 
                    "Column1", 
                    Record.FieldNames(OrdersTable[Column1]{0})
                )
            else
                OrdersTable
        in
            ExpandedTable
in
    GetOrders
