// Salla Shipments Complete Report - ALL SHIPPING DATA
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

    // Step 2: Get Shipments with Full Details
    GetShipmentsPage = (pageNum as number) =>
        let
            ShipmentsResponse = Web.Contents(
                "https://api.salla.dev/admin/v2/shipments?page=" & Number.ToText(pageNum) & "&per_page=50",
                [
                    Headers = [
                        #"Authorization" = "Bearer " & AccessToken,
                        #"Accept" = "application/json"
                    ]
                ]
            ),
            ShipmentsJson = Json.Document(ShipmentsResponse)
        in
            ShipmentsJson,

    // Get first page to determine total pages
    FirstPage = GetShipmentsPage(1),
    TotalPages = if FirstPage[pagination]? <> null then FirstPage[pagination][totalPages] else 1,
    
    // Generate list of all pages (limit to first 10 pages for performance)
    PageNumbers = List.Numbers(1, Number.Min(TotalPages, 10)),
    
    // Get all pages
    AllPages = List.Transform(PageNumbers, each GetShipmentsPage(_)),
    AllShipmentsData = List.Combine(List.Transform(AllPages, each if _[data]? <> null then _[data] else {})),
    
    // Step 3: Transform Shipments Data
    ShipmentsTable = Table.FromList(AllShipmentsData, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    
    // Step 4: Expand main shipment fields (if data exists)
    ShipmentsExpanded = if Table.RowCount(ShipmentsTable) > 0 then
        Table.ExpandRecordColumn(ShipmentsTable, "Column1", 
            {"id", "tracking_number", "status", "company", "order", "created_at", "updated_at", "shipped_at", "delivered_at"}, 
            {"ShipmentID", "TrackingNumber", "Status", "Company", "Order", "CreatedAt", "UpdatedAt", "ShippedAt", "DeliveredAt"})
    else
        Table.FromRecords({}),
    
    // Step 5: Extract comprehensive shipment fields (if data exists)
    FinalShipmentsReport = if Table.RowCount(ShipmentsExpanded) > 0 then
        let
            // shipment_id
            AddShipmentID = Table.AddColumn(ShipmentsExpanded, "shipment_id", each 
                if [ShipmentID] <> null then [ShipmentID] else null),
            
            // tracking_number
            AddTrackingNumber = Table.AddColumn(AddShipmentID, "tracking_number", each 
                if [TrackingNumber] <> null then [TrackingNumber] else null),
            
            // shipment_status
            AddShipmentStatus = Table.AddColumn(AddTrackingNumber, "shipment_status", each 
                if [Status] <> null then [Status] else null),
            
            // shipping_company_name
            AddShippingCompanyName = Table.AddColumn(AddShipmentStatus, "shipping_company_name", each 
                if [Company] <> null and [Company][name]? <> null then [Company][name] else null),
            
            // shipping_company_id
            AddShippingCompanyID = Table.AddColumn(AddShippingCompanyName, "shipping_company_id", each 
                if [Company] <> null and [Company][id]? <> null then [Company][id] else null),
            
            // order_id
            AddOrderID = Table.AddColumn(AddShippingCompanyID, "order_id", each 
                if [Order] <> null and [Order][id]? <> null then [Order][id] else null),
            
            // order_reference_id
            AddOrderReferenceID = Table.AddColumn(AddOrderID, "order_reference_id", each 
                if [Order] <> null and [Order][reference_id]? <> null then [Order][reference_id] else null),
            
            // shipment_created_date
            AddShipmentCreatedDate = Table.AddColumn(AddOrderReferenceID, "shipment_created_date", each 
                if [CreatedAt] <> null then [CreatedAt] else null),
            
            // shipment_updated_date
            AddShipmentUpdatedDate = Table.AddColumn(AddShipmentCreatedDate, "shipment_updated_date", each 
                if [UpdatedAt] <> null then [UpdatedAt] else null),
            
            // shipment_shipped_date
            AddShipmentShippedDate = Table.AddColumn(AddShipmentUpdatedDate, "shipment_shipped_date", each 
                if [ShippedAt] <> null then [ShippedAt] else null),
            
            // shipment_delivered_date
            AddShipmentDeliveredDate = Table.AddColumn(AddShipmentShippedDate, "shipment_delivered_date", each 
                if [DeliveredAt] <> null then [DeliveredAt] else null),
            
            // Select final columns
            SelectedColumns = Table.SelectColumns(AddShipmentDeliveredDate, {
                "shipment_id",
                "tracking_number",
                "shipment_status",
                "shipping_company_name",
                "shipping_company_id",
                "order_id",
                "order_reference_id",
                "shipment_created_date",
                "shipment_updated_date",
                "shipment_shipped_date",
                "shipment_delivered_date"
            })
        in
            SelectedColumns
    else
        Table.FromRecords({[
            shipment_id = null,
            tracking_number = "No shipments found",
            shipment_status = "No data",
            shipping_company_name = null,
            shipping_company_id = null,
            order_id = null,
            order_reference_id = null,
            shipment_created_date = null,
            shipment_updated_date = null,
            shipment_shipped_date = null,
            shipment_delivered_date = null
        ]}),
    
    // Step 6: Add metadata
    FinalTable = Table.AddColumn(
        Table.AddColumn(FinalShipmentsReport, "DataSource", each "Salla API - Shipments"),
        "RetrievedAt", each DateTime.LocalNow()
    )

in
    FinalTable
