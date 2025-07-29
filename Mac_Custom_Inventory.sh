#!/bin/bash
 
# Replace with your Log Analytics Workspace ID
CustomerId="<ENTER YOUR LOG ANALYTICS WORKSPACE ID>"
 
# Replace with your Primary Key
SharedKey="<ENTER YOUR LOG ANALYTICS PRIMARY KEY HERE>"
 
#Control if you want to collect App or Device Inventory or both (True = Collect)
CollectDeviceInventory=true
CollectAppInventory=true
 
# You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
# DO NOT DELETE THIS VARIABLE. Recommened keep this blank.
TimeStampField=""
 
#endregion initialize
 
#region functions
 
# Function to create the authorization signature
# function New-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
function New-Signature() {
    customerId=$1
    sharedKey=$2
    date=$3
    contentLength=$4
    method=$5
    contentType=$6
    resource=$7
 
    xHeaders="x-ms-date:$date"
    stringToHash="$method\n$contentLength\n$contentType\n$xHeaders\n$resource"
 
    # Convert the message and secret to bytes
    bytesToHash=$(echo -ne "$stringToHash" | xxd -p -u -c 256)
    keyBytes=$(echo "$sharedKey" | base64 -d | xxd -p -u -c 256)
    # Calculate HMAC-SHA256
    calculatedHash=$(echo -n "$bytesToHash" | xxd -r -p | openssl dgst -sha256 -mac HMAC -macopt hexkey:$keyBytes -binary | base64)
 
    authorization=$(echo "SharedKey" $customerId:$calculatedHash)
 
    echo $authorization
    
}
 
# Function to create and post the request
# Function Send-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
function Send-LogAnalyticsData() {
    customerId=$1
    sharedKey=$2
    body=$3
    logType=$4
 
    method="POST"
    contentType="application/json"
    resource="/api/logs"
    rfc1123date=$(date -u +%a,\ %d\ %b\ %Y\ %H:%M:%S\ GMT)
 
    #contentLength=${#body}
    bodyEncoded=$(echo -n "$body" | iconv -f UTF-8 -t WINDOWS-1252 | iconv -f WINDOWS-1252 -t UTF-8)
    contentLength=$(echo -n "$bodyEncoded" | wc -c | tr -d '[:space:]')
    
    signature=$(New-Signature "$customerId" "$sharedKey" "$rfc1123date" "$contentLength" "$method" "$contentType" "$resource")
    uri="https://$customerId.ods.opinsights.azure.com$resource?api-version=2016-04-01"
    
    # Define the maximum payload size limit in bytes
    max_payload_size=$(echo -n "scale=2; 31.9 * 1024 * 1024" | bc)
    # Calculate the payload size in bytes
    payload_size=$(echo "scale=2; $(echo -n "$body"| wc -c)"| bc)
 
    # Convert the payload size to megabytes with one decimal place
    payload_size_mb=$(echo -n "scale=2; $payload_size / 1024 / 1024" | bc)
 
    # Check if the payload size exceeds the limit
    if [ $(bc -l <<< "$payload_size > $max_payload_size") -eq 1 ]; then
        statusmessage="Upload payload is too big and exceeds the 32Mb limit for a single upload. Please reduce the payload size. Current payload size is: $payload_size_mb Mb"
    else
        payloadsize_kb=$(echo "Upload payload size is " $(echo "scale=2; $(echo -n "$body"| wc -c)/ 1024"| bc)"Kb")
 
        response=$(curl --location "$uri" -w "%{http_code}" --header "Authorization: $signature" --header "Log-Type: $logType" --header "x-ms-date: $rfc1123date" --header "time-generated-field;" --header "Content-Type: $contentType" --data "$body" --silent)
 
        statusmessage="$response : $payloadsize_kb"
    fi
 
    echo $statusmessage
}
#endregion functions
 
#region script
 
#Get Common data for App and Device Inventory:
 
#Get Intune DeviceID and ComputerName
 
# Retrieve Intune DeviceID
ManagedDeviceID=$(security find-certificate -a | awk -F= '/issu/ && /MICROSOFT INTUNE MDM DEVICE CA/ { getline; gsub(/"/, "", $2); print $2}' | head -n 1)
# Retrieve ComputerName
ComputerName=$(scutil --get ComputerName)
 
 
#region APPINVENTORY
 
if [ "$CollectAppInventory" = true ]; then
    #Set Name of Log
    AppLog="PowerStacksAppInventory"
 
    #installedApps=$(Get-InstalledApplications)
    installedApps=$(system_profiler SPApplicationsDataType -json)
 
    # Use awk to parse JSON data and extract fields
    InstalledAppJson=$(echo "$installedApps" | awk -F'[:,]' '
        $1 ~ /_name/ {
            name = $2
            gsub(/"/, "", name)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
        }
        $1 ~ /lastModified/ {
            lastModified = $0
            sub(/.*: /, "", lastModified)
            gsub(/"/, "", lastModified)
            gsub(/,$/, "", lastModified)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", lastModified)
        }
        $1 ~ /path/ {
            path = $2
            gsub(/"/, "", path)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", path)
        }
        $1 ~ /version/ {
            version = $2
            gsub(/"/, "", version)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", version)
            print "{\"AppName\":\"" name "\",\"AppVersion\":\"" version "\",\"AppInstallDate\":\"" lastModified "\",\"AppInstallPath\":\"" path "\"}"
        }
    ' | paste -sd "," -)
    
    # Encode to UTF-8, compress, and then encode to base64
    InstalledAppJson=$(echo -n "[$InstalledAppJson]" | iconv -t utf-8 | gzip -c -n | base64 | tr -d '\n')
 
    # Define chunk size
    chunk_size=31744
 
    # Split the string into chunks and store in an array
    InstalledAppJsonArr=()
    while [ -n "$InstalledAppJson" ]; do
        chunk=$(echo "$InstalledAppJson" | cut -c 1-$chunk_size)
        InstalledAppJsonArr+=("$chunk")
        InstalledAppJson=$(echo "$InstalledAppJson" | cut -c $(($chunk_size + 1))-)
    done
 
    # Print each chunk
    i=0
    InstalledApps=""
    for chunk in "${InstalledAppJsonArr[@]}"; do
        i=$(echo $i + 1 | bc)
        if [ "$i" == "1" ]; then
            InstalledApps=$(echo "\"InstalledApps$i\":\"$chunk\"")
        else
            InstalledApps="$InstalledApps,$(echo "\"InstalledApps$i\":\"$chunk\"")"
        fi
    done
    #echo $InstalledApps
    
    # Define the maximum installapps size limit in bytes
    max_installapps_size=$(echo -n "scale=2; 10.0 * 31 * 1024" | bc)
    #max_installapps_size=$((1 * 1 * 1))
    # Calculate the installapps size in bytes
    installapps_size=$(echo "scale=2; $(echo -n "$InstalledApps"| wc -c)"| bc)
    # Convert the installapps size to kilobytes with one decimal place
    installapps_size_kb=$(echo -n "scale=2; $installapps_size / 1024" | bc)
 
    if [ $(bc -l <<< "$installapps_size > $max_installapps_size") -eq 1 ]; then
        echo "InstalledApp is too big and exceed the 32kb limit per column for a single upload. Please increase number of columns (#10). Current payload size is: $installapps_size_kb kb"
        exit 1
    fi
 
    MainApp="[{\"ComputerName\":\"$ComputerName\",\"ManagedDeviceID\":\"$ManagedDeviceID\",$InstalledApps}]"
 
    ResponseAppInventory=$(Send-LogAnalyticsData "$CustomerId" "$SharedKey" "$MainApp" "$AppLog")
 
fi
#endregion APPINVENTORY

#region DEVICEINVENTORY
 
if [ "$CollectDeviceInventory" = true ]; then
    #Set Name of Log
    DeviceLog="PowerStacksDeviceInventory"
 
    # --- CPU Info ---
    cpu_manufacturer=$(sysctl -n machdep.cpu.vendor 2>/dev/null || echo "Apple")
    cpu_name=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Apple Silicon")
    if [[ "$cpu_name" == Apple* ]]; then
        cpu_vendor="Apple"
    else
        cpu_vendor=$(sysctl -n machdep.cpu.vendor 2>/dev/null || echo "Intel")
    fi
    cpu_physical=$(sysctl -n hw.packages)
    cpu_cores=$(sysctl -n hw.physicalcpu)
    cpu_logical=$(sysctl -n hw.logicalcpu)
    if [ "$cpu_vendor" != "Apple" ]; then
        cpu_max_clock=$(bc <<< "$(sysctl -n hw.cpufrequency_max)/1000") # MHz
    fi
    # --- Memory ---
    memory=$(sysctl -n hw.memsize)

    # --- Boot Time ---
    last_boot=$(sysctl -n kern.boottime | awk -F '[=,]' '{print $2}' | xargs -I{} date -u -r {} +"%Y-%m-%dT%H:%M:%S.0000000Z")

    # --- Device Info ---
    device_model=$(system_profiler SPHardwareDataType | awk -F': ' '/Model Identifier/{print $2}')
    device_manufacturer="Apple Inc."

    # --- Disk Info ---
    disk_id="disk0"
    disk_info=$(diskutil info "$disk_id")

    # Extract fields
    disk_model=$(echo "$disk_info" | awk -F': ' '/Device \/ Media Name/ {print $2}' | xargs)
    disk_bus=$(echo "$disk_info" | awk -F': ' '/Protocol/ {print $2}'| xargs)
    disk_type=$(echo "$disk_info" | awk -F': *' '/Solid State/ { print ($2 == "Yes" ? "SSD" : "HDD") }')
    disk_size_bytes=$(echo "$disk_info" | awk -F'[()]' '/Disk Size/ {gsub(/[^0-9]/, "", $2); print $2}')
    disk_smart=$(echo "$disk_info" | awk -F': ' '/SMART Status/ {print $2}' | xargs)
    disk_temp=$(ioreg -lw0 | grep -i "temperature" | grep -Eo '[0-9]+' | head -n 1)
    disk_temp="${disk_temp:-0}"
    if [ "$disk_smart" == "Verified" ]; then
        disk_smart="Healthy"
    fi

    # --- Battery Info ---
    battery_check=$(pmset -g batt 2>&1)

    if [[ "$battery_check" != *"No battery"* ]]; then
        battery_data=$(ioreg -r -n AppleSmartBattery)
        if [ "$cpu_vendor" == "Apple" ]; then
            max_capacity=$(echo "$battery_data" | awk '/"AppleRawMaxCapacity" / { print $NF }')
        else
            max_capacity=$(echo "$battery_data" | awk '/"MaxCapacity" / { print $NF }')
        fi
        design_capacity=$(echo "$battery_data" | awk '/"DesignCapacity" / { print $NF }')
        battery_health=""
        if [ -n "$max_capacity" ] && [ -n "$design_capacity" ]; then
            percent=$(echo "scale=2; $max_capacity/$design_capacity*100" | bc)
            battery_health=$(printf "%.2f" "$percent")
        fi
    fi

    # --- Build Raw JSON ---
    DeviceDetails="
    {
    \"Memory\": \"$memory\",
    \"CPUManufacturer\": \"$cpu_manufacturer\",
    \"CPUName\": \"$cpu_name\",
    \"CPUMaxClockSpeed\": \"$cpu_max_clock\",
    \"CPUPhysical\": \"$cpu_physical\",
    \"CPUCores\": \"$cpu_cores\",
    \"CPULogical\": \"$cpu_logical\",
    \"LastBootTime\": \"$last_boot\",
    \"BatteryHealthPercent\": \"$battery_health\",
    \"BatteryFullChargedCapacity\": \"$max_capacity\",
    \"BatteryDesignedCapacity\": \"$design_capacity\",
    \"PhysicalDisks\": [
        {
        \"BusType\": \"$disk_bus\",
        \"HealthStatus\": \"$disk_smart\",
        \"Manufacturer\": \"Apple\",
        \"Model\": \"$disk_model\",
        \"Size\": \"$disk_size_bytes\",
        \"Type\": \"$disk_type\",
        \"Temperature\": \"$disk_temp\"
        }
    ],
    \"DeviceManufacturer\": \"$device_manufacturer\",
    \"DeviceModel\": \"$device_model\"
    }"

    DeviceDetailsJson=$(echo -n "$DeviceDetails" | iconv -t utf-8 | gzip -c -n | base64 | tr -d '\n')


    MainDevice="[{\"ComputerName\":\"$ComputerName\",\"ManagedDeviceID\":\"$ManagedDeviceID\",\"DeviceDetails1\":\"$DeviceDetailsJson\"}]"
 
    ResponseDeviceInventory=$(Send-LogAnalyticsData "$CustomerId" "$SharedKey" "$MainDevice" "$DeviceLog")
 
fi
#endregion DEVICEINVENTORY
 
#Report back status
 
# Get current date in the specified format
date=$(date -u +"%d-%m %H:%M")
 
# Initialize output message
output_message="InventoryDate: $date"
 
# Check CollectDeviceInventory flag
if [ "$CollectDeviceInventory" = true ]; then
    # Check response for DeviceInventory
    if [[ "$ResponseDeviceInventory" =~ "200 :" ]]; then
        output_message="$output_message DeviceInventory: OK $ResponseDeviceInventory"
    else
        output_message="$output_message DeviceInventory: Fail - $ResponseDeviceInventory"
        exit 1
    fi
fi
 
# Check CollectAppInventory flag
if [ "$CollectAppInventory" = true ]; then
    # Check response for AppInventory
    if [[ "$ResponseAppInventory" =~ "200 :" ]]; then
        output_message="$output_message AppInventory: OK $ResponseAppInventory"
    else
        output_message="$output_message AppInventory: Fail - $ResponseAppInventory"
        exit 1
    fi
fi
 
echo "$output_message"
exit 0
 
#endregion script
