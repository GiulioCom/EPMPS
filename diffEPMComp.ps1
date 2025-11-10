# Define the paths to your two CSV files
$fileEndpointReport = "C:\Users\giulioc\Desktop\Volvo\Endpoints_03-Oct-25-10-35-05.csv"
$fileMyComputerReport = "C:\Users\giulioc\Desktop\Volvo\MyComputer_04-Oct-25-10-35-14.csv"

# 1. Import all data
$allRefData = Import-Csv -Path $fileEndpointReport
$allDiffData = Import-Csv -Path $fileMyComputerReport

# 2. Extract and filter the Computer names to compare (removes any blank/null entries)
$refComputers = $allRefData.Computer | Where-Object { $_ }
$diffComputers = $allDiffData.Computer | Where-Object { $_ }

# 3. Compare the lists of computer names
# Find names in $diffComputers ($fileMyComputerReport) that are NOT in $refComputers ($fileEndpointReport)
$missingNames = Compare-Object `
    -ReferenceObject $refComputers `
    -DifferenceObject $diffComputers `
    | Where-Object { $_.SideIndicator -eq '=>' } `
    | Select-Object -ExpandProperty InputObject

# 4. Use the missing names to retrieve the full object details from the original report
Write-Host "--- Computers present in MyComputerReport but missing in EndpointReport ---"
$missingComputers = $allDiffData | Where-Object { $_.Computer -in $missingNames }

# 5. Print the results (or export to a new CSV)
$missingComputers | Select-Object "Computer", "Agent Version", "Last Seen" | Format-Table -AutoSize

# Optional: Export the results to a new CSV
$missingComputers | Export-Csv -Path "C:\Users\giulioc\Desktop\Volvo\Missing_Computers.csv" -NoTypeInformation