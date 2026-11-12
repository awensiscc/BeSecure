
$output = Get-NetTCPConnection | 
 Where-Object State -contains 'Established' | 
 Select-Object RemoteAddress, RemotePort, State,OwningProcess, 
 @{Name="ProcessName"; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

$output | ConvertTo-Json -Depth 5 | Out-File connections.json -Encoding UTF8