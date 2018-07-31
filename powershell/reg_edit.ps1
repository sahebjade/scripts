$RegKey = "HKLM:\System\CurrentControlSet\Services\HTTP\Parameters"


if(!(Test-path -Path $RegKey)) {
     New-Item $RegKey -Force
}

$maxFieldLength = (Get-ItemProperty -Path $RegKey).MaxFieldLength

$maxRequestBytes = (Get-ItemProperty -Path $RegKey).MaxRequestBytes

if(($maxFieldLength -ne 65534) -or ($maxRequestBytes -ne 16777216)) {
  Set-ItemProperty -Path $RegKey -Name "maxFieldLength" -Value 65534 -Type "DWord"
  Set-ItemProperty -Path $RegKey -Name "maxRequestBytes" -Value 16777216 -Type "DWord"

  Write-Host "maxFieldLength and maxRequestBytes value set..."
}
else {
  Write-Host "maxFieldLength and maxRequestBytes value already set..."
}
