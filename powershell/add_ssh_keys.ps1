param(
  [string]$ssh_keys
)

$username = "azure"

Function Get-RandomPassword ($length = 14)
{
  $punc = 40..46 + 33 + 35..38
  $digits = 48..57
  $letters = 65..90 + 97..122

  [System.Collections.ArrayList]$al_index = 1..($length-1)
  [System.Collections.ArrayList]$al_value = (Get-Random -Count $length -Input ($punc + $digits + $letters) |  % -Begin { $aa = $null } -Process {$aa += [char]$_} -End {$aa}).ToCharArray()

  #1st character can only be alphanumeric
  $al_value[0] = [char](Get-Random -Count 1 -Input ($digits + $letters))

  #Replace random characters (excluding first) with values from each group
  foreach ($group in ($punc, $digits, $letters))
  {
    $pos = Get-Random -Count 1 -Input ($al_index)
    $al_value[$pos] = [char](Get-Random -Count 1 -Input ($group))
    $al_index.Remove($pos)
  }

  [string]$sPassword = -Join $al_value
  return $sPassword
}

#generate a random password
$random_password = Get-RandomPassword(14)

#Add a local user
Invoke-Command -ScriptBlock {net user $username ""$random_password"" /add}

#Add the user to administrators group
Invoke-Command -ScriptBlock {net localgroup Administrators $username /add}


$config_file = "C:\cygwin64\home\$($username)\.ssh\authorized_keys"

if(!(Test-Path -Path $config_file)) {
  New-Item $config_file -type file -force
}
Add-Content $config_file -Value $ssh_keys

#Make this user an owner of home dir
Invoke-Command -ScriptBlock {icacls "C:\cygwin64\home\$($username)" /setowner $username /T /C /q}
