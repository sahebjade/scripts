param(
  [string]$ssh_keys
)

$remote_path = ''
$packages = "openssh,rsync,procps,cygrunsrv,lynx,wget,curl,bzip,tar,make,gcc-c,gcc-g++,libxml2"
$username = "azure"


try {

	# 1. Download and install Cygwin
    if (!(Test-Path "C:\cygwin64\bin\bash.exe"))
	{
		#Downloading setup.exe and determine offline/online mode
		if(($remote_path.Length -ne 0) -And (Test-Path $remote_path))
		  {
			$path = "$remote_path\Cygwin"
			$arg_list = "-q -n -R C:\cygwin64 -P $packages -L -l $path\CygwinPackages"
			$mode = "offline"
		  }
		else
		  {
			$path = "C:\Windows\Temp"
			$arg_list = "-q -n -R C:\cygwin64 -P $packages -s http://cygwin.mirror.constant.com/"
			$mode = "online"
			Write-Host "Downloading Cygwin setup.exe"
			wget "https://cygwin.com/setup-x86_64.exe" -outfile "$path\CygwinSetup-x86_64.exe"
		  }

		#Installing Cygwin
		Write-Host "Installing Cygwin from $mode repo"
		Start-Process -PassThru -Wait -FilePath "$path\CygwinSetup-x86_64.exe" -ArgumentList $arg_list
	}


	# 2. Set up sshd service
	if (!(Get-Service sshd -ErrorAction Ignore))
	{
		#generate a random password
		[Reflection.Assembly]::LoadWithPartialName("System.Web")
		$random_password = "Ez1!_"+[System.Web.Security.Membership]::GeneratePassword(20,0)

		Invoke-Command -ScriptBlock {C:\cygwin64\bin\bash.exe --login -i ssh-host-config -y -c "tty ntsec" -N "sshd" -u "cyg_server" -w $random_password}
		# Create allow firewall rule for SSH traffic
		Write-Host "Creating SSH-Inbound firewall rule"
		Invoke-Command -ScriptBlock {netsh advfirewall firewall add rule name="SSH-Inbound" dir=in action=allow enable=yes localport=22 protocol=tcp}
	}

    # 3. Start sshd service
    if ((Get-Service sshd).Status -ne "Running") {Start-Service sshd}

}
catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Throw "Cygwin-Install failed at $FailedItem. The error message was $ErrorMessage"
}


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
