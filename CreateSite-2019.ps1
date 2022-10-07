### Script setup ###
Trap {Continue} Stop-Transcript
Start-Transcript -path D:\PS\Deploy\CreateSite-2016.log -append

### Prompt for information ###

$AgencyCode = Read-Host "Please enter the agency code (such as EDD)"
$URL = Read-Host "Please enter website URL, without www (such as webtools.ca.gov)"
$PartialIP = Read-Host "Please enter last part of IP address, with a dot and 3 numbers always (such as .004)"
$FullIP = Read-Host "Please enter the full IP address (such as 134.186.25.187). If this Site should not be bound to an IP, enter *"
$HostHeader = Read-Host "If the Site uses host header(s), please enter full URL (such as www.webtools.ca.gov). If host headers are not used, please press <enter>"

$Confirm = Read-Host "Please verify the above information is correct. If it is, type next"
If ($Confirm -eq "next")
{

### Variable setup ###

$Name = "WWW $PartialIP $AgencyCode $URL"
$Path = "D:\DTSWeb\Sites\$AgencyCode\$URL\wwwroot"
$HostHeader = $HostHeader.Split(",")

### Create site and logfiles directory structure ###

New-Item -Type Directory -Path D:\DTSWeb\Sites -Name $AgencyCode
New-Item -Type Directory -Path D:\DTSWeb\Sites\$AgencyCode -Name $URL
New-Item -Type Directory -Path D:\DTSWeb\Sites\$AgencyCode\$URL -Name wwwroot
New-Item -Type Directory -Path D:\DTSWeb\LogFiles -Name $AgencyCode
New-Item -Type Directory -Path D:\DTSWeb\LogFiles\$AgencyCode\$URL
Copy-Item Default.htm $Path

### Create IIS site and app pool ###
Import-Module WebAdministration

$ID = (Dir IIS:\Sites | ForEach {$_.ID} | Sort -Descending | Select -First 1) + 1
New-WebSite -Name $Name -Port 80 -PhysicalPath $Path -IPAddress $FullIP -ID $id
New-WebAppPool -Name $Name
Set-ItemProperty IIS:\AppPools\$Name -Name managedRuntimeVersion -Value v4.0

### Remove default binding and add bindings to site ###

Get-WebBinding -Port 80 -Name $Name | Remove-WebBinding
ForEach ($Header in $HostHeader)
{
    New-WebBinding -Name $Name -Port 80 -IPAddress $FullIP -HostHeader $Header -Protocol http
    New-WebBinding -Name $Name -Port 21 -IPAddress $FullIP -HostHeader $Header -Protocol ftp
}

### Assign app pool to site ###

Set-ItemProperty IIS:\Sites\$Name -Name ApplicationPool -Value "$Name"


### Configure FTP and HTTP logging directories ###
$logpath = "D:\DTSWeb\LogFiles\$AgencyCode\$URL"
Set-ItemProperty IIS:\Sites\$Name -Name logFile -value @{directory=$LogPath}
Set-ItemProperty IIS:\Sites\$Name -Name FtpServer.LogFile -value @{directory=$LogPath}
#Set-ItemProperty IIS:\Sites\$Name -Name LogFile.Directory -Value "D:\DTSWeb\LogFiles\$AgencyCode\$URL"
#Set-ItemProperty IIS:\Sites\$Name -Name FtpServer.LogFile.Directory -Value "D:\DTSWeb\LogFiles\$AgencyCode\$URL" 


### Make request to site to initialize application pool ###

$IPAddress = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPENABLED=TRUE | Select -expand IPAddress -first 1
$WebRequest = [net.WebRequest]::Create("http://" + $IPAddress)
Try { $Response = $WebRequest.GetResponse() }
Catch { }

### Set permissions on wwwroot folder ###

$acl = Get-Acl $Path
$acl.SetAccessRuleProtection($False, $True)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS AppPool\$Name","ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $Path $acl

}

### Script clean up ###

Stop-Transcript
