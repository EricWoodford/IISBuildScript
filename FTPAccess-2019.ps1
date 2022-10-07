### Script setup ###

Trap {Continue} Stop-Transcript
Start-Transcript -path D:\PS\Deploy\FTPAccess-2019.log -append
Import-Module WebAdministration

### Prompt for information ###

$SiteID = Read-Host "Please enter the IIS Site ID"
$FTPGroup = Read-Host "Please enter AD group or user to grant FTP access (such as TDC\WebServerConsulting Global)"

$Confirm = Read-Host "Please verify the above information is correct. If it is, type continue"
If ($Confirm -eq "continue")
{

### Get Site Info ###

$SiteInfo = Get-WebSite | Where-Object {$_.ID -eq $SiteID}

### Grant NTFS access ###

$Path = $SiteInfo.PhysicalPath
$acl = Get-Acl $Path
$acl.SetAccessRuleProtection($False, $True)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($FTPGroup,"Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $path $acl

### Grant FTP authorization ###

$Name = $SiteInfo.Name
Add-WebConfiguration -Filter /System.FTPServer/Security/Authorization -PSPath 'IIS:\' -Value (@{AccessType="Allow"; Users=""; Roles="$FTPGroup"; Permissions="Read, Write"}) –Location $Name

}

### Script clean up ###

Stop-Transcript