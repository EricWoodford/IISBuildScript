<# 
.SYNOPSIS 
    enable IIS and FTP on local machine

.DESCRIPTION 
    Script will enable the windows features, then if optional parameters are specified, it will configure IIS to meet those needs.

.NOTES 
    
 
.COMPONENT 
    Requires Module ActiveDirectory
 
.LINK 
    https://github.com/scriptrunner/ActionPacks/tree/master/ActiveDirectory/Users 

.Parameter ConfigureWebsite
    Include this switch to create the web folder on the drive and folder specified.

.Parameter Web_drive_letter
    drive letter for the web site's default install folder.  (D, E..)

.Parameter web_path
    folder where IIS will be configured to look for new websites. Default value is 'CA.Web'
 
.Parameter AdminGroup
    The security group that will be granted permissions to the website folder. Default value is 'TDC\WebServerAdmin Group'

.Parameter ConfigureFTP
    Include this switch to configure default FTP server.

.Parameter RemoveWeb
    Include this switch to remove the web feature from the server.

.Parameter RemoteFTP
    Include this switch to remove the FTP feature from the server. 
    
.EXAMPLE
    .\installIIS-2019.ps1 
    Installs IIS feature 

.EXAMPLE
    .\InstallIIS-2019.ps1 -ConfigureWebSite -web_drive_letter D
    Install IIS feature, creates folder on drive D called CA.Web and configures permissions for the TDC\WebServerAdmin Group to the folder. 

.EXAMPLE
    .\InstallIIS-2019.ps1 -ConfigureWebSite -web_drive_letter D -web_path 'EDDWebServer' -adminGroup 'edd\webAdmins' -configureFTP
    Install IIS feature, creates folder on drive D called EDDWebServer and configures permissions for the EDD\WebAdmins Group to the folder. In addition, enables the FTP service and grants the EDD\WebAdmins group permissions.     
#>


[CmdLetBinding()]
param( 
    [parameter(Mandatory = $false, ParameterSetName = "configWeb")]
    [switch]$configureWebsite,
    [parameter(Mandatory = $false)]    
    [switch]$removeWeb,    
    [parameter(Mandatory = $false, ParameterSetName = "configWeb")]
    [string]$Web_Drive_letter,
    [parameter(Mandatory = $false, ParameterSetName = "configWeb")]
    [string]$Web_Path = "CA.Web",
    [parameter(Mandatory = $false)]    
    [string]$AdminGroup = "TDC\WebServerAdmin Global",
    [parameter(Mandatory = $false)]
    [switch]$ConfigureFTP,
    [parameter(Mandatory = $false)]    
    [switch]$removeFTP
)
# with no switches, the script will install the windows features for IIS
# when variables are specified it will configure different items on the server. 


# variable used to track if a reboot is required after any portion of script. 
$restartNeeded = $false

#$Name = "World Wide Web Publishing Service"
$webService = Get-Service -name W3SVC -ErrorAction SilentlyContinue 
$FTPService = Get-Service -name FTPSV -ErrorAction SilentlyContinue 

# might be useful to capture if reboot necessary. 
# ref: https://devblogs.microsoft.com/scripting/use-powershell-to-find-servers-that-need-a-reboot/
#get-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" 

### Install IIS and features ###
import-module servermanager, WebAdministration
if ($removeWeb) {
    $CaptureInstall = remove-WindowsFeature Web-Server, Web-Http-Redirect, Web-ASP, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Includes, Web-Log-Libraries, Web-Http-Tracing, Web-Basic-Auth, Web-Windows-Auth, Web-IP-Security, Web-Url-Auth, Web-Scripting-Tools, Web-Mgmt-Service, Web-FTP-Server, Web-Ftp-Service, Web-Dyn-Compression, Web-Mgmt-Console 
    $restartNeeded = $restartNeeded -or ($CaptureInstall.restartNeeded -eq "yes")
} 

if ($null -eq $webService) {
    $CaptureInstall = Add-WindowsFeature Web-Server, Web-Http-Redirect, Web-ASP, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Includes, Web-Log-Libraries, Web-Http-Tracing, Web-Basic-Auth, Web-Windows-Auth, Web-IP-Security, Web-Url-Auth, Web-Scripting-Tools, Web-Mgmt-Service, Web-FTP-Server, Web-Ftp-Service, Web-Dyn-Compression, Web-Mgmt-Console 
    $restartNeeded = $restartNeeded -or ($CaptureInstall.restartNeeded -eq "yes")
    if ($catpureInstall.exitCode -ne "Success") { return "failed to install Windows Features" }
}


# add .net components
$captureInstall = Install-WindowsFeature Net-Framework-Core -source \\network\share\sxs
$restartNeeded = $restartNeeded -or ($CaptureInstall.restartNeeded -eq "yes")

if ((get-WindowsFeature web-asp-net).installstate -ne "Installed") {
    $captureInstall = add-windowsfeature web-asp-net
    $restartNeeded = $restartNeeded -or ($CaptureInstall.restartNeeded -eq "yes")
}
if ((get-WindowsFeature web-asp-net45).installstate -ne "Installed") {
    #Install-WindowsFeature Web-Asp-Net45 -source c:\windows\winsxs
    $captureInstall = add-windowsfeature Net-Framework-45-Core
    $restartNeeded = $restartNeeded -or ($CaptureInstall.restartNeeded -eq "yes")
}

### Remove default site and app pools ###
Remove-WebSite -name *
Remove-WebAppPool -name *


### Configure server level HTTP settings ###

set-webconfigurationproperty /system.applicationHost/sites/siteDefaults/logFile -name logExtFileFlags -value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"
set-webconfigurationproperty /system.applicationHost/sites/siteDefaults/logFile -name localTimeRollover -value "True"
set-webconfigurationproperty /system.applicationHost/log -name logInUTF8 -value "False"
set-webconfigurationproperty /system.webServer/security/authentication/anonymousAuthentication -name userName -value ""
set-webconfigurationproperty /system.applicationHost/applicationPools/applicationPoolDefaults -name managedRuntimeVersion -value "v4.0"

if ($ConfigureFTP) {
    ### Configure sever level FTP settings ###

    set-webconfigurationproperty /system.applicationHost/sites/siteDefaults/ftpserver/logFile -name logExtFileFlags -value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,FtpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,Host,FtpSubStatus,Session,FullPath,Info,ClientPort"
    set-webconfigurationproperty /system.applicationHost/sites/siteDefaults/ftpserver/logFile -name localTimeRollover -value "True"
    
    set-webconfigurationproperty /system.ftpserver/log -name logInUTF8 -value "False"
    set-webconfigurationproperty /system.applicationhost/sites/siteDefaults/ftpserver/security/authentication/basicauthentication -name Enabled -value True
    set-webconfigurationproperty /system.ftpserver/firewallsupport -name LowDataChannelPort -value 50000
    set-webconfigurationproperty /system.ftpserver/firewallsupport -name HighDataChannelPort -value 50050
    set-webconfigurationproperty /system.applicationhost/sites/siteDefaults/ftpserver/security/ssl -name ssl128 -value True
    ###$hostname = hostname
    ###$cert = get-childitem cert:/localmachine/my | where-object {$_.subject -eq "CN=WMSvc-$hostname"}
    $cert = get-childitem cert:/localmachine/my | where-object { $_.subject -eq "CN=WMSVC-SHA2" }
    set-webconfigurationproperty /system.applicationhost/sites/siteDefaults/ftpserver/security/ssl -name serverCertHash -value $cert.thumbprint
    Add-WebConfiguration -Filter /System.FTPServer/Security/Authorization -PSPath 'IIS:\' -Value (@{AccessType = "Allow"; Users = $AdminGroup; Roles = $AdminGroup; Permissions = "Read, Write" })
}

if ($configureWebsite) {
    if ($Web_Drive_letter -like "*:") { $Web_Drive = $Web_Drive_letter + "\" } 
    else { $web_drive = $(get-psDrive -name $web_drive_letter).root }
    if ($null -eq $web_drive -or $Web_Drive -eq "") { return "invalid drive requested" }

    $Web_folder = $web_drive + $Web_Path
    ### Create WAU folder structure ###
    if (!(test-path -path $web_folder)) { New-Item -Type Directory -Path $web_drive -Name $Web_Path }
    if (!(test-path -path $($web_folder + "/certs"))) { New-Item -Type Directory -Path $Web_folder -Name Certs }
    if (!(test-path -path $($web_folder + "/LogFiles"))) { New-Item -Type Directory -Path $Web_folder -Name LogFiles }
    if (!(test-path -path $($web_folder + "/Sites"))) { New-Item -Type Directory -Path $Web_folder -Name Sites }
    if (!(test-path -path $($web_folder + "/Utils"))) { New-Item -Type Directory -Path $Web_folder -Name Utils }
    compact.exe /c /s $($Web_folder + "\LogFiles")
    Attrib.exe +i $($Web_folder + "\LogFiles")

    set-webconfigurationproperty /system.applicationHost/sites/siteDefaults/logFile -name directory -value $($Web_folder + "\LogFiles")
    set-webconfigurationproperty /system.applicationHost/sites/siteDefaults/ftpserver/logFile -name directory -value $($Web_folder + "\LogFiles")

    ### Set permissions oN WAU folder Structure ###

    $acl = Get-Acl $Web_folder
    $acl.SetAccessRuleProtection($True, $False)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("System", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($AdminGroup, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl $Web_folder $acl
}


if ($restartNeeded ) {
    write-verbose "reboot required. "
    #triggers reboot with 60s delay.
    Restart-Computer -timeout 60 -force
}

