<#
.SYNOPSIS
   Compress then purge old IIS logs
.DESCRIPTION
   Looks for Log files over a certain date. 
   	 - Compress files that are over a certain date to ZIP format. 
	 - Delete ZIP files that exceed longer date. 
   Uses 7ZIP if installed - needs it if running as a scheduled task.
       Download: http://7-zip.org/
 #>

#default values for run-time
$folderRoot = "C:\inetpub\logs\LogFiles\"
$compressAfter = 14
$deleteAfter = 367

#variables for folder management
invoke-expression $(get-content .\schedTask.ini)
if ($null -eq $folderRoot) { return "couldn't read config file." }
if (!(Test-Path -Path $folderRoot)) { return "invalid log file path" }


$Folders = Get-ChildItem $folderRoot *. | Select-Object -ExpandProperty fullname

ForEach ($FolderPath in $folders) {
    #Folder path to where the IIS logs reside.
    #$FolderPath = "C:\inetpub\logs\LogFiles\W3SVC1\"

    #LOGS older than this date (-7 days ago) will be compressed.
    $CompressLogsDate = (Get-Date).AddDays($compressAfter)

    #ZIPs older than this date (-30 days ago) will be deleted.
    $OldestZIPDate = (Get-Date).AddDays($deleteAfter)

    if ($null -eq $(get-command "compress-7zip")) {
        # -and ((Get-WmiObject -Class Win32_OperatingSystem -ComputerName "." -ea 0).OSArchitecture -eq "64-bit")) {
        # if machine is a 64bit OS, it downloads and installs 7Zip from vendor site. 
        # ref: https://gmusumeci.medium.com/unattended-install-of-7-zip-using-powershell-1387ceb1e714
        write-verbose "installing 7zip"
        #$Installer7Zip = $env:TEMP + "\7z1900.msi"; 
        #Invoke-WebRequest "https://www.7-zip.org/a/7z1900-x64.msi" -OutFile $Installer7Zip; 
        #msiexec /i $Installer7Zip /qb;
        #Remove-Item $Installer7Zip;
        #$Use7Zip = (test-path $7_64Bit_ZipPath)
        #set-alias sz $7_64Bit_ZipPath

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force;
        Set-PSRepository -Name 'PSGallery' -SourceLocation "https://www.powershellgallery.com/api/v2" -InstallationPolicy Trusted;
        Install-Module -Name 7Zip4PowerShell -Force;
        
    }
    

    $Use7Zip = ($null -ne $(get-command "compress-7zip")) 
    #Delete ZIPs over a specific date
    $ZipPath = $FolderPath + "\" + "*.log"
    $RemoveZips = Get-ChildItem $ZipPath | where-object { $_.creationtime -lt $OldestZIPDate }
    if ($RemoveZips) {
        #Delete ZIP files older than $OldestZIPDate.
        write-host "Outdated LOG files:", $RemoveZips.Count
        ForEach ($zip in $RemoveZips) {
            Remove-Item $zip.VersionInfo.FileName.tostring()
        }
    } 

    $ZipPath = $FolderPath + "\" + "*.zip"
    $RemoveZips = Get-ChildItem $ZipPath | where-object { $_.creationtime -lt $OldestZIPDate }
    if ($RemoveZips) {
        #Delete ZIP files older than $OldestZIPDate.
        write-host "Outdated ZIP files:", $RemoveZips.Count
        ForEach ($zip in $RemoveZips) {
            Remove-Item $zip.VersionInfo.FileName.tostring()
        }
    } 

    #Find Logs that are older than specific date.
    $LogPath = $FolderPath + "\" + "*.log"
    $Oldlogs = Get-ChildItem $LogPath | where-object { $_.lastwritetime -lt $CompressLogsDate }

    if ($Oldlogs) {
        #Process old log files.
        write-host "LOG files (<30d):", $Oldlogs.Count
        ForEach ($Log in $Oldlogs) {
            $LogFileStr = $Log.VersionInfo.FileName.tostring() 
            $TempZipName = $LogFileStr.replace(".log", ".zip")
            if (!(Test-Path $tempZipName)) {
                #Create a new ZIP if one doesn't exist
                if ($Use7Zip ) {
                    #Use 7Zip if using a scheduled task. 				
                    #sz a -tzip $TempZipName $LogFileStr 
                    
                    compress-7zip -ArchiveFileName $TempZipName -Path $Folders -Format zip -append 
                }
                else { break }
                #Give new ZIP, same last write date as original log file. 
                $ZipObj = (Get-Item $tempZipName) 
                $ZipObj.creationtime = $log.lastWriteTime
                $ZipObj.LastWriteTime = $log.lastWriteTime
            }
            $newZipFile = Get-Item $TempZipName 
            $CreatedTodayBool = $newZipFile.creationtime -gt (get-date).addhours(-1)
            if ($newZipFile.length -gt 1kb -or $Use7Zip) { 
                #Delete original LOG file it ZIP is larger than creation size. 
                if (Test-Path $log) { Remove-Item $Log }
            }
            else {
                #Make sure not deleting zips created in last hour. Might still be compressing files. 
                if (!$CreatedTodayBool -or $Use7Zip) {
                    #Delete ZIP files that are only 1KB in size. 
                    Remove-Item $tempZipName 
                }
            }

        }
    }
    else {
        write-host "No old log files: ", $FolderPath
    }
}