### Copy 2 files to run and setup RemoveOldLogs scheduler task

set-ExecutionPolicy 0 –force   
Copy-Item RemoveOldlogs.ps1 D:\DTSWeb\Logfiles
Copy-Item RemoveOldlogs.xml D:\DTSWeb\Logfiles

### Import RemoveOldLogs.xml to create RemoveOldLogs scheduler task
schtasks.exe /create /RU SYSTEM /TN RemoveOldLogs /XML D:\DTSWeb\Logfiles\removeOldLogs.xml