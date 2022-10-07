D:
cd DTSWeb\Logfiles

### The next line for viewing the removing logs before deleting (change -whatif to -force) to delete.
### get-childitem –include *.log -recurse|where-object {$_.LastWriteTime –lt (get-date).AddDays(-180)}|remove-item –whatif

get-childitem –include *.log -recurse|where-object {$_.LastWriteTime –lt (get-date).AddDays(-180)}|remove-item –force


