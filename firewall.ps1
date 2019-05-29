#
# firewall.ps1
#
# Get-NetFirewallRule >> x.txt to see what the empty paths are referencing.
#

# Disable NetBIOS
ForEach ($adapter In Get-WmiObject -Class Win32_NetWorkAdapterConfiguration -Filter "IPEnabled=$true" | Select-Object -Property Description,TcpipNetbiosOptions) {
    If($adapter.TcpipNetbiosOptions -ne 2) {
        $adapter.TcpipNetbiosOptions = 2
        Write-Host "NetBIOS disabled on"$adapter.Description
    }
}

ForEach($rule In Get-NetFirewallRule | Get-NetFirewallApplicationFilter) {
    If(-not $rule.AppPath) { # UWP apps have no paths.
        If($rule.CreationClassName.Substring(0, 22) -ne 'MSFT|FW|FirewallRule|{') { # Crude check for Windows 10 apps.
            Write-Host 'REMOVING ID: ' $rule.InstanceID
            Get-NetFirewallRule $rule.InstanceID | Remove-NetFirewallRule
            #} else {
            #Write-Host $rule.CreationClassName
            #Get-NetFirewallRule $rule.InstanceID | Format-List Platform
        }
        } else { # Firewall rule contains a path.
        If(-not (Test-Path $rule.AppPath) -and $rule.AppPath -ne 'System'-and $rule.AppPath.ToLower().IndexOf('\system32\svchost.exe') -eq -1) { # Crude check for Windows 10 itself.
            Write-Host 'REMOVING APP:' $rule.AppPath
            Get-NetFirewallRule $rule.InstanceID | Remove-NetFirewallRule
        }
    }
}