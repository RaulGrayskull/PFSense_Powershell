$Flow = @{
    "alias" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFAlias"
    }

    "gateway" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFGateway"
#        "print" = "param(`$InputObject); `$InputObject | Get-PFGateway | Format-Table *"
    }

    "interface" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFInterface"
    }

    "StaticRoute" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFStaticRoute"
    }

    "dnsResolver" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFUnbound"
    }    

    "dnsResolverHost" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFUnboundHost"
    }   
 
    "portfwd" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFNATRule"
    }    
    "Firewall" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFFirewallRule"
    } 
    "dhcpd" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFDHCPd"
    } 
    "dhcpStaticMap" = @{
        "print" = "param(`$InputObject); Write-PFObject -InputObject `$InputObject -PFObjectType PFDHCPStaticMap"
    }  

}