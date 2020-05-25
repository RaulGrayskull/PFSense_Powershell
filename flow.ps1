$Flow = @{
    "alias" = @{
        "print" = "param(`$InputObject); Write-PFAlias -InputObject `$InputObject"
    }

    "dhcpd" = @{
        "print" = "param(`$InputObject); Write-PFDHCPd -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$Network,`$Gateway,`$Description) ; Add-PFDHCPd -InputObject `$InputObject -Interface `$Interface -From `$From -To `$To -netmask `$netmask -Domain `$Domain -Gateway `$Gateway -DNSServer `$DNSServer -NTPServer `$NTPServer "
    } 
    "dhcpStaticMap" = @{
        "print" = "param(`$InputObject); Write-PFDHCPstaticmap -InputObject `$InputObject"
    }  
    "dnsResolver" = @{
        "print" = "param(`$InputObject); Write-PFUnbound -InputObject `$InputObject"
    }    
    "dnsResolverHost" = @{
        "print" = "param(`$InputObject); Write-PFUnboundHost -InputObject `$InputObject"
    }   
    "Firewall" = @{
        "print" = "param(`$InputObject); Write-PFFirewall -InputObject `$InputObject"
    } 

    "gateway" = @{
        "print" = "param(`$InputObject); Write-PFGateway -InputObject `$InputObject"
    }

    "interface" = @{
        "print" = "param(`$InputObject); Write-PFInterface -InputObject `$InputObject"
    }

    "portfwd" = @{
        "print" = "param(`$InputObject); Write-PFNatRule -InputObject `$InputObject"
    }    

    "StaticRoute" = @{
        "print" = "param(`$InputObject); Write-PFStaticRoute -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$Network,`$Gateway,`$Description) ; Add-PFStaticRoute -InputObject `$InputObject -Network `$Network -Gateway `$Gateway -Description `$Description"
    }
    "Vlan" = @{
        "print" = "param(`$InputObject); Write-PFVlan -InputObject `$InputObject"
    }
}