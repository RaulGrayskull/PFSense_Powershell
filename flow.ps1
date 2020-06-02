$Flow = @{
    "alias" = @{
        "print" = "param(`$InputObject); Write-PFAlias -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Entry,`$Type) ; Add-pfalias -InputObject `$InputObject -Alias `$Alias -Type `$Type -address `$Address -detail `$detail -Description `$Description"
        "Delete" = "param(`$InputObject,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Entry,`$Type) ; Delete-pfalias -InputObject `$InputObject -Alias `$Alias"
        "AddEntry" = "param(`$InputObject,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Entry,`$Type) ; AddEntry-pfalias -InputObject `$InputObject -Alias `$Alias -address `$Address -detail `$detail"
        "DeleteEntry" = "param(`$InputObject,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Entry,`$Type) ; DeleteEntry-pfalias -InputObject `$InputObject -Alias `$Alias -detail `$detail"
    }

    "dhcpd" = @{
        "print" = "param(`$InputObject); Write-PFDHCPd -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$Network,`$Gateway,`$Description) ; Add-PFDHCPd -InputObject `$InputObject -Interface `$Interface -From `$From -To `$To -netmask `$netmask -Domain `$Domain -Gateway `$Gateway -DNSServer `$DNSServer -NTPServer `$NTPServer "
        "Set" = "param(`$InputObject,`$Network,`$Gateway,`$Description) ; Add-PFDHCPd -InputObject `$InputObject -Interface `$Interface -From `$From -To `$To -netmask `$netmask -Domain `$Domain -Gateway `$Gateway -DNSServer `$DNSServer -NTPServer `$NTPServer "

    } 
    "dhcpStaticMap" = @{
        "print" = "param(`$InputObject); Write-PFDHCPstaticmap -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr) ; Add-PFDHCPstaticmap -InputObject `$InputObject -Interface `$Interface -Hostname `$Hostname -Domain `$Domain -ClientID `$ClientID -MACaddr `$MACaddr -Address `$Address -Description `$Description -Gateway `$Gateway -DNSserver `$DNSserver -NTPServer `$NTPServer"
        "Delete" = "param(`$InputObject,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr) ; Delete-PFDHCPstaticmap -InputObject `$InputObject -Interface `$Interface -Hostname `$Hostname -Domain `$Domain -ClientID `$ClientID -MACaddr `$MACaddr -Address `$Address -Description `$Description -Gateway `$Gateway -DNSserver `$DNSserver -NTPServer `$NTPServer"
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