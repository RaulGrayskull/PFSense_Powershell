$Flow = @{
    "All" = @{
        "Save" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Save-PFAll -InputObject `$InputObject -path `$path -File `$file"
        "Restore" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Restore-PFAll -InputObject `$InputObject -path `$path -File `$file"
    }


    "alias" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFAlias -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Add-pfalias -InputObject `$InputObject -Alias `$Alias -Type `$Type -address `$Address -detail `$detail -Description `$Description"
        "Delete" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Delete-pfalias -InputObject `$InputObject -Alias `$Alias"
        "AddEntry" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; AddEntry-pfalias -InputObject `$InputObject -Alias `$Alias -address `$Address -detail `$detail"
        "DeleteEntry" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; DeleteEntry-pfalias -InputObject `$InputObject -Alias `$Alias -detail `$detail"
    }

    "dhcpd" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFDHCPd -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Add-PFDHCPd -InputObject `$InputObject -Interface `$Interface -From `$From -To `$To -netmask `$netmask -Domain `$Domain -Gateway `$Gateway -DNSServer `$DNSServer -NTPServer `$NTPServer "
        "Set" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Add-PFDHCPd -InputObject `$InputObject -Interface `$Interface -From `$From -To `$To -netmask `$netmask -Domain `$Domain -Gateway `$Gateway -DNSServer `$DNSServer -NTPServer `$NTPServer "
        "Enable" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; EnableOrDisable-PFDHCPd -InputObject `$InputObject -Interface `$Interface -EnableOrDisable `$True"
        "Disable" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; EnableOrDisable-PFDHCPd -InputObject `$InputObject -Interface `$Interface -EnableOrDisable `$False"

    } 
    "dhcpStaticMap" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFDHCPstaticmap -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Add-PFDHCPstaticmap -InputObject `$InputObject -Interface `$Interface -Hostname `$Hostname -Domain `$Domain -ClientID `$ClientID -MACaddr `$MACaddr -Address `$Address -Description `$Description -Gateway `$Gateway -DNSserver `$DNSserver -NTPServer `$NTPServer"
        "Edit" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Add-PFDHCPstaticmap -InputObject `$InputObject -Interface `$Interface -Hostname `$Hostname -Domain `$Domain -ClientID `$ClientID -MACaddr `$MACaddr -Address `$Address -Description `$Description -Gateway `$Gateway -DNSserver `$DNSserver -NTPServer `$NTPServer"
        "Delete" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Delete-PFDHCPstaticmap -InputObject `$InputObject -Interface `$Interface -MACaddr `$MACaddr"
    }  
    "dnsResolver" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFUnbound -InputObject `$InputObject"
    }    
    "dnsResolverHost" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFUnboundHost -InputObject `$InputObject"
    }   
    "Firewall" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFFirewall -InputObject `$InputObject"
    } 

    "gateway" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFGateway -InputObject `$InputObject"
    }

    "interface" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFInterface -InputObject `$InputObject"
    }

    "portfwd" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFNatRule -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Add-PFNatRule -InputObject `$InputObject -Interface `$Interface -Protocol `$Protocol -SourceAddress `$SourceAddress -SourcePort `$SourcePort -DestAddress `$DestAddress -DestPort `$DestPort -NatIp `$NatIp -NatPort `$NatPort -Description `$Description"
    }    

    "StaticRoute" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFStaticRoute -InputObject `$InputObject"
        "Add" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Add-PFStaticRoute -InputObject `$InputObject -Network `$Network -Gateway `$Gateway -Description `$Description"
        "Edit" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Add-PFStaticRoute -InputObject `$InputObject -Network `$Network -Gateway `$Gateway -Description `$Description"
        "Delete" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort) ; Delete-PFStaticRoute -InputObject `$InputObject -Network `$Network"
    }
    "Vlan" = @{
        "print" = "param(`$InputObject,`$path,`$file,`$Network,`$Gateway,`$Description,`$Interface,`$From,`$To,`$netmask,`$Domain,`$DNSServer,`$NTPServer,`$Alias,`$Type,`$Address,`$Detail,`$HostName,`$ClientID,`$MacAddr,`$Protocol,`$SourceAddress,`$DestAddress,`$DestPort,`$NatIp,`$NatPort); Write-PFVlan -InputObject `$InputObject"
    }
}