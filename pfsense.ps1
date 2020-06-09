Param
    (
    [Parameter(Mandatory=$true, HelpMessage='The pfSense network address (DNS or IP)')] [string] $Server,
    [Parameter(Mandatory=$false, HelpMessage='The Username')] [string] $Username,
    [Parameter(Mandatory=$false, HelpMessage='The Password')] [string] $InsecurePassword,
    [Parameter(Mandatory=$false, HelpMessage='The service you would like to talke to')] [string] $Service,
    [Parameter(Mandatory=$false, HelpMessage='The action you would like to do on the service')] [string] $Action,
    [Parameter(Mandatory=$false, HelpMessage='The Path where the xml file is to be stored, restored from')] [string] $Path,
    [Parameter(Mandatory=$false, HelpMessage='The File name of the xml file')] [string] $File,
    [Parameter(Mandatory=$false, HelpMessage='The Network value')] [string] $Network,
    [Parameter(Mandatory=$false, HelpMessage='The Gateway name')] [string] $Gateway,
    [Parameter(Mandatory=$false, HelpMessage='The Description')] [string] $Description,
    [Parameter(Mandatory=$false, HelpMessage='The Interface')] [string] $Interface,
    [Parameter(Mandatory=$false, HelpMessage='The Starting point')] [string] $From,
    [Parameter(Mandatory=$false, HelpMessage='The End point')] [string] $To,
    [Parameter(Mandatory=$false, HelpMessage='The Network IPv4 our IPv6 inclusing /subnet')] [string] $netmask,
    [Parameter(Mandatory=$false, HelpMessage='The Domain')] [string] $Domain,
    [Parameter(Mandatory=$false, HelpMessage='The IP address of the DNS Server')] [string] $DNSServer,
    [Parameter(Mandatory=$false, HelpMessage='The IP address of the NTP Server')] [string] $NTPServer,
    [Parameter(Mandatory=$false, HelpMessage='The Alias Name')] [string] $Alias,
    [Parameter(Mandatory=$false, HelpMessage='Type')] [string] $Type,
    [Parameter(Mandatory=$false, HelpMessage='Address')] [string] $Address,
    [Parameter(Mandatory=$false, HelpMessage='Detail - not the description')] [string] $Detail,
    [Parameter(Mandatory=$false, HelpMessage='Hostname')] [string] $HostName,
    [Parameter(Mandatory=$false, HelpMessage='Client ID')] [string] $ClientID,
    [Parameter(Mandatory=$false, HelpMessage='Mac Address')] [string] $MacAddr,
    [Parameter(Mandatory=$false, HelpMessage='Network protocol like: TCP, UDP, ICMP')] [string] $Protocol,
    [Parameter(Mandatory=$false, HelpMessage='Source Address')] [string] $SourceAddress,
    [Parameter(Mandatory=$false, HelpMessage='Source Port')] [string] $SourcePort,
    [Parameter(Mandatory=$false, HelpMessage='Destination Address')] [string] $DestAddress,
    [Parameter(Mandatory=$false, HelpMessage='Destination Port')] [string] $DestPort,
    [Parameter(Mandatory=$false, HelpMessage='The Local Ip Address')] [string] $NatIp,
    [Parameter(Mandatory=$false, HelpMessage='The Local Port')] [string] $NatPort,
    [Switch] $NoTLS,
    [switch] $SkipCertificateCheck
    )

# Test to see if the xmlrpc is installed, if not install
# TODO: make this a bit nicer, with error handling and stuff
if (Get-Module -ListAvailable -Name XmlRpc) {
    Write-Host "Module exists"
}   
else {
    Install-Module -Name XmlRpc
}

<# . source the Api #>
. .\pfsense_api.ps1
<# . source the possible execution flows #>
. .\flow.ps1

Function Add-PFAlias{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Alias Name')][string]$Alias,
        [Parameter(Mandatory=$true, HelpMessage='Type')][string]$Type,
        [Parameter(Mandatory=$false, HelpMessage='Address')] [string] $Address,
        [Parameter(Mandatory=$false, HelpMessage='Detail - not the description')] [string] $Detail,
        [Parameter(Mandatory=$true)][String]$Description
    )
    Process{
        $Properties = @{
            _Address = $Address
            _Detail = $Detail
        }
        $EntryObject = New-Object -TypeName "PFAliasEntry" -Property $Properties
        $Properties = @{
            Name = $Alias
            Type = $Type
            Description = $Description
            Entry = $EntryObject
        }
        $NewObject = New-Object -TypeName "PFAlias" -Property $Properties
        $PFObject = Get-PFAlias -Server $PFserver
        if($NewObject.name -in $PFObject.name){
            $Index = 0
            While($PFObject[$index]){
                if($PFObject[$index].name -eq $NewObject.name){$PFObject[$index] = $NewObject}
                $index++
            }
        }
        else{$PFObject = $PFObject + $NewObject}
        Set-PFAlias -InputObject $PFserver -PFObject $PFObject
    }
}
Function AddEntry-PFAlias{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Alias Name')][string]$Alias,
        [Parameter(Mandatory=$false, HelpMessage='Address')] [string] $Address,
        [Parameter(Mandatory=$false, HelpMessage='Detail - not the description')] [string] $Detail
    )
    Process{
        $Properties = @{
            _Address = $Address
            _Detail = $Detail
        }
        $EntryObject = New-Object -TypeName "PFAliasEntry" -Property $Properties
        $PFObject = Get-PFAlias -Server $PFserver
        if($Alias -in $PFObject.name){
            $Index = 0
            While($PFObject[$index]){
                if($PFObject[$index].name -eq $Alias){$PFObject[$index].entry += ($EntryObject)}
                $index++
            }
        }
        else{
            Write-Error "$Alias Was not found, could not add $EntryObject"
            exit 6
    }
        Set-PFAlias -InputObject $PFserver -PFObject $PFObject
    }
}

Function Delete-PFAlias{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Alias Name')][string]$Alias
    )
    $PFObject = Get-PFAlias -Server $PFserver
    if($Alias -in $PFObject.name){
        $PFObject = $PFObject | where {$Alias -ne $_.name}
    }
    Else{
        Write-Error -Message "$Alias Was not found, and could not be deleted"
        exit 7}
    Set-PFAlias -InputObject $PFserver -PFObject $PFObject
}

Function DeleteEntry-PFAlias{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Alias Name')][string]$Alias,
        [Parameter(Mandatory=$false, HelpMessage='Detail - not the description')] [string] $Detail
    )
    Process{
        $PFObject = Get-PFAlias -Server $PFserver
        if($Alias -in $PFObject.name){
            $Index = 0
            While($PFObject[$index]){
                if($PFObject[$index].name -eq $Alias){
                    $PFObject[$index].Entry = $PFObject[$index].Entry | where {$Detail -ne $_._Detail}
                }
                $index++
            }
        }
        else{
            Write-Error "$Alias Was not found, could not Delete entry $Detail"
            exit 8
    }
        Set-PFAlias -InputObject $PFserver -PFObject $PFObject
    }
}

Function Write-PFAlias{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
        $Collection = New-Object System.Collections.ArrayList
        $Object = (New-Object -TypeName "PFAlias")
    }
    process{
        $PFObject = get-pfalias -Server $InputObject
        foreach($AliasEntry in $PFObject){
            $indexAliasEntry = 0
            $Properties = @{}
            while($AliasEntry.Entry[$indexAliasEntry]){
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                $Property = $_.Name
                if($indexAliasEntry -eq 0){
                    if($Property -eq "Entry"){$PropertyValue = $AliasEntry.$Property[$indexAliasEntry]}
                    else{$PropertyValue = $AliasEntry.$Property}
                }
                else{
                    if($Property -eq "Entry"){
                        try {$PropertyValue = $AliasEntry.$Property[$indexAliasEntry]}
                        catch{$PropertyValue = $AliasEntry.$Property}
                    }
                    else{
                        $PropertyValue = "" 
                    }
                }
                $Properties.$Property = $PropertyValue
            }
            $Object = New-Object -TypeName "PFAlias" -Property $Properties
            $Collection.Add($Object) | Out-Null
            $indexAliasEntry++
        }
    }
    $exclude = ("_Address", "_Detail")
    $Collection | Select-Object -ExcludeProperty $exclude | Format-table *
    }

}
Function Add-PFDHCPd{
    <#
    Create a new PFStaticRoute object with the value's you would like to add
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true)][String]$Gateway,
        [Parameter(Mandatory=$false, HelpMessage='The Interface the DHCPd listen on')] [string]$Interface,
        [Parameter(Mandatory=$false, HelpMessage='The Starting ip address of the pool')] [string]$From,
        [Parameter(Mandatory=$false, HelpMessage='The Last IP address of the pool')] [string]$To,
        [Parameter(Mandatory=$false, HelpMessage='The Netmask used by the pool')] [string]$netmask,
        [Parameter(Mandatory=$false, HelpMessage='The Domain')] [string]$Domain,
        [Parameter(Mandatory=$false, HelpMessage='The DNSServer used bij the pool')] [string]$DNSServer,
        [Parameter(Mandatory=$false, HelpMessage='The NTPServer used bij the pool')] [string]$NTPServer
    )
    Process{
        $Properties = @{
            Gateway = $Gateway
            Interface = $($InputObject | Get-PFInterface -Description $Interface)
            RangeFrom = $From
            RangeTo = $To
            netmask = $netmask
            Domain = $Domain
            DNSServer = $DNSServer
            NTPServer = $NTPServer
        }
        $new = New-Object -TypeName "PFDHCPd" -Property $Properties
        $PFObject = get-pfdhcpd -Server $InputObject
        # ToDo: Get the staticmap and reuse those if the dhcp setting already excists
        if($new.interface.Description -in $PFObject.interface.Description){
            $PFObject | ForEach-Object{
                if($new.Interface.Description -eq $_.Interface.Description){
                    $new.staticmaps = $_.staticmaps
                }
            }
        }
        Set-PFDHCPd -InputObject $PFserver -NewObject $new
    }
}
Function EnableOrDisable-PFDHCPd{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
            [Parameter(Mandatory=$true, HelpMessage='The Interface the DHCPd listen on')] [string]$Interface,
            [Parameter(Mandatory=$true, HelpMessage='The Interface the DHCPd listen on')] [bool]$EnableOrDisable
            )
    Begin{
        $InterfaceObject = $($InputObject | Get-PFInterface -Description $Interface)
    }
    process{
        $PFObject = get-pfdhcpd -Server $InputObject
        if($InterfaceObject.description -in $PFObject.interface.description){
            $PFObject | ForEach-Object{
                if($InterfaceObject.Description -eq $_.Interface.Description){
                    $new = $_
                }
            }        
        }
        $new.enable = $EnableOrDisable
        Set-PFDHCPd -InputObject $PFserver -NewObject $new
    }
}
Function Write-PFDHCPd{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-pfdhcpd -Server $InputObject
        $exclude = ("ddnsdomainkeyalgorithm","ddnsdomainprimary","domainsearchlist","filename64","ddnsdomainkey","ddnsdomainkeyname","nextserver","tftp","maxleasetime","ddnsdomain","ldap","failover_peerip","filename","pool","filename32","mac_allow","numberoptions","dhcpleaseinlocaltime","defaultleasetime","ddnsclientupdates","mac_deny","_staticmaps","rootpath","staticmap","StaticHostname","StaticDomain","StaticClientID","StaticMACaddr","StaticIPaddr","StaticDescription","StaticGateway","StaticDNSserver","StaticNTPServer","Staticrootpath","Staticldap","Statictftp","Staticfilename","Staticmaxleasetime","Staticdomainsearchlist","Staticddnsdomainkey","Staticddnsdomainprimary","Staticdefaultleasetime","Staticddnsdomainkeyname","Staticddnsdomain","_StaticHostname","_StaticDomain","_StaticClientID","_StaticMACaddr","_StaticIPaddr","_StaticDescription","_StaticGateway","_StaticDNSserver","_StaticNTPServer","_Staticrootpath","_Staticldap","_Statictftp","_Staticfilename","_Staticmaxleasetime","_Staticdomainsearchlist","_Staticddnsdomainkey","_Staticddnsdomainprimary","_Staticdefaultleasetime","_Staticddnsdomainkeyname","_Staticddnsdomain","staticmaps")
        $PFObject | Select-Object -ExcludeProperty $exclude | Format-table *
    }
}

Function Add-PFDHCPstaticmap{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Hostname you want to add')][String]$Hostname,
        [Parameter(Mandatory=$True, HelpMessage='The Interface Static Map is going to be created on')] [string]$Interface,
        [Parameter(Mandatory=$false, HelpMessage='The Domain')] [string]$Domain,
        [Parameter(Mandatory=$True, HelpMessage='The Client ID for this entry, this is mandatory but can be the mac address')] [string]$ClientID,
        [Parameter(Mandatory=$True, HelpMessage='Mac Address of the new entry')] [string]$MACaddr,
        [Parameter(Mandatory=$True, HelpMessage='IP Address of the new entry')] [string]$Address,
        [Parameter(Mandatory=$false, HelpMessage='Description')] [string]$Description,
        [Parameter(Mandatory=$false, HelpMessage='Gateway, if non is enterd the gateway of the pool is used')] [string]$Gateway,
        [Parameter(Mandatory=$false, HelpMessage='Gateway, if non is enterd the DNS Server of the pool is used')] [string]$DNSServer,
        [Parameter(Mandatory=$false, HelpMessage='Gateway, if non is enterd the NTP Server of the pool is used')] [string]$NTPServer
    )
    Process{
        $Properties = @{
            Interface = $($InputObject | Get-PFInterface -Description $Interface)
            Hostname = $Hostname
            Domain = $Domain
            ClientID = $ClientID
            MACaddr = $MACaddr
            IPaddr = $Address
            Description = $Description
            Gateway = $Gateway # This does not have to be a known gateway on the pfsense, no need for: $(if($Gateway){$InputObject | Get-PFGateway -Name $Gateway})
            DNSServer = $DNSServer
            NTPServer = $NTPServer
        }
        $new = New-Object -TypeName "PFDHCPstaticmap" -Property $Properties
        $PFObject = get-pfdhcpd -Server $InputObject
        if($new.Interface.Description -in $PFObject.interface.Description){
            foreach($DHCPObject in $PFObject){
                if($DHCPObject.Interface.Description -eq $new.Interface.Description){
                    if($New.MACaddr -in $DHCPObject.staticmaps.MACaddr){ # If the Mac address allready excists, update the entry
                        $DHCPObject.staticmaps | foreach {
                            if($New.MACaddr -eq $_.MACaddr){
                                $_.PSObject.Properties.ForEach({
                                    $_.Value = $new.($_.name)
                                })
                            }
                        }
                    }
                    else{
                    $DHCPObject.staticmaps += $New # If it is a new staticmap, add the staticmap to staticmaps
                    }
                    Set-PFDHCPd -InputObject $PFserver -NewObject $DHCPObject
                }
            }
        }
        else{
            "Could not find Interface {0}" -f $new.interface
        }     
    }
}

Function Delete-PFDHCPstaticmap{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Interface Static Map is going to be deleted on')] [string]$Interface,
        [Parameter(Mandatory=$True, HelpMessage='Mac Address of the entry you would like to delete')] [string]$MACaddr
    )
    Process{
        $PFObject = get-pfdhcpd -Server $InputObject
        $InterfaceObject = $($InputObject | Get-PFInterface -Description $Interface)
        if($InterfaceObject.Description -in $PFObject.interface.Description){
            foreach($DHCPObject in $PFObject){
                if($DHCPObject.Interface.Description -eq $InterfaceObject.Description){
                    $DHCPObject.staticmaps = $DHCPObject.staticmaps | Where-Object { $_.MacAddr -ne $MacAddr }
                    Set-PFDHCPd -InputObject $InputObject -NewObject $DHCPObject
                    return
                }
            }
        }
    }
}

Function Write-PFDHCPstaticmap{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
        $Object = New-Object -TypeName "PFDHCPstaticmap" -Property @{}
        $Collection = New-Object System.Collections.ArrayList
    }
    process{
        $PFObject = get-pfdhcpd -Server $InputObject
        foreach($DHCPStatiMap in $PFObject){
            $indexDHCPStatiMap = 0
            try{
                while($DHCPStatiMap.staticmaps[$indexDHCPStatiMap]){
                    $Properties = @{}
                    $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                        $Properties.add($_.name,$DHCPStatiMap.staticmaps[$indexDHCPStatiMap].($_.name))
                    }
                    $Properties.Interface = $DHCPStatiMap.Interface
                    $NewObject = New-Object -TypeName "PFDHCPstaticmap" -Property $Properties
                    $Collection.add($NewObject)
                    $indexDHCPStatiMap++
                }
            }catch{}
        }
        $exclude = ("rootpath","ldap","tftp","filename","maxleasetime","domainsearchlist","ddnsdomainkey","ddnsdomainprimary","defaultleasetime","ddnsdomainkeyname","ddnsdomain")
        $Collection | Select-Object -ExcludeProperty $exclude | Format-table *
    }
}

Function Write-PFUnbound{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
        $Object = (New-Object -TypeName "PFdhcpStaticMapWrite")
    }
    process{
        $PFObject = Get-PFUnbound -Server $InputObject
        $Properties = @{}
        $Object = New-Object -TypeName "PFUnbound" -Property $Properties
        foreach($Rule in $PFObject){
            $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                if($Rule.($_.name)){$Properties.($_.name) = $Rule.($_.name)}
            }
        }
        if(-not $Properties.port){$Properties.port = "53"}
        if(-not $Properties.sslport){$Properties.sslport = "853"}
        $Object = New-Object -TypeName "PFUnbound" -Property $Properties
        $Object | format-table *
    }
}

Function Write-PFUnboundHost{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFunboundHost -Server $InputObject
        $exclude = ("")
        $PFObject | Select-Object -ExcludeProperty $exclude | Format-table *
    }
}

Function Write-PFFirewall{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFFirewall -Server $InputObject
        $exclude = ("statetype","direction","os","tag","maxsrcstates","icmptype","created","max","updated","tagged","statetimeout","maxsrcnodes","maxsrcconn","Source","Destination","tracker","associatedruleid")
        $PFObject | Select-Object -ExcludeProperty $exclude | Format-table *
    }
}

Function Write-PFGateway{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
        $Collection = New-Object System.Collections.ArrayList
    }
    process{
        $PFObject = get-pfgateway -Server $InputObject
        $exclude = ("")
        foreach($Rule in $PFObject){
            # Real interfaces have a physical interface, if not, do not display
            if($rule.Interface){
                $Collection.Add($Rule) | out-null
            }
        }
        $Collection | Select-Object -ExcludeProperty $exclude | Format-table *
    }
}


Function Write-PFInterface{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
        $Collection = New-Object System.Collections.ArrayList
    }
    process{
        $PFObject = get-pfinterface -Server $InputObject
        foreach($Rule in $PFObject){
            # Real interfaces have a physical interface, if not, do not display
            if($rule.Interface){
                $Collection.Add($Rule) | out-null
            }
        }
        $Collection | format-table *
    }
}

Function Add-PFNatRule{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Interface the port forward is going to be created on')] [string]$Interface,
        [Parameter(Mandatory=$false, HelpMessage='Network protocol like: TCP, UDP, ICMP')] [string] $Protocol,
        [Parameter(Mandatory=$false, HelpMessage='Source Address')] [string] $SourceAddress,
        [Parameter(Mandatory=$false, HelpMessage='Source Port')] [string] $SourcePort,
        [Parameter(Mandatory=$false, HelpMessage='Destination Address')] [string] $DestAddress,
        [Parameter(Mandatory=$false, HelpMessage='Destination Port')] [string] $DestPort,
        [Parameter(Mandatory=$false, HelpMessage='The Local Ip Address')] [string] $NatIp,
        [Parameter(Mandatory=$false, HelpMessage='The Local Port')] [string] $NatPort,
        [Parameter(Mandatory=$false, HelpMessage='The Description')] [string] $Description
        )
    Begin{
        $Updated = @{
            Username = $Username
            time = [string][Math]::Floor((New-TimeSpan -Start $(Get-Date -Date "01/01/1970") -End $(get-date)).TotalSeconds)
        }
    }
    process{
        $Properties = @{
            Interface = $($InputObject | Get-PFInterface -Description $Interface)
            Protocol = $Protocol
            SourceAddress = $SourceAddress
            SourcePort = $SourcePort
            DestinationAddress = $DestAddress
            DestinationPort = $DestPort
            target = $NatIp
            LocalPort = $NatPort
            Description = $Description
            Updated = $Updated
            created = $Updated
        }
    $new = New-Object -TypeName "PFNATRule" -Property $Properties
    $PFObject = get-PFNATRule -Server $InputObject
    $PFObject += $new
    Set-PFNatRule -InputObject $InputObject -NewObject $PFObject
    }
}

Function Write-PFNatRule{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFNATRule -Server $InputObject
        $exclude = ("Source","Destination","updated","created")
        $PFObject | Select-Object -ExcludeProperty $exclude | Format-table *
    }
}
Function Add-PFStaticRoute{
    <#
    Create a new PFStaticRoute object with the value's you would like to add
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true)][String]$Network,
        [Parameter(Mandatory=$true)][String]$Gateway,
        [Parameter(Mandatory=$true)][String]$Description
    )
    begin{
        $PFObject = Get-PFStaticRoute -Server $InputObject
    }
    Process{
        $Properties = @{
            Network = $Network
            Gateway = $($InputObject | Get-PFGateway -Name $Gateway)
            Description = $Description
        }
        $NewObject = New-Object -TypeName "PFStaticRoute" -Property $Properties
        if($NewObject.Network -in $PFObject.Network){
            $Index = 0
            While($PFObject[$index]){
                if($PFObject[$index].Network -eq $NewObject.Network){$PFObject[$index] = $NewObject}
                $index++
            }
        }
        else{$PFObject = $PFObject + $NewObject}

        Set-PFStaticRoute -InputObject $InputObject -NewObject $PFObject
    }
}

Function Delete-PFStaticRoute{
    <#
    Create a new PFStaticRoute object with the value's you would like to add
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true)][String]$Network)
    begin{
        $PFObject = Get-PFStaticRoute -Server $InputObject
    }
    process{
        if($Network -in $PFObject.Network){
            $PFObject = $PFObject | Where-Object {$Network -ne $_.Network}
        }
        else{Write-Error "Could not find network $Network, unable to delete"}
        Set-PFStaticRoute -InputObject $InputObject -NewObject $PFObject
    }
}


Function Write-PFStaticRoute{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFStaticroute -Server $InputObject
        $exclude = ("")
        $PFObject | Select-Object -ExcludeProperty $exclude | Format-table *
    }
}

Function Write-PFVlan{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFVlan -Server $InputObject
        $exclude = ("vlanif")
        $PFObject | Select-Object -ExcludeProperty $exclude | Format-table *
    }
}

<# test objects
# make a clear visual distinction between this run and the previous run
#<#
1..30 | ForEach-Object { Write-Host "" }

# works
Write-Host "Known interfaces:" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFInterface | Format-table *

# works
Write-Host "LAN interface:" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFInterface -Name "lan" | Format-table *

# works
# TODO: separate each address/detail in a separate child object, like PFAliasEntry or something like that. Each PFAlias should then contain a collection of these.
Write-Host "Registered aliases:" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFAlias | Format-table *

# works
Write-Host "Registered DHCPd servers" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$DHCPdServers = $PFServer | Get-PFDHCPd
$DHCPdServers | Format-table *
$DHCPdInterfaceType = ($DHCPdServers | Select-Object -First 1 -ExpandProperty Interface).GetType()
$DHCPdInterfaceIsPFInterface = $DHCPdInterfaceType -eq [PFInterface]
Write-Host ("Typecheck of Interface property of DHCPd server 1: {0}" -f $DHCPdInterfaceType) -ForegroundColor ($DHCPdInterfaceIsPFInterface ? "Green" : "Red")

# TODO: a lot
Write-Host "Registered static DHCP leases" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFDHCPStaticMap | Format-table *

# TODO: source/destination
Write-Host "All firewall rules" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
# TODO: if you want to convert System.Collections.Hashtable into something more meaningful (display only), do it here
#       obviously creating a Write-PFFirewall function would be an even better idea :)
#       DO NOT change it in the ConvertTo-PFObject function, since that will really complicate the reverse operation (changing and uploading the rule)
$PFServer | Get-PFFirewall | Select-Object -ExcludeProperty Source, Destination | Format-table *

# works
Write-Host "Registered gateways" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFGateway | Format-table *

# TODO: a lot
Write-Host "All NAT rules" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray 
$PFServer | Get-PFNATRule | Format-table *

# TODO: mapping to PFGateway object
Write-Host "All static routes" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFStaticRoute | Format-table *

# TODO: mapping to PSObject 
Write-Host "DNS server settings" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFUnbound | Format-table *

# TODO: mapping to PSObject
Write-Host "DNS host overrides" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFunboundHost | Format-table *

Write-Host "THE END" -BackgroundColor Gray -ForegroundColor DarkGray
exit;
#>   


## BEGIN OF CONTROLLER LOGIC, should be moved to a different script later in order to be able to dotsource this file in your own scripts.
# since debugging dotsourced files s*, leave it here for now until we're ready for a first release
# TODO: create a switch for the program to skip this contoller logic and be able to test dotsourcing this file in your own scripts too.

Clear-Host

$PFServer = New-Object -TypeName "PFServer" -Property @{
    Address = $Server
    NoTLS = $NoTLS
    SkipCertificateCheck = $SkipCertificateCheck
}

# Warn the user if no TLS encryption is used
if($PFServer.NoTLS){
    Write-Warning "Your administrative level credentials are being transmitted over an INSECURE connection!"
}

# Test credentials before we continue.
Write-Progress -Activity "Testing connection and your credentials" -Status "Connecting..." -PercentComplete -1
try{
    if(-not [string]::IsNullOrWhiteSpace($Username)){
        if(-not [string]::IsNullOrWhiteSpace($InsecurePassword)){
            $Password = ConvertTo-SecureString -String $InsecurePassword -AsPlainText -Force
            $PFServer.Credential = New-Object System.Management.Automation.PSCredential($Username, $Password) 

        } else {
            $PFServer.Credential = Get-Credential -UserName $Username
        }
    }
    while(-not (TestPFCredential -Server $PFServer)){ $PFServer.Credential = Get-Credential }

} catch [System.TimeoutException] {
    Write-Error -Message $_.Exception.Message
    exit 4

} finally {
    Write-Progress -Activity "Testing connection and your credentials" -Completed
}

# Get- all config information so that we can see what's inside.
$PFServer = ($PFServer | Get-PFConfiguration -NoCache)
 
 
<# execute requested flow #> 
try{
    if(-not $Flow.ContainsKey($Service)){  Write-Host "Unknown service '$Service'" -ForegroundColor red; exit 2 }
    if(-not $Flow.$Service.ContainsKey($Action)){ Write-Host "Unknown action '$Action' for service '$Service'" -ForegroundColor red; exit 3 }

    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Flow.$Service.$Action)) -ArgumentList $PFServer,$path,$file,$Network,$Gateway,$Description,$Interface,$From,$To,$netmask,$Domain,$DNSServer,$NTPServer,$Alias,$Type,$Address,$Detail,$HostName,$ClientID,$MacAddr,$Protocol, $SourceAddress, $DestAddress, $DestPort, $NatIp, $NatPort
 
} catch { 
    Write-Error $_.Exception 
    exit 1
}

