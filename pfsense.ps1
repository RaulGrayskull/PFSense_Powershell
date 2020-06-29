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
    [Parameter(Mandatory=$false, HelpMessage='The Monitoring address')] [string] $Monitor,
    [Parameter(Mandatory=$false, HelpMessage='The Weight')] [string] $Weight,
    [Parameter(Mandatory=$false, HelpMessage='The Name of the entry')] [string] $Name,
    [Parameter(Mandatory=$false, HelpMessage='The type of ip protocol, inet, inet6 or inet46')] [string] $IpProtocol,
    [Parameter(Mandatory=$false, HelpMessage='if logging is enabled')] [Bool] $IsLogged,
    [Parameter(Mandatory=$false, HelpMessage='if Quick match is enabled')] [Bool] $IsQuick,
    [Parameter(Mandatory=$false, HelpMessage='if it is a floating rule')] [Bool] $IsFloating,
    [Parameter(Mandatory=$false, HelpMessage='The Tracker id of the firewall rule you would like to edit')] [string] $tracker,
    [Parameter(Mandatory=$false, HelpMessage='The old line number')][Alias('OldLN')] [string] $OldLineNumber,
    [Parameter(Mandatory=$false, HelpMessage='The new line number')][Alias('NewLN')] [string] $NewLineNumber,
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
    <#
    .SYNOPSIS
    The Add-PFAlias function add's a new alias to the pfsense.

    .DESCRIPTION
    The Add-PFAlias function add's a new alias to the pfsense.
    it also check's if the alias name does not excists yet, the name is a unique id.

    .PARAMETER Alias
    The Name of the Alias

    .PARAMETER Type
    The Type of the alias, could be Host, Network or Port

    .PARAMETER Address
    The IP, Network address or the Port number

    .PARAMETER Detail
    The description of the address value

    .PARAMETER Description
    The description of the Alias
    
    .EXAMPLE
    ./pfsense.ps1' -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service alias -action add -Alias UploadTest -Type Host -address 192.168.0.5 -Detail 'To test XMLRPC' -Description 'Test the upload of a alias' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Alias Name')][string]$Name,
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
        $Entry = New-Object -TypeName "PFAliasEntry" -Property $Properties
        $PFObject = Get-PFAlias -Server $PFserver
        if($NewObject.name -cin $PFObject.name){
            throw "$($NewObject.name) Already excists, you could use edit to change it value's"
        }
        $Properties = @{}
        $Object = New-Object -TypeName "PFAlias" -Property $Properties
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $NewObject = New-Object -TypeName "PFAlias" -Property $Properties

        $PFObject += $NewObject
        Set-PFAlias -InputObject $PFserver -PFObject $PFObject
    }
}

Function Edit-PFAlias{
    <#
    .SYNOPSIS
    The edit-PFAlias function edit's a excisting alias on the pfsenes.

    .DESCRIPTION
    The edit-PFAlias function edit's a excisting alias on the pfsenes.
    first it check's if the alias excisits, the unique identifier is the name.
    If the Address and Detail are enterd these will overwrite the excisting one's

    .PARAMETER Alias
    The Name of the Alias

    .PARAMETER Type
    The Type of the alias, could be Host, Network or Port

    .PARAMETER Address
    The IP, Network address or the Port number

    .PARAMETER Detail
    The description of the address value

    .PARAMETER Description
    The description of the Alias
    
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service alias -action edit -Alias UploadTest -Type Host -address 192.168.0.5 -Detail 'To test XMLRPC' -Description 'Test the upload of a alias' -notls

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service alias -action edit -Alias host_alias -Type Port -Description 'Test the Edit a alias' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Alias Name')][string]$Alias,
        [Parameter(Mandatory=$false, HelpMessage='Type')][string]$Type,
        [Parameter(Mandatory=$false, HelpMessage='Address')] [string] $Address,
        [Parameter(Mandatory=$false, HelpMessage='Detail - not the description')] [string] $Detail,
        [Parameter(Mandatory=$false)][String]$Description
    )
    Process{
        if($address -and $Detail){ # it is not mandatory to upload a new entry object, this can be empty or the excisiting one
            $Properties = @{
                _Address = $Address
                _Detail = $Detail
            }
            $EntryObject = New-Object -TypeName "PFAliasEntry" -Property $Properties
        }
        $PFObject = Get-PFAlias -Server $PFserver # get the existing Aliasses
        if($Alias -cNotIn $PFObject.name){
            throw "$($Alias) Could not be found, please check the input or use Add" # if the alias does not excisits we can not edit it and we throw a error
        }
        foreach($aliasObject in $PFObject){
            if($aliasObject.name -ceq $Alias){ # loop true all the aliasses, if we find the correct alias, edit it
                if($EntryObject){ # Only change the Entry object if a now entryobject has been created
                    $aliasObject.Entry = $EntryObject
                }
                $aliasObject | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                    # Only set if variable is set
                    if(get-variable $_.name -valueOnly -ErrorAction Ignore){ # Only set object if variable is set. don't override with empty value's
                        $aliasObject.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
                    }
                }
            }
        }
        Set-PFAlias -InputObject $PFserver -PFObject $PFObject
    }
}

Function Delete-PFAlias{
    <#
    .SYNOPSIS
    The Delete-PFAlias function Deletes's a entry of the aliasses on the pfsense.

    .DESCRIPTION
    The Delete-PFAlias function Deletes's a entry of the aliasses on the pfsense.
    first it check's if it can find the alias, if not it will throw a error.
    if the alias name excists we delete it.

    .PARAMETER Alias
    The Name of the Alias

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service alias -action Delete -Alias host_alias -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Alias Name')][string]$Alias
    )
    $PFObject = Get-PFAlias -Server $PFserver
    if($Alias -cNotIn $PFObject.name){  #Todo: must be case sensivive
        throw "$($Alias) Could not be found, please check the alias name" # if the alias does not excisits we can not delete it, so throw a error
    }
    $PFObject = $PFObject | where {$Alias -cne $_.name}
    Set-PFAlias -InputObject $PFserver -PFObject $PFObject
}

Function AddEntry-PFAlias{
    <#
    .SYNOPSIS
    The AddEntry-PFAlias function add's a new entry to a alias of the pfsense.

    .DESCRIPTION
    The AddEntry-PFAlias function add's a new entry to a alias of the pfsense.
    first it check's if it can find the alias, if not it will throw a error.

    .PARAMETER Alias
    The Name of the Alias

    .PARAMETER Address
    The IP, Network address or the Port number

    .PARAMETER Detail
    The description of the address value
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service alias -action addEntry -Alias host_alias -address 192.168.0.5 -Detail 'To test XMLRPC' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Alias Name')][string]$Alias,
        [Parameter(Mandatory=$true, HelpMessage='Address')] [string] $Address,
        [Parameter(Mandatory=$true, HelpMessage='Detail - not the description')] [string] $Detail
    )
    Process{
        $Properties = @{
            _Address = $Address
            _Detail = $Detail
        }
        $EntryObject = New-Object -TypeName "PFAliasEntry" -Property $Properties
        $PFObject = Get-PFAlias -Server $PFserver
        if($Alias -cNotIn $PFObject.name){  #Todo: must be case sensivive
            throw "$($Alias) Could not be found, please check the input or Add the alias" # if the alias does not excisits we can not add a entry to it so we throw a error.
        }
        foreach($AliasObject in $PFObject){
            if($AliasObject.name -ceq $Alias){
                $AliasObject.entry += ($EntryObject)
            }
        }
        Set-PFAlias -InputObject $PFserver -PFObject $PFObject
    }
}

Function DeleteEntry-PFAlias{
    <#
    .SYNOPSIS
    The DeleteEntry-PFAlias function delete's a entry of a alias on the pfsense.

    .DESCRIPTION
    The DeleteEntry-PFAlias function delete's a entry of a alias on the pfsense.
    first it check's if it can find the alias, if not it will throw a error.
    then we check if the entry excists on the alias, if not trow a error.
    if it excists we delete the entry

    .PARAMETER Alias
    The Name of the Alias

    .PARAMETER Address
    The IP, Network address or the Port number

    .PARAMETER Detail
    The description of the address value
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service alias -action DeleteEntry -Alias multiple_hosts -address 192.168.0.4 -Detail 'Firewall vip 3' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Alias Name')][string]$Alias,
        [Parameter(Mandatory=$true, HelpMessage='Address')] [string] $Address,
        [Parameter(Mandatory=$true, HelpMessage='Detail - not the description')] [string] $Detail
    )
    Process{
        $PFObject = Get-PFAlias -Server $PFserver
        if($Alias -cNotIn $PFObject.name){ #Todo: must be case sensivive
            throw "$($Alias) Could not be found, please check the input or Add the alias" # if the alias does not excisits we can not add a entry to it so we throw a error.
        }
        foreach($AliasObject in $PFObject){
            if($AliasObject.name -ceq $Alias){
                $AliasObject.Entry = $AliasObject.Entry | Where-Object {($Detail -cne $_._Detail) -and ($Address -cne $_._Address)}
            }
        }
        Set-PFAlias -InputObject $PFserver -PFObject $PFObject
    }
}

Function Write-PFAlias{
    <#
    .SYNOPSIS
    The Write-PFAlias function prints all the aliasses and there entries of the pfsense

    .DESCRIPTION
    The Write-PFAlias function prints all the aliasses and there entries of the pfsense
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service alias -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
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
            try{ # Try added, if the alias has no entry's it did crash the script
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
            catch{
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                    $Property = $_.Name
                    $PropertyValue = $AliasEntry.$Property
                    $Properties.$Property = $PropertyValue
                }
                $Object = New-Object -TypeName "PFAlias" -Property $Properties
                $Collection.Add($Object) | Out-Null
                $indexAliasEntry++
            }
        }
    $Collection | Format-table Name,Type,Description,Entry
    }

}
Function Edit-PFDHCPd{
    <#
    .SYNOPSIS
    The Edit-PFDHCPd function edit's the dhcp settings on a specific interface.

    .DESCRIPTION
    The Edit-PFDHCPd function edit's the dhcp settings on a specific interface.
    The start and end of the pool must be in the interface subnet

    .PARAMETER Interface
    The interface the dhcpd is going to listen on

    .PARAMETER From
    the start ipaddress of the dhcp pool

    .PARAMETER to
    the last ipaddress of the dhcp pool

    .PARAMETER netmask
    the netmask the dhcpd gives out with the ip address

    .PARAMETER Gateway
    the Gateway the dhcpd gives out with the ip address

    .PARAMETER Domain
    the Domain the dhcpd gives out with the ip address

    .PARAMETER DNSServer
    the DNSServer the dhcpd gives out with the ip address

    .PARAMETER NTPServer
    the NTPServer the dhcpd gives out with the ip address
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dhcpd -action edit -Interface Manage -From 172.16.20.10 -To 172.16.20.20 -netmask 255.255.255.0 -Domain test.com -Gateway WAN_DHCP -DNSServer 172.16.20.2 -NTPServer 172.16.20.5 -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Interface the DHCPd listen on')] [string]$Interface,
        [Parameter(Mandatory=$True, HelpMessage='The Starting ip address of the pool')] [string]$RangeFrom,
        [Parameter(Mandatory=$True, HelpMessage='The Last IP address of the pool')] [string]$RangeTo,
        [Parameter(Mandatory=$True, HelpMessage='The Netmask used by the pool')] [string]$netmask,
        [Parameter(Mandatory=$false)][String]$Gateway,
        [Parameter(Mandatory=$false, HelpMessage='The Domain')] [string]$Domain,
        [Parameter(Mandatory=$True, HelpMessage='The DNSServer used bij the pool')] [string]$DNSServer,
        [Parameter(Mandatory=$True, HelpMessage='The NTPServer used bij the pool')] [string]$NTPServer
    )
    Process{
        $PFObject = get-pfdhcpd -Server $InputObject
        if($Interface -NotIn $PFObject.interface.Description){
            throw "the DHCPD doen not know $($Interface), Make sure the interface has a fixed ip address and not a /32 subnet."
        }
        foreach($dhcpdObject in $PFObject){
            if($dhcpdObject.interface.Description -eq $Interface){
                # check if the pool addresses are in the interface range
                [net.IPAddress]$InterfaceAddress = $dhcpdObject.interface.IPv4Address
                $Int64 = ([convert]::ToInt64(('1' * $($dhcpdObject.interface.IPv4Subnet) + '0' * (32 - $($dhcpdObject.interface.IPv4Subnet))), 2)) 
                [net.IPAddress]$subnet = '{0}.{1}.{2}.{3}' -f ([math]::Truncate($Int64 / 16777216)).ToString(), ([math]::Truncate(($Int64 % 16777216) / 65536)).ToString(), ([math]::Truncate(($Int64 % 65536)/256)).ToString(), ([math]::Truncate($Int64 % 256)).ToString()
                [net.IPAddress]$Rangefromaddress = $Rangefrom
                [net.IPAddress]$RangeToaddress = $RangeTo
                if(($InterfaceAddress.Address -band $subnet.address) -ne ($Rangefromaddress.address -band $subnet.address) -or `
                ($InterfaceAddress.Address -band $subnet.address) -ne ($RangeToaddress.address -band $subnet.address)){
                    Throw "the pool range is not in the same subnet as the interface"
                }
                # Set al the settings
                $dhcpdObject | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                    # Only set if variable is set
                    if(get-variable $_.name -valueOnly -ErrorAction Ignore){ # Only set object if variable is set. don't override with empty value's
                        $dhcpdObject.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
                    }
                }
            }
        }
        Set-PFDHCPd -InputObject $PFserver -NewObject $PFObject
    }
}
Function EnableOrDisable-PFDHCPd{
    <#
    .SYNOPSIS
    The EnableOrDisable-PFDHCPd function enable's or disables the dhcp server on a interface

    .DESCRIPTION
    The EnableOrDisable-PFDHCPd function enable's or disables the dhcp server on a interface

    .PARAMETER Interface
    The interface the dhcpd is going to listen on

    .PARAMETER EnableOrDisable
    EnableOrDisable is a Bool variable, if true it enable's the dhcp server on that interface. if false, it disable's

  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dhcpd -action Disable -Interface client -notls

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dhcpd -action Disable -Interface client -notls


    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
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
        if($Interface -NotIn $PFObject.interface.Description){
            throw "We cannot find $($interface) in the dhcpd"
        }
        $PFObject | ForEach-Object{
            if($InterfaceObject.Description -eq $_.Interface.Description){
                $_.enable = $EnableOrDisable
            }
        }        
        Set-PFDHCPd -InputObject $PFserver -NewObject $PFObject
    }
}
Function Write-PFDHCPd{
    <#
    .SYNOPSIS
    The Write-PFDHCPd function prints all the DHCP server settings if there are any on a interface

    .DESCRIPTION
    The Write-PFDHCPd function prints all the DHCP server settings if there are any on a interface
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dhcpd -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-pfdhcpd -Server $InputObject
        $PFObject | Format-table enable,Interface,RangeFrom,RangeTo,netmask,Domain,Gateway,DNSServer,NTPServer
    }
}

Function Add-PFDHCPstaticmap{
    <#
    .SYNOPSIS
    The Add-PFDHCPstaticmap function add's a new staticmap entry to the dhcp deamon on a interface.

    .DESCRIPTION
    The Add-PFDHCPstaticmap function add's a new staticmap entry to the dhcp deamon on a interface.
    It does check if that mac address and Cliend Id are allready in use on that interface. if so, than we need to use edit.

    .PARAMETER Interface
    The interface of the dhcpd deamon you would like to use
    
    .PARAMETER Hostname
    The Hostname of the static entry you are adding

    .PARAMETER Domain
    The Domain name you would like to give to the client.

    .PARAMETER ClientId
    The Client ID you are giving to the dhcp client

    .PARAMETER MACaddr
    The mac address of the client that is going to get this ip address

    .PARAMETER Address
    The ip address you would like to give to the dhcp client
  
    .PARAMETER Description
    a description of the dhcp static entry

    .PARAMETER Gateway
    the gateway of this specific entry

    .PARAMETER DNSServer
    the DNSServer of this specific entry

    .PARAMETER NTPServer
    the NTPServer of this specific entry

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dhcpstaticmap -action add -Interface Client -Hostname TestHostXMLRPS -Domain test.com -ClientID 10:f0:05:eb:ba:97 -MACaddr 10:f0:05:eb:ba:97 -Address 172.16.20.16 -Description 'To Test XML RPC ADD' -Gateway WAN_DHCP -DNSServer 172.16.20.2 -NTPServer 172.16.20.5 -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Hostname you want to add')][String]$Hostname,
        [Parameter(Mandatory=$True, HelpMessage='The Interface Static Map is going to be created on')] [string]$Intface,
        [Parameter(Mandatory=$false, HelpMessage='The Domain')] [string]$Domain,
        [Parameter(Mandatory=$True, HelpMessage='The Client ID for this entry, this is mandatory but can be the mac address')] [string]$ClientID,
        [Parameter(Mandatory=$True, HelpMessage='Mac Address of the new entry')] [string]$MACaddr,
        [Parameter(Mandatory=$True, HelpMessage='IP Address of the new entry')] [string]$IPaddr,
        [Parameter(Mandatory=$false, HelpMessage='Description')] [string]$Description,
        [Parameter(Mandatory=$false, HelpMessage='Gateway, if non is enterd the gateway of the pool is used')] [string]$Gateway,
        [Parameter(Mandatory=$false, HelpMessage='Gateway, if non is enterd the DNS Server of the pool is used')] [string]$DNSServer,
        [Parameter(Mandatory=$false, HelpMessage='Gateway, if non is enterd the NTP Server of the pool is used')] [string]$NTPServer
    )
    Process{
        $PFObject = get-pfdhcpd -Server $InputObject
        if($Intface -NotIn $PFObject.interface.Description){
            Throw "Could not find Interface $($Intface)"
        }
        $Interface = $($InputObject | Get-PFInterface -Description $Intface)
        $Properties = @{}
        $Object = New-Object -TypeName "PFDHCPstaticmap" -Property $Properties
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $NewObject = New-Object -TypeName "PFDHCPstaticmap" -Property $Properties
        foreach($DHCPObject in $PFObject){
            if($DHCPObject.Interface.Description -eq $NewObject.Interface.Description){
                if($New.MACaddr -in $DHCPObject.staticmaps.MACaddr){
                    Throw "Mac address $($NewObject.MACaddr) is already in use."
                }
                elseif($NewObject.ClientID -in $DHCPObject.staticmaps.ClientID){
                    Throw "ClientID $($NewObject.ClientID) is already in use."
                }
                else{
                $DHCPObject.staticmaps += $NewObject
                }
                Set-PFDHCPd -InputObject $PFserver -NewObject $DHCPObject
            }
        }
    }
}

Function Edit-PFDHCPstaticmap{
    <#
    .SYNOPSIS
    The Edit-PFDHCPstaticmap function edit's a staticmap entry of the dhcp deamon on a interface.

    .DESCRIPTION
    The Edit-PFDHCPstaticmap function edit's a staticmap entry of the dhcp deamon on a interface.
    It first check's if we can find the entry. it uses the combination of mac and interface to see if it already excists. 
    if it does not excists we throw a error and u should use add.

    .PARAMETER Interface
    The interface of the dhcpd deamon you would like to use

    .PARAMETER Hostname
    The Hostname of the static entry you are adding

    .PARAMETER Domain
    The Domain name you would like to give to the client.

    .PARAMETER ClientId
    The Client ID you are giving to the dhcp client

    .PARAMETER MACaddr
    The mac address of the client that is going to get this ip address

    .PARAMETER Address
    The ip address you would like to give to the dhcp client
  
    .PARAMETER Description
    a description of the dhcp static entry

    .PARAMETER Gateway
    the gateway of this specific entry

    .PARAMETER DNSServer
    the DNSServer of this specific entry

    .PARAMETER NTPServer
    the NTPServer of this specific entry
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dhcpstaticmap -action Edit -Interface Client -Hostname TestHostXMLRPS -Domain test.com -ClientID 10:f0:05:eb:ca:97 -MACaddr 10:f0:05:eb:ca:97 -Address 192.168.0.199 -Description 'To Test XML RPC ADD' -Gateway WAN_DHCP -DNSServer 172.16.20.2 -NTPServer 172.16.20.5 -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
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
        $PFObject = get-pfdhcpd -Server $InputObject
        if($interface -NotIn $PFObject.interface.Description){
            Throw "Could not find Interface $($interface)"
        }
        $IPaddr = $Address
        foreach($DHCPObject in $PFObject){
            if($DHCPObject.Interface.Description -eq $Interface){
                if($MACaddr -NotIn $DHCPObject.staticmaps.MACaddr){Throw "Could not find Mac address $($Macaddress)"}
                elseif($ClientID -NotIn $DHCPObject.staticmaps.ClientID){Throw "Could not find ClientID address $($ClientID)"}
                $TrowError = $True # we set the throw error on true, if we cannot find the correct combination. the error will be thrown, if we find the combination we set the throw error on false
                foreach($staticmap in $DHCPObject.staticmaps){
                    if(($staticmap.MACaddr -eq $MACaddr) -and ($staticmap.ClientID -eq $ClientID)){
                        $staticmap | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                            # Only set if variable is set
                            if(get-variable $_.name -valueOnly -ErrorAction Ignore){ # Only set object if variable is set. don't override with empty value's
                                if($_.name -eq "Interface"){} #the Interface is not set in the object, but in it's parrent
                                else{
                                    $staticmap.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
                                }
                            }
                        }

                        $TrowError = $False
                    }
                }
                if($TrowError){Throw "Could not find the combination of MacAddress $($Macaddr) and ClientID $($ClientID) on interface $($Interface)"}
            }
        }
        Set-PFDHCPd -InputObject $PFserver -NewObject $PFObject    
    }
}

Function Delete-PFDHCPstaticmap{
     <#
    .SYNOPSIS
    The Delete-PFDHCPstaticmap function delete's a staticmap entry on the interface using the mac as identifier

    .DESCRIPTION
    The Delete-PFDHCPstaticmap function delete's a staticmap entry on the interface using the mac as identifier.
    It does check if the mac address excists, if not it throws a error.

    .PARAMETER MACaddr
    The mac address of the client that is going to get this ip address

    .PARAMETER Interface
    The interface of the dhcpd deamon you would like to use
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dhcpstaticmap -action Delete -Interface Client -MACaddr 10:f0:05:eb:ca:97 -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Interface Static Map is going to be deleted on')] [string]$Interface,
        [Parameter(Mandatory=$True, HelpMessage='Mac Address of the entry you would like to delete')] [string]$MACaddr
    )
    Process{
        $PFObject = get-pfdhcpd -Server $InputObject
        if($interface -NotIn $PFObject.interface.Description){
            Throw "Could not find Interface $($interface)"
        }
        foreach($DHCPObject in $PFObject){
            if($DHCPObject.Interface.Description -eq $Interface){
                if($MacAddr -NotIn $DHCPObject.staticmaps.macaddr){
                    Throw "Cound not find MacAddress: $($MacAddr) on Interface $($interface)"
                }
                $DHCPObject.staticmaps = $DHCPObject.staticmaps | Where-Object { $_.MacAddr -ne $MacAddr }
            }
        }
        Set-PFDHCPd -InputObject $InputObject -NewObject $PFObject
    }
}

Function Write-PFDHCPstaticmap{
     <#
    .SYNOPSIS
    The Write-PFDHCPstaticmap function display's the staticmap entry's per interface.

    .DESCRIPTION
    The Write-PFDHCPstaticmap function display's the staticmap entry's per interface.

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dhcpstaticmap -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
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
                    $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object { # first we get al the dhcpstaticmap settings
                        $Properties.add($_.name,$DHCPStatiMap.staticmaps[$indexDHCPStatiMap].($_.name))
                    }
                    $Properties.Interface = $DHCPStatiMap.Interface # then we add the interface this staticmap excists on
                    $NewObject = New-Object -TypeName "PFDHCPstaticmap" -Property $Properties # create a new pfdhcpstaticmap object with the property's we just added
                    $Collection.add($NewObject) # we add the new object to the array
                    $indexDHCPStatiMap++
                }
            }catch{}
        }
        $Collection | Format-table Interface,Hostname,Domain,ClientID,MACaddr,IPaddr,Description,Gateway,DNSserver,NTPServer
    }
}

Function Add-PFFirewall{
    <#
    .SYNOPSIS
    The Add-PFFirewall function add's a firewall rule.

    .DESCRIPTION
    The Add-PFFirewall function add's a firewall rule.
    The interface entry is a single entry, except if it is a floating rule, than there are multiple interface's in a array possible
    These interfaces must be enterd seperated by a space.
    If the source or destination contain a space, it must be a internal interface address or network.

    .PARAMETER IsFloating
    if it is a floating rule (this is a bool)

    .PARAMETER IsQuick
    if Quick match is enabled (this is a bool)

    .PARAMETER IsLogged
    if logging is enabled (this is a bool)

    .PARAMETER Type
    Type of firewall rule, Block, Rejector Pass

    .PARAMETER IpProtocol
    The type of ip protocol, inet, inet6 or inet46

    .PARAMETER Interface
    The Interface

    .PARAMETER Protocol
    Network protocol like: TCP, UDP, ICMP

    .PARAMETER SourceAddress
    Source Address

    .PARAMETER SourcePort
    Source Port

    .PARAMETER DestinationAddress
    Destination Address

    .PARAMETER DestinationPort
    Destination Port

    .PARAMETER Description
    The Description of the firewall rule

    .PARAMETER NewLineNumber
    The New Line Number


    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Firewall -action add -IsFloating $true -IsQuick $false -IsLogged $false -Type pass -IpProtocol inet -Interface 'WAN manage' -Protocol any -SourceAddress 'Client address' -SourcePort any -DestAddress any -DestPort any -Description 'This is a xmlrpc test' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='if it is a floating rule')] [Bool] $IsFloating,
        [Parameter(Mandatory=$false, HelpMessage='if Quick match is enabled')] [Bool] $IsQuick,
        [Parameter(Mandatory=$false, HelpMessage='if logging is enabled')] [Bool] $IsLogged,
        [Parameter(Mandatory=$false, HelpMessage='Type of firewall rule, Block, Rejector Pass')] [string] $Type,
        [Parameter(Mandatory=$false, HelpMessage='The type of ip protocol, inet, inet6 or inet46')] [string] $IpProtocol,
        [Parameter(Mandatory=$false, HelpMessage='The Interface')] [array] $Interface,
        [Parameter(Mandatory=$false, HelpMessage='Network protocol like: TCP, UDP, ICMP')] [string] $Protocol,
        [Parameter(Mandatory=$false, HelpMessage='Source Address')] [string] $SourceAddress,
        [Parameter(Mandatory=$false, HelpMessage='Source Port')] [string] $SourcePort,
        [Parameter(Mandatory=$false, HelpMessage='Destination Address')] [string] $DestinationAddress,
        [Parameter(Mandatory=$false, HelpMessage='Destination Port')] [string] $DestinationPort,
        [Parameter(Mandatory=$false, HelpMessage='The Description of the firewall rule')] [string] $Description,
        [Parameter(Mandatory=$false, HelpMessage='The new line number')][Alias('NewLN')][Alias('NewLineNumber')] [string] $lineNumber
    )
    Begin{
        $created = $updated = @{
            Username = $Username
            time = [int](get-date -UFormat "%s")
        }
        $IsDisabled = $False
        $tracker = [int](get-date -UFormat "%s")
    }
    process{
        $PFObject = get-PFFirewall -Server $InputObject
        $InterfaceObject = Get-PFInterface -server $InputObject
        $Alias = Get-PFAlias -server $InputObject
        # Line number editting
        if(-not $lineNumber){$lineNumber = ($PFObject | Measure-Object -Property Linenumber -maximum).count} # i use count because this starts at 1 and not at 0 as the array does, so i don't need to add one.
        if($lineNumber -in $PFObject.linenumber){ # If the linenumber exists we need add one to the original and all up line number to shift them down
            $PFObject | ForEach-Object {
                if($_.linenumber -ge $lineNumber){$_.linenumber += 1}
            }
        }
        $Properties = @{}
        # if Protocol is any, convert to a blank value
        if($Protocol -eq "Any"){$Protocol = ""}
        
        # If IsFloating, then interface can be a array of interfaces
        if($IsFloating){
            $Interface = $Interface.split(" ")
        }
        $Interface | ForEach-Object {
            if($_ -NotIn $InterfaceObject.Description){Throw "Cannot find interface $($_) on the PFsense"}
            [array]$intface += (Get-PFInterface -server $InputObject -Description $_)
        }
        $Interface = $intface
        # source and destination address can be a address, internal network or a alias
        ($Sourceaddress,$DestinationAddress) | foreach{
            if($_ -match " "){ # if there is a space, it must be a internal network or address
                if($_.split(" ")[0] -NotIn $InterfaceObject.Description){Throw "Cannot find interface $($_.split(" ")[0]) network or address on the PFsense"}
                if($_.split(" ")[1] -NotIn ("address","network")){Throw "$($_.split(" ")[1]) isn't a valid input, it can only be Address or Network"}
            }
            elseif($_ -eq "any"){}
            # if there is no space, it must be a ipaddress, a ipnetwork, or a alias
            else{
                try{  # in the try we try to convert the value to a ipaddress
                    if($_ -match "/"){ # here we see if it is a subnetted address
                        if(([ipaddress]$_.split("/")[0]) -and $_.split("/")[1] -in 1..128){} #ToDo: check if ipv4 32 and ipv6 128
                    }
                    else{ # or a host address
                        if([ipaddress]$_){}
                    }
                }
                catch{ # if we cannot convert to a ipaddress or ipnetwork. it must be a alias, if it's no alias, it isn't a valid input so throw a error.
                    if($_ -cNotIn $alias.name){Throw "$($_) isn't a valid input."}
                }
            }
        }
        $Object = New-Object -TypeName "PFFirewall" -Property $Properties
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $NewObject = New-Object -TypeName "PFFirewall" -Property $Properties
        $PFObject += $NewObject
        Set-pffirewall -InputObject $InputObject -NewObject $PFObject
    }
}

function Delete-PFFirewall{
     <#
    .SYNOPSIS
    The Delete-PFFirewall function delete's a Firewall rule based on it's tracker number.

    .DESCRIPTION
    The Delete-PFFirewall function delete's a Firewall rule based on it's tracker number.
    It does check if the tracker number excists

    .PARAMETER tracker
    The tracker number of the firewall rule you like to delete
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Firewall -action delete -tracker 1586431324 -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Tracker id of the firewall rule you would like to edit')] [string] $tracker
    )
    Process{
        $PFObject = Get-PFFirewall -Server $InputObject
        if($tracker -NotIn $PFObject.tracker){
            Throw "Could not find tracker number $($tracker)"
        }
        $PFObject = $PFObject | Where-Object { $_.tracker -ne $tracker }
        Set-pffirewall -InputObject $InputObject -NewObject $PFObject
    }
}

Function edit-PFFirewall{
    <#
    .SYNOPSIS
    The Add-PFFirewall function add's a firewall rule.

    .DESCRIPTION
    The Add-PFFirewall function add's a firewall rule.
    The interface entry is a single entry, except if it is a floating rule, than there are multiple interface's in a array possible
    These interfaces must be enterd seperated by a space.
    If the source or destination contain a space, it must be a internal interface address or network.

    .PARAMETER IsFloating
    if it is a floating rule (this is a bool)

    .PARAMETER IsQuick
    if Quick match is enabled (this is a bool)

    .PARAMETER IsLogged
    if logging is enabled (this is a bool)

    .PARAMETER Type
    Type of firewall rule, Block, Rejector Pass

    .PARAMETER IpProtocol
    The type of ip protocol, inet, inet6 or inet46

    .PARAMETER Interface
    The Interface

    .PARAMETER Protocol
    Network protocol like: TCP, UDP, ICMP

    .PARAMETER SourceAddress
    Source Address

    .PARAMETER SourcePort
    Source Port

    .PARAMETER DestinationAddress
    Destination Address

    .PARAMETER DestinationPort
    Destination Port

    .PARAMETER Description
    The Description of the firewall rule

    .PARAMETER tracker
    The Tracker id of the firewall rule you would like to edit

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Firewall -action edit -tracker 1586431324 -IsFloating $true -IsQuick $false -IsLogged $true -Type pass -IpProtocol inet -Interface 'WAN manage' -Protocol any -SourceAddress 'Client address' -SourcePort any -DestAddress any -DestPort any -Description 'This is a xmlrpc test' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='if it is a floating rule')] [Bool] $IsFloating,
        [Parameter(Mandatory=$false, HelpMessage='if Quick match is enabled')] [Bool] $IsQuick,
        [Parameter(Mandatory=$false, HelpMessage='if logging is enabled')] [Bool] $IsLogged,
        [Parameter(Mandatory=$false, HelpMessage='Type of firewall rule, Block, Rejector Pass')] [string] $Type,
        [Parameter(Mandatory=$false, HelpMessage='The type of ip protocol, inet, inet6 or inet46')] [string] $IpProtocol,
        [Parameter(Mandatory=$false, HelpMessage='The Interface')] [array] $Interface,
        [Parameter(Mandatory=$false, HelpMessage='Network protocol like: TCP, UDP, ICMP')] [string] $Protocol,
        [Parameter(Mandatory=$false, HelpMessage='Source Address')] [string] $SourceAddress,
        [Parameter(Mandatory=$false, HelpMessage='Source Port')] [string] $SourcePort,
        [Parameter(Mandatory=$false, HelpMessage='Destination Address')] [string] $DestinationAddress,
        [Parameter(Mandatory=$false, HelpMessage='Destination Port')] [string] $DestinationPort,
        [Parameter(Mandatory=$true, HelpMessage='The Tracker id of the firewall rule you would like to edit')] [string] $tracker,
        [Parameter(Mandatory=$false, HelpMessage='The Description of the firewall rule')] [string] $Description
    )
    Begin{
        $updated = @{
            Username = $Username
            time = [int](get-date -UFormat "%s")
        }
    }
    process{
        $PFObject = get-PFFirewall -Server $InputObject
        $InterfaceObject = Get-PFInterface -server $InputObject
        $Alias = Get-PFAlias -server $InputObject
        $Properties = @{}
        # if Protocol is any, convert to a blank value
        if($Protocol -eq "Any"){$Protocol = ""}
        # Check if the tracker number is valid
        if($tracker -NotIn $PFObject.tracker){Throw "Can not find a firewall rule with tracker number $($tracker)"}
        # If IsFloating, then interface can be a array of interfaces
        if($IsFloating){
            $Interface = $Interface.split(" ")
        }
        $Interface | ForEach-Object {
            if($_ -NotIn $InterfaceObject.Description){Throw "Cannot find interface $($_) on the PFsense"}
            [array]$intface += (Get-PFInterface -server $InputObject -Description $_)
        }
        $Interface = $intface
        # source and destination address can be a address, internal network or a alias
        ($Sourceaddress,$DestinationAddress) | foreach{
            if($_ -match " "){ # if there is a space, it must be a internal network or address
                if($_.split(" ")[0] -NotIn $InterfaceObject.Description){Throw "Cannot find interface $($_.split(" ")[0]) network or address on the PFsense"}
                if($_.split(" ")[1] -NotIn ("address","network")){Throw "$($_.split(" ")[1]) isn't a valid input, it can only be Address or Network"}
            }
            elseif($_ -eq "any"){}
            # if there is no space, it must be a ipaddress, a ipnetwork, or a alias
            else{
                try{  # in the try we try to convert the value to a ipaddress
                    if($_ -match "/"){ # here we see if it is a subnetted address
                        if(([ipaddress]$_.split("/")[0]) -and $_.split("/")[1] -in 1..128){}
                    }
                    else{ # or a host address
                        if([ipaddress]$_){}
                    }
                }
                catch{ # if we cannot convert to a ipaddress or ipnetwork. it must be a alias, if it's no alias, it isn't a valid input so throw a error.
                    if($_ -NotIn $alias.name){Throw "$($_) isn't a valid input."}
                }
            }
        }
        foreach($FirewallRule in $PFObject){
            if($FirewallRule.tracker -eq $tracker){
                # Set al the settings
                $FirewallRule | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                    # Only set if variable is set
                    if(get-variable $_.name -valueOnly -ErrorAction Ignore){ # Only set object if variable is set. don't override with empty value's
                        $FirewallRule.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
                    }
                }
            }
        }
        Set-pffirewall -InputObject $InputObject -NewObject $PFObject
    }
}

function Move-PFFirewall{
    <#
    .SYNOPSIS
    The Move-PFFirewall function move's a firewall rule from the old line number to the new line number. 

    .DESCRIPTION
    The Move-PFFirewall function move's a firewall rule from the old line number to the new line number. 

    .PARAMETER OldLineNumber
    The line number you would like to move

    .PARAMETER NewLineNumber
    the line number you would like to move the line to.

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Firewall -action move -OldLineNumber 6 -newlinenumber 3 -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell

    #>
    [CmdletBinding()]
    param (
    [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
    [Parameter(Mandatory=$false, HelpMessage='The old line number')][Alias('OldLN')] [string] $OldLineNumber,
    [Parameter(Mandatory=$false, HelpMessage='The new line number')][Alias('NewLN')] [string] $NewLineNumber
    )
    Process{
        $PFObject = Get-PFFirewall -Server $InputObject
        if($NewLineNumber -eq $OldLineNumber){Throw "The Old and New linenumber are equal, no need to move exiting"}
        if($NewLineNumber -NotIn $PFObject.lineNumber){Throw "The NewLineNumber does not excists on the pfsense"}
        if($oldLineNumber -NotIn $PFObject.lineNumber){Throw "The OldLineNumber does not excists on the pfsense"}
        if($NewLineNumber -gt $OldLineNumber){
            $PFObject | ForEach-Object {
                if($_.Linenumber -eq $OldLineNumber){$workObject = $_} # save the working object to change it's linenumber after the movement's have been done
                if(($_.linenumber -le $NewLineNumber) -and ($_.Linenumber -ge $OldLineNumber)){$_.linenumber -= 1}
            }
        }
        if($NewLineNumber -lt $OldLineNumber){
            $PFObject | ForEach-Object {
                if($_.Linenumber -eq $OldLineNumber){$workObject = $_}
                if(($_.linenumber -ge $NewLineNumber) -and ($_.Linenumber -le $OldLineNumber)){$_.linenumber += 1}
            }
        }
        $workObject.linenumber = $NewLineNumber 
        Set-pffirewall -InputObject $InputObject -NewObject $PFObject
    }
}


function UpDown-PFFirewall{
    <#
   .SYNOPSIS
   The UpDown-PFFirewall function move's a firewall rule up or down one line. 

   .DESCRIPTION
   The UpDown-PFFirewall function move's a firewall rule up or down one line.
   It does check if the tracker number excists.
   Default it move's the rule down, the switch up make's the rule go up

   .PARAMETER tracker
   The tracker number of the firewall rule you would like to move up or down.

   .PARAMETER Up
   The Up switch move's the firewall rule up instead of down

   .EXAMPLE
   ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Firewall -action down -tracker 1586354712 -notls

   .EXAMPLE
   ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Firewall -action up -tracker 1586354712 -notls

   .LINK
   https://github.com/RaulGrayskull/PFSense_Powershell
   
   #>
   [CmdletBinding()]
   param (
       [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
       [Parameter(Mandatory=$true, HelpMessage='The Tracker id of the firewall rule you would like to edit')] [string] $tracker,
       [Parameter(Mandatory=$false, HelpMessage='The Tracker id of the firewall rule you would like to edit')] [switch] $up
   )
   Process{
       $PFObject = Get-PFFirewall -Server $InputObject
       if($tracker -NotIn $PFObject.tracker){
           Throw "Could not find tracker number $($tracker)"
       }
       $newPFObject= @()
       if($up){[array]::Reverse($PFObject)}
       $Hold = $false
       while($PFObject){
           $First, $PFObject = $PFObject
           if($Hold){
               $newPFObject += $first
               $newPFObject += $Hold
               $Hold = $false
           }
           else{
               if($tracker -eq $first.tracker){
                   $hold = $first
               }
               else{
                   $newPFObject += $first
               }
           }
       }
       if($up){[array]::Reverse($newPFObject)}
       Set-pffirewall -InputObject $InputObject -NewObject $NewPFObject
   }
}



Function Write-PFFirewall{
    <#
    .SYNOPSIS
    The Write-PFFirewall function display's Firewall rule's

    .DESCRIPTION
    The Write-PFFirewall function display's Firewall rule's

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Firewall -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFFirewall -Server $InputObject
        $PFObject | Format-table lineNumber,IsFloating,IsQuick,IsDisabled,IsLogged,Type,IPProtocol,interface,Protocol,SourceAddress,SourcePort,DestinationAddress,DestinationPort,Description,tracker 
    }
}

Function Add-PFGateway{
    <#
   .SYNOPSIS
   The Add-PFGateway function Add's a Gateway to the PFSense. 

   .DESCRIPTION
   The Add-PFGateway function Add's a Gateway to the PFSense. 
   The Name, IpAddress and MonitoringAddress must be unique of each gateway.

   .PARAMETER Name
   The name of the new gateway

   .PARAMETER IntFace
   The name of the interface where the gateway live's one. this is te user name.

   .PARAMETER IpProtocol
   The Ip Protocol that is going to be used (inet, inet6 or inet46)

   .PARAMETER Gateway
   The exual gateway address

   .PARAMETER Monitor
   The ip address of the monitoring address of the gateway

   .PARAMETER Weight
   The weight the gateway has, this can be used for fail over orders.

   .PARAMETER Description
   The description of the gateway

   .EXAMPLE
   ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service gateway -action add -name XMLRPC -Interface Manage -Gateway 172.16.20.9 -Weight 1 -Monitor 172.16.20.8 -Protocol inet -Description 'To Test xml rpc add' -notls

   .LINK
   https://github.com/RaulGrayskull/PFSense_Powershell
   
   #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='The Name for this entry')] [string] $Name,
        [Parameter(Mandatory=$True, HelpMessage='The Interface the port forward is going to be created on')][Alias('Interface')] [string]$Intface,
        [Parameter(Mandatory=$false, HelpMessage='The Ip Protocol, inet or inet6')][Alias('Protocol')] [string] $IpProtocol,
        [Parameter(Mandatory=$false, HelpMessage='The gateway address')] [string] $Gateway,
        [Parameter(Mandatory=$false, HelpMessage='The Monitoring address')] [string] $Monitor,
        [Parameter(Mandatory=$false, HelpMessage='The weight of the route')] [string] $Weight,
        [Parameter(Mandatory=$false, HelpMessage='The description of the route')] [string] $Description
        )
    Begin{
    }
    process{
        $PFObject = Get-PFGateway -Server $InputObject
        # Check User input
        if($name -in $PFObject.name){Throw "The Gateway name: $($name) is already in use"}
        if($Gateway -in $PFObject.Gateway){Throw "The Gateway address: $($Gateway) is already in use"}
        if($Monitor -in $PFObject.Monitor){Throw "The Gateway monitoring address: $($Monitor) is already in use"}
        # Actual adding
        $interface = $($InputObject | Get-PFInterface -Description $Intface)
        $Object = New-Object -TypeName "PFGateway" -Property $Properties
        $Properties = @{}
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $NewObject = New-Object -TypeName "PFGateway" -Property $Properties
        $PFObject += $NewObject
        Set-PFGateway -InputObject $InputObject -NewObject $PFObject
    }
}


Function Delete-PFGateway{
    <#
   .SYNOPSIS
   The Delete-PFGateway function deletes a Gateway to the PFSense. 

   .DESCRIPTION
   The Delete-PFGateway function deletes a Gateway to the PFSense. 
   The Name of the gateway is used to identifie it and delete it from the pfsense

   .PARAMETER Name
   The name of the new gateway

   .EXAMPLE
   ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service gateway -action Delete -name extra_gateway -notls

   .LINK
   https://github.com/RaulGrayskull/PFSense_Powershell
   
   #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='The Name for this entry')] [string] $Name
        )
    Begin{
    }
    process{
        $PFObject = Get-PFGateway -Server $InputObject
        # Check User input
        if($name -NotIn $PFObject.name){Throw "The Gateway name: $($name). Cannot be found"}
        # Delete the PFobject that has the name in the $name variable
        $PFObject = ($PFObject | Where-Object {$_.name -ne $name})
        Set-PFGateway -InputObject $InputObject -NewObject $PFObject
    }
}


Function Edit-PFGateway{
    <#
   .SYNOPSIS
   The Edit-PFGateway function edit's a Gateway to the PFSense. 

   .DESCRIPTION
   The Edit-PFGateway function edit's a Gateway to the PFSense. 
   The Unique Identifier is the name, the ipaddress and monitoring address must also be unique on the pfsense

   .PARAMETER Name
   The name of the gateway

   .PARAMETER IntFace
   The name of the interface where the gateway live's one. this is te user name.

   .PARAMETER IpProtocol
   The Ip Protocol that is going to be used (inet, inet6 or inet46)

   .PARAMETER Gateway
   The exual gateway address

   .PARAMETER Monitor
   The ip address of the monitoring address of the gateway

   .PARAMETER Weight
   The weight the gateway has, this can be used for fail over orders.

   .PARAMETER Description
   The description of the gateway

   .EXAMPLE
   ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service gateway -action edit -name extra_gateway -Interface Manage -Gateway 192.168.38.19 -Weight 1 -Monitor 192.168.38.19 -Protocol inet -Description 'this is a extra gateway' -notls

   .LINK
   https://github.com/RaulGrayskull/PFSense_Powershell
   
   #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Name for this entry')] [string] $Name,
        [Parameter(Mandatory=$True, HelpMessage='The Interface the port forward is going to be created on')][Alias('Interface')] [string]$Intface,
        [Parameter(Mandatory=$false, HelpMessage='The Ip Protocol, inet or inet6')][Alias('Protocol')] [string] $IpProtocol,
        [Parameter(Mandatory=$false, HelpMessage='The gateway address')] [string] $Gateway,
        [Parameter(Mandatory=$false, HelpMessage='The Monitoring address')] [string] $Monitor,
        [Parameter(Mandatory=$false, HelpMessage='The weight of the route')] [string] $Weight,
        [Parameter(Mandatory=$false, HelpMessage='The description of the route')] [string] $Description
        )
    Begin{
    }
    process{
        $PFObject = Get-PFGateway -Server $InputObject
        # Check User input
        if($name -NotIn $PFObject.name){Throw "The Gateway name: $($name). Cannot be found"}
        # The Gateway and monitoring do not have to change, so we need all the gateway and monitoring address, except the one we are editting to check for duplicte's
        $PFObjectCheck = ($PFObject | Where-Object {$_.name -ne $name})
        if($Gateway -in $PFObjectCheck.Gateway){Throw "The Gateway address: $($Gateway) is already in use"}
        if($Monitor -in $PFObjectCheck.Monitor){Throw "The Gateway monitoring address: $($Monitor) is already in use"}
        # Actual adding
        $interface = $($InputObject | Get-PFInterface -Description $Intface)
        foreach($GatewayObject in $PFObject){
            if($GatewayObject.name -eq $name){
                $GatewayObject | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                    # Only set if variable is set
                    if(get-variable $_.name -valueOnly -ErrorAction Ignore){ # Only set object if variable is set. don't override with empty value's
                        $GatewayObject.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
                    }
                }
            }

        }
        Set-PFGateway -InputObject $InputObject -NewObject $PFObject
    }
}



Function Write-PFGateway{
    <#
   .SYNOPSIS
   The Write-PFGateway function Display's all the Gateway's of the pfsense

   .DESCRIPTION
   The Write-PFGateway function Display's all the Gateway's of the pfsense

   .EXAMPLE
   ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service gateway -action print -notls

   .LINK
   https://github.com/RaulGrayskull/PFSense_Powershell
   
   #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
        $Collection = New-Object System.Collections.ArrayList
    }
    process{
        $PFObject = get-pfgateway -Server $InputObject
        $exclude = ("")
        foreach($Rule in $PFObject){
            if($rule.Interface){
                $Collection.Add($Rule) | out-null
            }
        }
        $Collection | Format-table Name,Interface,Gateway,Monitor,Weight,IPProtocol,Description
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
        $Collection | format-table Enable,Name,Description,Interface,IPv4Address,IPv4Subnet,IPv4Gateway,IPv6Address,IPv6Subnet,IPv6Gateway,blockpriv,BlockBogons,Media
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
            time = [int](get-date -UFormat "%s")
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
    # ToDo: Create check to look for duplicate
    Set-PFNatRule -InputObject $InputObject -NewObject $PFObject
    }
}


Function Delete-PFNatRule{
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
        }
    $Delete = New-Object -TypeName "PFNATRule" -Property $Properties
    $PFOriginal = get-PFNATRule -Server $InputObject
     $PFObject = $PFOriginal | Where-Object {
        ($_.Protocol -ne $Delete.protocol) -or
        ($_.SourceAddress -ne $Delete.SourceAddress) -or
        ($_.SourcePort -ne $Delete.SourcePort) -or
        ($_.DestinationAddress -ne $Delete.DestinationAddress) -or
        ($_.DestinationPort -ne $Delete.DestinationPort) -or
        ($_.target -ne $Delete.target)
        }

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

    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Flow.$Service.$Action)) -ArgumentList $PFServer,$path,$file,$Network,$Gateway,$Description,$Interface,$From,$To,$netmask,$Domain,$DNSServer,$NTPServer,$Alias,$Type,$Address,$Detail,$HostName,$ClientID,$MacAddr,$Protocol,$SourceAddress,$DestAddress,$DestPort,$NatIp,$NatPort,$Weight,$Monitor,$Name,$IpProtocol,$IsLogged,$IsQuick,$IsFloating,$tracker,$OldLineNumber,$NewLineNumber
 
} catch { 
    Write-Error $_.Exception.Message
    exit 1
}

