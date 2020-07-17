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
    [Parameter(Mandatory=$false, HelpMessage='IPv4 Address')][Alias('IPv4A')] [string] $IPv4Address,
    [Parameter(Mandatory=$false, HelpMessage='IPv4 Subnet')][Alias('IPv4S')] [string] $IPv4Subnet,
    [Parameter(Mandatory=$false, HelpMessage='IPv4 Gateway')][Alias('IPv4G')] [string] $IPv4Gateway,
    [Parameter(Mandatory=$false, HelpMessage='IPv6 Address')][Alias('IPv6A')] [string] $IPv6Address,
    [Parameter(Mandatory=$false, HelpMessage='IPv6 Subnet')][Alias('IPv6S')] [string] $IPv6Subnet,
    [Parameter(Mandatory=$false, HelpMessage='IPv6 Gateway')][Alias('IPv6')] [string] $IPv6Gateway,
    [Parameter(Mandatory=$false, HelpMessage='Block private networks and loopback addresses')][string] $blockpriv,
    [Parameter(Mandatory=$false, HelpMessage='Block bogon networks')][string] $BlockBogons,
    [Parameter(Mandatory=$false, HelpMessage='The Active interfaces')][Alias('ActiveInterface')][string] $ActiveInt,
    [Parameter(Mandatory=$false, HelpMessage='The Outgoint Interfaces')][string] $OutgoingInterface,
    [Parameter(Mandatory=$false, HelpMessage='DNS Sec enable or disable')][bool] $dnssec,
    [Parameter(Mandatory=$false, HelpMessage='.')][bool] $DHCPReg,
    [Parameter(Mandatory=$false, HelpMessage='.')][bool] $DHCPRegstatic,
    [Parameter(Mandatory=$false, HelpMessage='.')][bool] $Dhcpfirst,
    [Parameter(Mandatory=$false, HelpMessage='.')][bool] $DomainNeeded,
    [Parameter(Mandatory=$false, HelpMessage='.')][bool] $StrictOrder,
    [Parameter(Mandatory=$false, HelpMessage='.')][bool] $NoPrivateReverse,
    [Parameter(Mandatory=$false, HelpMessage='.')][bool] $Strictbind,
    [Parameter(Mandatory=$false, HelpMessage='The port you would like to use')][string] $port,
    [Parameter(Mandatory=$false, HelpMessage='The SSL port')][string] $sslport,
    [Parameter(Mandatory=$false, HelpMessage='Costum Options')][string] $CustomOptions,
    [Parameter(Mandatory=$false, HelpMessage='SSL cert Ref of a ssl certificate known by the PFsense')][string] $sslcertref,
    [Parameter(Mandatory=$False, HelpMessage='Hostname of the Alias')] [string] $HostNameAlias,
    [Parameter(Mandatory=$False, HelpMessage='The Domain of the Alias')] [string] $DomainAlias,
    [Parameter(Mandatory=$false, HelpMessage='The Description of the Alias')] [string] $DescriptionAlias,
    [Parameter(Mandatory=$false, HelpMessage='When set, queries to all DNS servers for this domain will be sent using SSL/TLS on the default port of 853.')] [Bool] $TLSQueries,
    [Parameter(Mandatory=$false, HelpMessage='An optional TLS hostname used to verify the server certificate when performing TLS Queries.')] [string] $TlsHostname,
    [Parameter(Mandatory=$false, HelpMessage='802.1Q VLAN tag (between 1 and 4094).')][int]$Tag,
    [Parameter(Mandatory=$false, HelpMessage='802.1Q VLAN Priority (between 0 and 7).')][int]$Priority,
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
    The name of the alias may only consist of the characters "a-z, A-Z, 0-9 and _"

    .PARAMETER Type
    The Type of the alias, could be Host, Network or Port

    .PARAMETER Address
    The IP, Network address or the Port number

    .PARAMETER Detail
    The description of the address value

    .PARAMETER Description
    A description may be entered here for administrative reference (not parsed).
    
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
    The name of the alias may only consist of the characters "a-z, A-Z, 0-9 and _".

    .PARAMETER Type
    The Type of the alias, could be Host, Network or Port

    .PARAMETER Address
    The IP, Network address or the Port number

    .PARAMETER Detail
    The description of the address value

    .PARAMETER Description
    A description may be entered here for administrative reference (not parsed).
    
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
                    if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
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
    The name of the alias may only consist of the characters "a-z, A-Z, 0-9 and _".

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
    The name of the alias may only consist of the characters "a-z, A-Z, 0-9 and _".

    .PARAMETER Address
    The IP, Network address or the Port number

    .PARAMETER Detail
    A description may be entered here for administrative reference (not parsed).
  
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
    The name of the alias may only consist of the characters "a-z, A-Z, 0-9 and _".

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

Function Write-PFCert{
    <#
    .SYNOPSIS
    the Write-PFCert Function display's the cert's ReferenceID and Description of the pfsense

    .DESCRIPTION
    the Write-PFCert Function display's the cert's ReferenceID and Description of the pfsense
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service cert -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFCert -Server $InputObject
        $PFObject | Format-table ReferenceID,Description
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
        [Parameter(Mandatory=$True, HelpMessage='The Interface the DHCPd listen on')][Alias('Interface')] [string]$Intfa,
        [Parameter(Mandatory=$false, HelpMessage='The Starting ip address of the pool')] [string]$RangeFrom,
        [Parameter(Mandatory=$false, HelpMessage='The Last IP address of the pool')] [string]$RangeTo,
        [Parameter(Mandatory=$false, HelpMessage='The Netmask used by the pool')] [string]$netmask,
        [Parameter(Mandatory=$false)][String]$Gateway,
        [Parameter(Mandatory=$false, HelpMessage='The Domain')] [string]$Domain,
        [Parameter(Mandatory=$false, HelpMessage='The DNSServer used bij the pool')] [string]$DNSServer,
        [Parameter(Mandatory=$false, HelpMessage='The NTPServer used bij the pool')] [string]$NTPServer,
        [Parameter(Mandatory=$false, HelpMessage='Enable or disable the dhcp deamon on the interface')] [Bool]$Enable
    )
    Process{
        $PFObject = get-pfdhcpd -Server $InputObject
        if($Intfa -NotIn $PFObject.interface.Description){
            throw "the DHCPD doen not know $($Intfa), Make sure the interface has a fixed ip address and not a /32 subnet."
        }
        $Interface = $($InputObject | Get-PFInterface -Description $Intfa)
        foreach($dhcpdObject in $PFObject){
            if($dhcpdObject.interface.Description -eq $Interface){
                # check if the pool addresses are in the interface range, but only if range is set
                if(($RangeFrom) -or ($RangeTo)){
                    [net.IPAddress]$InterfaceAddress = $dhcpdObject.interface.IPv4Address
                    $Int64 = ([convert]::ToInt64(('1' * $($dhcpdObject.interface.IPv4Subnet) + '0' * (32 - $($dhcpdObject.interface.IPv4Subnet))), 2)) 
                    [net.IPAddress]$subnet = '{0}.{1}.{2}.{3}' -f ([math]::Truncate($Int64 / 16777216)).ToString(), ([math]::Truncate(($Int64 % 16777216) / 65536)).ToString(), ([math]::Truncate(($Int64 % 65536)/256)).ToString(), ([math]::Truncate($Int64 % 256)).ToString()
                    [net.IPAddress]$Rangefromaddress = $Rangefrom
                    [net.IPAddress]$RangeToaddress = $RangeTo
                    if(($InterfaceAddress.Address -band $subnet.address) -ne ($Rangefromaddress.address -band $subnet.address) -or `
                    ($InterfaceAddress.Address -band $subnet.address) -ne ($RangeToaddress.address -band $subnet.address)){
                        Throw "the pool range is not in the same subnet as the interface"
                    }
                }
                # Set al the settings
                $dhcpdObject | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                    # Only set if variable is set
                    if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
                    $dhcpdObject.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
                }
                }
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
        [Parameter(Mandatory=$True, HelpMessage='IP Address of the new entry')][alias('Address')] [string]$IPaddr,
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
        foreach($DHCPObject in $PFObject){
            if($DHCPObject.Interface.Description -eq $Interface){
                if($MACaddr -NotIn $DHCPObject.staticmaps.MACaddr){Throw "Could not find Mac address $($Macaddress)"}
                elseif($ClientID -NotIn $DHCPObject.staticmaps.ClientID){Throw "Could not find ClientID address $($ClientID)"}
                $TrowError = $True # we set the throw error on true, if we cannot find the correct combination. the error will be thrown, if we find the combination we set the throw error on false
                foreach($staticmap in $DHCPObject.staticmaps){
                    if(($staticmap.MACaddr -eq $MACaddr) -and ($staticmap.ClientID -eq $ClientID)){
                        $staticmap | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                            # Only set if variable is set
                            if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
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

Function Edit-PFDnsMasq{
    <#
    .SYNOPSIS
    the Edit-PFDnsMasq function sets the settings for the dnsmasq / dnsforwarder of the pfsense

    .DESCRIPTION
    the Edit-PFDnsMasq function sets the settings for the dnsmasq / dnsforwarder of the pfsense
  
    .parameter Enable 
    Enable DNS forwarder
    
    .parameter DHCPReg
    Register DHCP leases in DNS forwarder
    If this option is set machines that specify their hostname when requesting a DHCP lease will be registered in the DNS forwarder, so that their name can be resolved. The domain in System: General Setup should also be set to the proper value.

    .parameter DHCPRegstatic
    Register DHCP static mappings in DNS forwarder 
    If this option is set, IPv4 DHCP static mappings will be registered in the DNS forwarder so that their name can be resolved. The domain in System: General Setup should also be set to the proper value.

    .parameter Dhcpfirst
    Resolve DHCP mappings first
    If this option is set DHCP mappings will be resolved before the manual list of names below. This only affects the name given for a reverse lookup (PTR).

    .parameter DomainNeeded
    Require domain
    If this option is set pfSense DNS Forwarder (dnsmasq) will not forward A or AAAA queries for plain names, without dots or domain parts, to upstream name servers. If the name is not known from /etc/hosts or DHCP then a "not found" answer is returned. 

    .parameter StrictOrder
    Query DNS servers sequentially
    If this option is set pfSense DNS Forwarder (dnsmasq) will query the DNS servers sequentially in the order specified (System - General Setup - DNS Servers), rather than all at once in parallel. 

    .parameter NoPrivateReverse
    Do not forward private reverse lookups
    If this option is set pfSense DNS Forwarder (dnsmasq) will not forward reverse DNS lookups (PTR) for private addresses (RFC 1918) to upstream name servers. Any entries in the Domain Overrides section forwarding private "n.n.n.in-addr.arpa" names to a specific server are still forwarded. If the IP to name is not known from /etc/hosts, DHCP or a specific domain override then a "not found" answer is immediately returned. 

    .parameter Strictbind
    Strict interface binding
    If this option is set, the DNS forwarder will only bind to the interfaces containing the IP addresses selected above, rather than binding to all interfaces and discarding queries to other addresses.
    This option does NOT work with IPv6. If set, dnsmasq will not bind to IPv6 addresses.

    .parameter CustomOptions
    Enter any additional options to add to the dnsmasq configuration here, separated by a space or newline.

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsForwarder -action Edit -DHCPReg $True -DHCPRegstatic $false -Dhcpfirst $True -DomainNeeded $True -StrictOrder $True -NoPrivateReverse $True -Strictbind $True -CustomOptions 'This is a test entry' -notls

    .EXAMPLE
    ./pfsense.ps1' -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsForwarder -action Enable -notls
    
    .EXAMPLE
    ./pfsense.ps1' -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsForwarder -action Disable -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='Enable DNS forwarder')] [Bool]$Enable = $true,
        [Parameter(Mandatory=$false, HelpMessage='The port you would like to use')][string] $port,
        [Parameter(Mandatory=$false, HelpMessage='The Active interfaces')][Alias('ActiveInterface')][string] $ActiveInt,
        [Parameter(Mandatory=$false, HelpMessage='Register DHCP leases in DNS forwarder')][bool] $DHCPReg,
        [Parameter(Mandatory=$false, HelpMessage='Register DHCP leases in DNS forwarder')][bool] $DHCPRegstatic,
        [Parameter(Mandatory=$false, HelpMessage='Resolve DHCP mappings first')][bool] $Dhcpfirst,
        [Parameter(Mandatory=$false, HelpMessage='If this option is set pfSense DNS Forwarder (dnsmasq) will not forward A or AAAA queries for plain names')][bool] $DomainNeeded,
        [Parameter(Mandatory=$false, HelpMessage='If this option is set pfSense DNS Forwarder (dnsmasq) will query the DNS servers sequentially in the order specified (System - General Setup - DNS Servers), rather than all at once in parallel.')][bool] $StrictOrder,
        [Parameter(Mandatory=$false, HelpMessage='If this option is set pfSense DNS Forwarder (dnsmasq) will not forward reverse DNS lookups (PTR) for private addresses (RFC 1918) to upstream name servers.')][bool] $NoPrivateReverse,
        [Parameter(Mandatory=$false, HelpMessage='Strict interface binding')][bool] $Strictbind,
        [Parameter(Mandatory=$false, HelpMessage='any additional options')][string]$CustomOptions
        )
    Begin{
    }
    process{
        $PFObject = get-PFDnsMasq -Server $InputObject
        $PFObject | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
            # Only set if variable is set
            if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
                $PFObject.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
            }
        }
        Set-PFDnsMasq -InputObject $InputObject -NewObject $PFObject
        
    }
}
Function Write-PFDnsMasq{
    <#
    .SYNOPSIS
    The Write-PFDnsMasq function display's the DNSmasq/DNSForwarder settings

    .DESCRIPTION
    The Write-PFDnsMasq function display's the DNSmasq/DNSForwarder settings
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsForwarder -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFDnsMasq -Server $InputObject
        $PFObject | Format-table Enable,Port,ActiveInterface,DHCPReg,DHCPRegstatic,DHCPfirst,DomainNeeded,StrictOrder,NoPrivateReverse,Strictbind
    }
}

Function Write-PFDnsMasqHost{
    <#
    .SYNOPSIS
    

    .DESCRIPTION
    
  
    .EXAMPLE
    

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFDnsMasqhost -Server $InputObject
        $WriteObject = New-Object System.Collections.ArrayList
        foreach($PFHost in $PFObject){
            $index = 0
            $Object = New-Object -TypeName "PFDnsMasqHost" -Property $Properties
            $Properties = @{}
            try{
                # first we add the first alias to the $writeObject
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                    if($PFHost.$($_.name).gettype() -eq [PFDnsMasqHostEntry[]]){$Properties.add(($_.name),$PFHost.$($_.name)[$Index])}
                    else{$Properties.add(($_.name),$PFHost.$($_.name))}
                }
                $NewObject = New-Object -TypeName "PFDnsMasqHost" -Property $Properties 
                $WriteObject.add($NewObject) | out-null
                # Now we add one to the index to add all the other aliases to the writeobject
                $index++
                $Properties = @{}
                while($PFHost.Alias[$index]){
                    $Properties.Alias = $PFHost.Alias[$Index]
                    $NewObject = New-Object -TypeName "PFDnsMasqHost" -Property $Properties 
                    $WriteObject.add($NewObject) | out-null
                    $index++
                }
            }
            catch{$WriteObject.add($PFHost) | out-null}
        }
        $WriteObject | Format-table Hostname,Domain,Address,Description,Alias
    }
}


Function Write-PFDnsMasqCustomOptions {
    <#
    .SYNOPSIS
    The Write-PFDnsMasqCustomOptions function display's the DNSmasq/DNSForwarder CustomOptions

    .DESCRIPTION
    The Write-PFDnsMasqCustomOptions function display's the DNSmasq/DNSForwarder CustomOptions
  
    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsForwarder -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFDnsMasq -Server $InputObject
        $PFObject.CustomOptions 
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
                    if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
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
        $workObject = $PFObject | where-Object {$_.Linenumber -eq $OldLineNumber} # save the working object to change it's linenumber after the movement's have been done
        if($NewLineNumber -gt $OldLineNumber){
            $PFObject | Where-Object {($_.linenumber -le $NewLineNumber) -and ($_.Linenumber -ge $OldLineNumber)} | ForEach-Object {$_.Linenumber -= 1}
        }
        if($NewLineNumber -lt $OldLineNumber){
            $PFObject | Where-Object {($_.linenumber -ge $NewLineNumber) -and ($_.Linenumber -le $OldLineNumber)} | ForEach-Object {$_.Linenumber += 1}
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
                    if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
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

Function Edit-PFInterface{
    <#
    .SYNOPSIS
    The Edit-PFGateway function edit's a Gateway to the PFSense. 

    .DESCRIPTION
    The Edit-PFGateway function edit's a Gateway to the PFSense. 
    The Unique Identifier is the name, the ipaddress and monitoring address must also be unique on the pfsense

    .PARAMETER Name
    Internal name of the interface, For now this cannot be changed by this script
    It is here for when vlan's are implemented into the script

    .PARAMETER Description 
    Username of the interface

    .PARAMETER Interface 
    The FreeBSD Name of the interface, For now this cannot be changed by this script. 
    It is here for when vlan's are implemented into the script

    .PARAMETER IPv4Address 
    IPv4 Address

    .PARAMETER IPv4Subnet 
    IPv4 Subnet

    .PARAMETER IPv4Gateway 
    IPv4 Gateway

    .PARAMETER IPv6Address 
    IPv6 Address

    .PARAMETER IPv6Subnet 
    IPv6 Subnet

    .PARAMETER IPv6Gateway 
    IPv6 Gateway

    .PARAMETER blockpriv 
    Block private networks and loopback addresses

    .PARAMETER BlockBogons 
    Block bogon networks

    .PARAMETER Enable
    Enable or disable the interface, this is a bool so only take's $True or $False

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service interface -action Edit -Description Client -IPv4Address 192.168.199.1 -IPv4Subnet 231 -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='Internal name of the interface')][string] $Name,
        [Parameter(Mandatory=$True, HelpMessage='Username of the interface')][string] $Description,
        [Parameter(Mandatory=$false, HelpMessage='The FreeBSD Name of the interface')] [string] $Interface,
        [Parameter(Mandatory=$false, HelpMessage='IPv4 Address')][Alias('IPv4A')] [string] $IPv4Address,
        [Parameter(Mandatory=$false, HelpMessage='IPv4 Subnet')][Alias('IPv4S')] [string] $IPv4Subnet,
        [Parameter(Mandatory=$false, HelpMessage='IPv4 Gateway')][Alias('IPv4G')] [string] $IPv4Gateway,
        [Parameter(Mandatory=$false, HelpMessage='IPv6 Address')][Alias('IPv6A')] [string] $IPv6Address,
        [Parameter(Mandatory=$false, HelpMessage='IPv6 Subnet')][Alias('IPv6S')] [string] $IPv6Subnet,
        [Parameter(Mandatory=$false, HelpMessage='IPv6 Gateway')][Alias('IPv6')] [string] $IPv6Gateway,
        [Parameter(Mandatory=$false, HelpMessage='Block private networks and loopback addresses')][string] $blockpriv,
        [Parameter(Mandatory=$false, HelpMessage='Block bogon networks')][string] $BlockBogons,
        [Parameter(Mandatory=$false, HelpMessage='Block bogon networks')][bool] $Enable
    )
    Begin{}
    Process{
        $PFObject = get-pfinterface -Server $InputObject
        # Check User input
        if($Description -NotIn $PFObject.Description){Throw "The Interface: $($name). Cannot be found"}
        try{ # Check if the ipaddress are valid
            ($IPv4Address,$IPv4Gateway,$IPv6Address,$IPv6Gateway) | Foreach {
                if($_){# Only test if it is a valid variable
                    [Ipaddress]$IPCheck = $_
                }
            }
        }
        catch{throw "{0}" -f $_.Exception.Message}
        if(($IPv4Subnet -NotIn 1..32) -and ($IPv4Subnet)){Throw "{0} is not a valid IPv4Subnet" -f $IPv4Subnet}
        if(($IPv6Subnet -NotIn 1..128) -and ($IPv6Subnet)){Throw "{0} is not valid IPv4Subnet" -f $IPv6Subnet}

        # Actual Edit
        $WorkingObject = $PFObject | Where-Object {$_.Description -eq $Description}
        $WorkingObject | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
            # Only set if variable is set
            if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
                $WorkingObject.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
            }
        }
        Set-PFInterface -InputObject $InputObject -NewObject $PFObject
    }
}

Function Write-PFInterface{
    <#
    .SYNOPSIS
    The Write-PFInterface function Display's all the Interface's of the pfsense

    .DESCRIPTION
    The Write-PFInterface function Display's all the Interface's of the pfsense

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Interface -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
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
    <#
    .SYNOPSIS
    The Add-PFNatRule function Add's a NatRule / PortfwdRule to the PFSense. 

    .DESCRIPTION
    The Add-PFNatRule function Add's a NatRule / PortfwdRule to the PFSense. 

    .PARAMETER Interface
    The Interface the port forward is going to be created on

    .PARAMETER Protocol
    Network protocol like: TCP, UDP, ICMP

    .PARAMETER SourceAddress
    Source Address

    .PARAMETER SourcePort
    Source Port

    .PARAMETER DestAddress
    Destination Address

    .PARAMETER DestPort
    Destination Port

    .PARAMETER NatIp
    The Local Ip Address

    .PARAMETER NatPort
    The Local Port

    .PARAMETER Description
    The Description

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Portfwd -action Add -Interface Client -Protocol UDP -SourceAddress 'Manage Network' -SourcePort any -DestAddress 192.168.11.0/23 -DestPort 8443 -NatIp 192.168.1.4 -NatPort 443 -Description 'this is a test' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Interface the port forward is going to be created on')][Alias('Interface')] [string]$Intface,
        [Parameter(Mandatory=$false, HelpMessage='Network protocol like: TCP, UDP, ICMP')] [string] $Protocol,
        [Parameter(Mandatory=$false, HelpMessage='Source Address')] [string] $SourceAddress,
        [Parameter(Mandatory=$false, HelpMessage='Source Port')] [string] $SourcePort,
        [Parameter(Mandatory=$false, HelpMessage='Destination Address')][Alias('DestAddress')] [string] $DestinationAddress,
        [Parameter(Mandatory=$false, HelpMessage='Destination Port')][Alias('DestPort')] [string] $DestinationPort,
        [Parameter(Mandatory=$false, HelpMessage='The Local Ip Address')][Alias('NatIp')] [string] $target,
        [Parameter(Mandatory=$false, HelpMessage='The Local Port')][Alias('NatPort')] [string] $LocalPort,
        [Parameter(Mandatory=$false, HelpMessage='The Description')] [string] $Description
        )
    Begin{
        $Created = $Updated = @{
            Username = $Username
            time = [int](get-date -UFormat "%s")
        }
    }
    process{
        $PFObject = Get-PFNatRule -Server $InputObject
        # Check User input
#        try{ # Check if the ipaddress are valid
#            ($SourceAddress,$DestAddress,$NatPort) | Foreach {
#                if($_){# Only test if it is a valid variable
#                    [Ipaddress]$IPCheck = $_
#                }
#            }
#        }
#        catch{throw "{0}" -f $_.Exception.Message}
        # Actual adding
        $interface = $($InputObject | Get-PFInterface -Description $Intface)
        $Object = New-Object -TypeName "PFNatRule" -Property $Properties
        $Properties = @{}
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $NewObject = New-Object -TypeName "PFNatRule" -Property $Properties
        $PFObject += $NewObject

        Set-PFNatRule -InputObject $InputObject -NewObject $PFObject
    }
}


Function Delete-PFNatRule{
    <#
    .SYNOPSIS
    The Delete-PFNatRule function Delete's a NatRule / PortfwdRule to the PFSense. 

    .DESCRIPTION
    The Delete-PFNatRule function Delete's a NatRule / PortfwdRule to the PFSense. 

    .PARAMETER Interface
    The Interface the port forward is going to be created on

    .PARAMETER Protocol
    Network protocol like: TCP, UDP, ICMP

    .PARAMETER SourceAddress
    Source Address

    .PARAMETER SourcePort
    Source Port

    .PARAMETER DestAddress
    Destination Address

    .PARAMETER DestPort
    Destination Port

    .PARAMETER NatIp
    The Local Ip Address

    .PARAMETER NatPort
    The Local Port

    .PARAMETER Description
    The Description

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Portfwd -action Add -Interface Client -Protocol UDP -SourceAddress 'Manage Network' -SourcePort any -DestAddress 192.168.11.0/23 -DestPort 8443 -NatIp 192.168.1.4 -NatPort 443 -Description 'this is a test' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Interface the port forward is going to be created on')][Alias('Interface')] [string]$Intface,
        [Parameter(Mandatory=$false, HelpMessage='Network protocol like: TCP, UDP, ICMP')] [string] $Protocol,
        [Parameter(Mandatory=$false, HelpMessage='Source Address')] [string] $SourceAddress,
        [Parameter(Mandatory=$false, HelpMessage='Source Port')] [string] $SourcePort,
        [Parameter(Mandatory=$false, HelpMessage='Destination Address')][Alias('DestAddress')] [string] $DestinationAddress,
        [Parameter(Mandatory=$false, HelpMessage='Destination Port')][Alias('DestPort')] [string] $DestinationPort,
        [Parameter(Mandatory=$false, HelpMessage='The Local Ip Address')][Alias('NatIp')] [string] $target,
        [Parameter(Mandatory=$false, HelpMessage='The Local Port')][Alias('NatPort')] [string] $LocalPort,
        [Parameter(Mandatory=$false, HelpMessage='The Description')] [string] $Description
        )
    Begin{
    }
    process{
    $Interface = $($InputObject | Get-PFInterface -Description $Intface)
    $Properties = @{}
    $PFOriginal = get-PFNATRule -Server $InputObject
    $Object = New-Object -TypeName "PFNATRule" -Property $Properties
    $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
            $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
    }
    $Delete = New-Object -TypeName "PFNATRule" -Property $Properties

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
    <#
    .SYNOPSIS
    The Write-PFNatRule function Display's all the Nat / portforwarder rule's of the pfsense

    .DESCRIPTION
    The Write-PFNatRule function Display's all the Nat / portforwarder rule's of the pfsense

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Interface -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFNATRule -Server $InputObject
        $PFObject | Format-table Interface,Protocol,SourceAddress,SourcePort,DestinationAddress,DestinationPort,target,LocalPort,Description
    }
}
Function Add-PFStaticRoute{
    <#
    .SYNOPSIS
    The Add-PFStaticRoute function Add's a Staticroute to the PFSense. 

    .DESCRIPTION
    The Add-PFStaticRoute function Add's a Staticroute to the PFSense. 

    .PARAMETER Network
    The Network where for you are adding a route

    .PARAMETER Gateway
    The gateway where thru the network can be reached

    .PARAMETER Description
    The Description of the route

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service Portfwd -action Add -Interface Client -Protocol UDP -SourceAddress 'Manage Network' -SourcePort any -DestAddress 192.168.11.0/23 -DestPort 8443 -NatIp 192.168.1.4 -NatPort 443 -Description 'this is a test' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Network where for you are adding a route')][String]$Network,
        [Parameter(Mandatory=$true, HelpMessage='The gateway where thru the network can be reached')][Alias('Gateway')][String]$GatewayString,
        [Parameter(Mandatory=$true, HelpMessage='The Description of the route')][String]$Description
    )
    begin{
        $PFObject = Get-PFStaticRoute -Server $InputObject
    }
    Process{
        # Check User Input
        if($Network -in $PFObject.Network){Throw "A route to these destination networks already exists: {0}" -f $Network}
        # Check if the gateway excisit on the pfsense 
        $Gateway = $InputObject | Get-PFGateway -Name $GatewayString
        if(-not $Gateway){Throw "Could not find gateway: {0} on the PFSense" -f $GatewayString }
        # Actual adding
        $Object = New-Object -TypeName "PFStaticRoute" -Property $Properties
        $Properties = @{}
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $NewObject = New-Object -TypeName "PFStaticRoute" -Property $Properties
        $PFObject += $NewObject
        Set-PFStaticRoute -InputObject $InputObject -NewObject $PFObject
    }
}

Function Delete-PFStaticRoute{
    <#
    .SYNOPSIS
    The Delete-PFStaticRoute function Delete's a Staticroute on the PFSense. 

    .DESCRIPTION
    The Delete-PFStaticRoute function Delete's a Staticroute on the PFSense. 

    .PARAMETER Network
    The Network you would like to delete

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service staticroute -action Delete -Network 192.168.2.0/24 -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true)][String]$Network)
    begin{
        $PFObject = Get-PFStaticRoute -Server $InputObject
    }
    process{
        if($Network -NotIn $PFObject.network){Throw "Could not find network {0}, unable to delete" -f $Network}
        $PFUploadObject = $PFObject | Where-Object {$_.network -ne $Network}
        Set-PFStaticRoute -InputObject $InputObject -NewObject $PFUploadObject
    }
}

Function Edit-PFStaticRoute{
    <#
    .SYNOPSIS
    The edit-PFStaticRoute function edit's a Staticroute on the PFSense. 

    .DESCRIPTION
    The edit-PFStaticRoute function edit's a Staticroute on the PFSense. 

    .PARAMETER Network
    The Uniq ident you would like to edit

    .PARAMETER Gateway
    The new gateway

    .PARAMETER Description
    The new description

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service staticroute -action Edit -Network 192.168.2.0/24 -Gateway Null4 -Description 'To Null Route the 192.168.51.0/24 Network' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true, HelpMessage='The Network where for you are adding a route')][String]$Network,
        [Parameter(Mandatory=$false, HelpMessage='The gateway where thru the network can be reached')][Alias('Gateway')][String]$GatewayString,
        [Parameter(Mandatory=$false, HelpMessage='The Description of the route')][String]$Description
    )
    begin{
        $PFObject = Get-PFStaticRoute -Server $InputObject
    }
    Process{
        # Check User Input
        if($Network -NotIn $PFObject.network){Throw "Could not find network {0}, unable to Edit" -f $Network}
        # Check if the gateway excisit on the pfsense 
        if($GatewayString){
            $Gateway = $InputObject | Get-PFGateway -Name $GatewayString
            if(-not $Gateway){Throw "Could not find gateway: {0} on the PFSense" -f $GatewayString }
        }
        # Actual adding
        $WorkingObject = $PFObject | Where-Object {$_.network -eq $Network}
        $WorkingObject | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
            if(get-variable $_.name -valueOnly -ErrorAction Ignore){
                $WorkingObject.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
            }
        }
        Set-PFStaticRoute -InputObject $InputObject -NewObject $PFObject
    }
}

Function Write-PFStaticRoute{
    <#
    .SYNOPSIS
    The Write-PFStaticRoute function Prints all the Staticroute of the PFSense. 

    .DESCRIPTION
    The Write-PFStaticRoute function Prints all the Staticroute of the PFSense. 

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service staticroute -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFStaticroute -Server $InputObject
        $PFObject | Format-table Network,Gateway,Description
    }
}

Function Edit-PFUnbound{
    <#
    .SYNOPSIS
    The Edit-PFStaticRoute function Edit's the unbound DNSSettings on the PFSense. 

    .DESCRIPTION
    The Edit-PFStaticRoute function Edit's the unbound DNSSettings on the PFSense. 
    
    .PARAMETER ActiveInt / ActiveInterface
    The Active interfaces

    .PARAMETER OutgoingInt / OutgoingInterface
    The Outgoint Interfaces

    .PARAMETER dnssec
    DNS Sec enable or disable

    .PARAMETER Enable
    Enable or disable the DNS Unbound Deamon

    .PARAMETER sslport
    The SSL port

    .PARAMETER CustomOptions
    Costum Options "This must be a single string"

    .PARAMETER sslcertref
    SSL cert Ref of a ssl certificate known by the PFsense

    .PARAMETER port
    The port you would like to use

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolver -action edit -ActiveInterface 'All,Client' -OutgoingInterface Client -dnssec $True -port 53 -sslport 853 -notls

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolver -action Disable -notls

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolver -action Enable -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='The Active interfaces')][Alias('ActiveInterface')][string] $ActiveInt,
        [Parameter(Mandatory=$false, HelpMessage='The Outgoint Interfaces')][Alias('OutgoingInterface')][string] $OutgoingInt,
        [Parameter(Mandatory=$false, HelpMessage='DNS Sec enable or disable')][bool] $dnssec,
        [Parameter(Mandatory=$false, HelpMessage='Enable or disable the DNS Unbound Deamon')][bool] $Enable,
        [Parameter(Mandatory=$false, HelpMessage='The SSL port')][string] $sslport,
        [Parameter(Mandatory=$false, HelpMessage='Costum Options')][string] $CustomOptions,
        [Parameter(Mandatory=$false, HelpMessage='SSL cert Ref of a ssl certificate known by the PFsense')][string] $sslcertref,
        [Parameter(Mandatory=$false, HelpMessage='The port you would like to use')][string] $port
    )
    Begin{
        $Object = (New-Object -TypeName "PFUnbound")
    }
    process{
        $PFObject = Get-PFUnbound -Server $InputObject
        # Change to the correct format
        if(($ActiveInt) -and ($ActiveInt -match ",")){
            $ActiveInt.split(",") | foreach{
                [array]$ActiveInterface += $($InputObject | Get-PFInterface -Description $_)
            }
        }
        elseif($ActiveInt){[array]$ActiveInterface = $($InputObject | Get-PFInterface -Description $ActiveInt)}
        if(($OutgoingInt) -and ($OutgoingInt -match ",")){
            $OutgoingInt.split(",") | foreach{
                [array]$OutgoingInterface += $($InputObject | Get-PFInterface -Description $_)
            }
        }
        elseif($OutgoingInt){[array]$OutgoingInterface = $($InputObject | Get-PFInterface -Description $OutgoingInt)}


        $PFObject | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
            if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
                $PFObject.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
            }
        }
        Set-PFUnbound -InputObject $PFserver -NewObject $PFObject
    }
}


Function Write-PFUnbound{
    <#
    .SYNOPSIS
    The Write-PFStaticRoute function Prints all the unbound DNSSettings of the PFSense. 

    .DESCRIPTION
    The Write-PFStaticRoute function Prints all the unbound DNSSettings of the PFSense. 

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolver -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{}
    process{
        $PFObject = Get-PFUnbound -Server $InputObject
        # If the dns default port's are used, these are not in the xml config, we set them to display the correct settings
        if(-not $PFObject.port){$PFObject.port = "53"}
        if(-not $PFObject.sslport){$PFObject.sslport = "853"}
        # Display the settings
        $PFObject | format-table enable,ActiveInterface,OutgoingInterface,dnssec,port,sslport,CustomOptions,sslcertref
    }
}

Function Write-PFUnboundHost{
    <#
    .SYNOPSIS
    The Write-PFUnboundHost function Prints all the unbound DNS HostOverride's of the PFSense. 

    .DESCRIPTION
    The Write-PFUnboundHost function Prints all the unbound DNS HostOverride's of the PFSense. 

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverHost -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFunboundHost -Server $InputObject
        $WriteObject = New-Object System.Collections.ArrayList
        foreach($PFHost in $PFObject){
            $index = 0
            $Object = New-Object -TypeName "PFUnboundHost" -Property $Properties
            $Properties = @{}
            try{
                # first we add the first alias to the $writeObject
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                    if($PFHost.$($_.name).gettype() -eq [PFUnboundHostEntry[]]){$Properties.add(($_.name),$PFHost.$($_.name)[$Index])}
                    else{$Properties.add(($_.name),$PFHost.$($_.name))}
                }
                $NewObject = New-Object -TypeName "PFUnboundHost" -Property $Properties 
                $WriteObject.add($NewObject) | out-null
                # Now we add one to the index to add all the other aliases to the writeobject
                $index++
                $Properties = @{}
                while($PFHost.Alias[$index]){
                    $Properties.Alias = $PFHost.Alias[$Index]
                    $NewObject = New-Object -TypeName "PFUnboundHost" -Property $Properties 
                    $WriteObject.add($NewObject) | out-null
                    $index++
                }
            }
            catch{$WriteObject.add($PFHost) | out-null}
        }
        $WriteObject | Format-table Hostname,Domain,Address,Description,Alias
    }
}


Function Write-PFUnboundDomain{
    <#
    .SYNOPSIS
    The Write-PFUnboundDomain function Prints all the unbound DNS Domain Override's of the PFSense. 

    .DESCRIPTION
    The Write-PFUnboundDomain function Prints all the unbound DNS Domain Override's of the PFSense.
    This page is used to specify domains for which the resolver's standard DNS lookup process will be overridden,
    and the resolver will query a different (non-standard) lookup server instead. 
    It is possible to enter 'non-standard', 'invalid' and 'local' domains such as 'test', 'mycompany.localdomain', or '1.168.192.in-addr.arpa', 
    as well as usual publicly resolvable domains such as 'org', 'info', or 'google.co.uk'. 
    The IP address entered will be treated as the IP address of an authoritative lookup server for the domain (including all of its subdomains), 
    and other lookup servers will not be queried.

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverDomain -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFunboundDomain -Server $InputObject
        $PFObject | Format-table Domain,Address,TLSQueries,TlsHostname,Description
    }
}


Function add-PFUnboundHost{
    <#
    .SYNOPSIS
    add-PFUnboundHost Function add's a host to the unbound deamon

    .DESCRIPTION
    add-PFUnboundHost Function add's a host to the unbound deamon

    .PARAMETER HostName
    HostName

    .PARAMETER Domain
    Domain

    .PARAMETER Address
    Address
    
    .PARAMETER Description
    Description

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverHost -action add -Hostname XMLRPC -Domain EU -Address 192.168.0.28 -Description This is a xmlrpc test entry -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='Hostname')] [string] $HostName,
        [Parameter(Mandatory=$True, HelpMessage='The Domain')] [string] $Domain,
        [Parameter(Mandatory=$false, HelpMessage='Address')] [string] $Address,
        [Parameter(Mandatory=$false, HelpMessage='The Description')] [string] $Description
    )
    Begin{
        $Object = (New-Object -TypeName "PFUnboundHost")
    }
    process{
        $PFObject = Get-PFunboundHost -Server $InputObject
        # Test UserInput
        foreach($hostoverride in $PFObject){
            if(($hostoverride.Hostname -eq $HostName) -and ($hostoverride.Domain -eq $domain)){
                Throw "This host/domain override combination already exists with an IP address."
            }
        }
        try{[ipaddress]$testIpAddress = $Address}
        catch{ throw "{0}" -f $_ }
        <# Find a way to check the characters #>
        if(($HostName.StartsWith("-")) -or ($HostName.EndsWith("-")) <# Find a way to check the characters #>){throw "The hostname can only contain the characters A-Z, 0-9, '_' and '-'. It may not start or end with '-'."}

        # Create a new Object
        $alias = @{} # if we do not set alias to a hashtable, it will crash the creation of NewObject, it does expect $alias to be a hashtable
        $Properties = @{}
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $NewObject = New-Object -TypeName "PFUnboundHost" -Property $Properties
        $PFObject += $NewObject
        Set-PFUnboundHost -InputObject $PFserver -NewObject $PFObject
    }
}


Function add-PFUnboundHostAlias{
    <#
    .SYNOPSIS
    add-PFUnboundHostAlias Function add's a alias to a host of the unbound deamon

    .DESCRIPTION
    add-PFUnboundHostAlias Function add's a alias to a host of the unbound deamon

    .PARAMETER HostName
    HostName

    .PARAMETER Domain
    Domain

    .PARAMETER HostNameAlias / _AliasesHost
    Hostname of the Alias

    .PARAMETER DomainAlias / _AliasesDomain
    The Domain of the Alias

    .PARAMETER DescriptionAlias / _AliasesDescription
    The Description of the Alias

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverHost -action AliasAdd -Hostname one_host_override -Domain nl -HostNameAlias xmlrpcAlias -DomainAlias DE -DescriptionAlias 'To add a alias true xmlrpc' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='Hostname')] [string] $HostName,
        [Parameter(Mandatory=$True, HelpMessage='Hostname of the Alias')][Alias('HostNameAlias')] [string]$_AliasesHost,
        [Parameter(Mandatory=$True, HelpMessage='The Domain')] [string] $Domain,
        [Parameter(Mandatory=$True, HelpMessage='The Domain of the Alias')][Alias('DomainAlias')] [string]$_AliasesDomain,
        [Parameter(Mandatory=$false, HelpMessage='The Description of the Alias')][Alias('DescriptionAlias')] [string]$_AliasesDescription
    )
    Begin{
        $Object = (New-Object -TypeName "PFUnboundHostEntry")
    }
    process{
        $PFObject = Get-PFunboundHost -Server $InputObject
        # Test UserInput
        $ThrowError = $true
        foreach($hostoverride in $PFObject){
            if(($hostoverride.Hostname -eq $HostName) -and ($hostoverride.Domain -eq $domain)){
                $ThrowError = $false
            }
        }
        if($ThrowError){Throw "This host/domain override combination could not be found. please check or add instead."}
        # Create a new PFUnboundHostEntry Object
        $Properties = @{}
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $alias = New-Object -TypeName "PFUnboundHostEntry" -Property $Properties

        foreach($hostoverride in $PFObject){
            if(($hostoverride.Hostname -eq $HostName) -and ($hostoverride.Domain -eq $domain)){
                $hostoverride.alias += $alias
            }
        }
        Set-PFUnboundHost -InputObject $PFserver -NewObject $PFObject
    }
}

Function add-PFUnboundDomain{
    <#
    .SYNOPSIS
    add-PFUnboundDomain Function add's a Domain override to the unbound deamon

    .DESCRIPTION
    add-PFUnboundDomain Function add's a Domain override to the unbound deamon.
    This page is used to specify domains for which the resolver's standard DNS lookup process will be overridden,
    and the resolver will query a different (non-standard) lookup server instead. 
    It is possible to enter 'non-standard', 'invalid' and 'local' domains such as 'test', 'mycompany.localdomain', or '1.168.192.in-addr.arpa', 
    as well as usual publicly resolvable domains such as 'org', 'info', or 'google.co.uk'. 
    The IP address entered will be treated as the IP address of an authoritative lookup server for the domain (including all of its subdomains), 
    and other lookup servers will not be queried.
    
    .PARAMETER Domain
    Domain whose lookups will be directed to a user-specified DNS lookup server.

    .PARAMETER Address
    IPv4 or IPv6 address of the authoritative DNS server for this domain. e.g.: 192.168.100.100
    To use a non-default port for communication, append an '@' with the port number.
    
    .PARAMETER TLSQueries
    When set, queries to all DNS servers for this domain will be sent using SSL/TLS on the default port of 853.

    .PARAMETER TlsHostname
    An optional TLS hostname used to verify the server certificate when performing TLS Queries.

    .PARAMETER Description
    A description may be entered here for administrative reference (not parsed)

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverDomain -action add -Domain EU -Address 192.168.0.2888 -TLSQueries $True -TlsHostname TestServer -Description 'This is a xmlrpc test entry' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='Domain whose lookups will be directed to a user-specified DNS lookup server.')] [string] $Domain,
        [Parameter(Mandatory=$True, HelpMessage='IPv4 or IPv6 address of the authoritative DNS server for this domain. e.g.: 192.168.100.100 To use a non-default port for communication, append an "@" with the port number.')] [string] $Address,
        [Parameter(Mandatory=$false, HelpMessage='When set, queries to all DNS servers for this domain will be sent using SSL/TLS on the default port of 853.')] [Bool] $TLSQueries,
        [Parameter(Mandatory=$false, HelpMessage='An optional TLS hostname used to verify the server certificate when performing TLS Queries.')] [string] $TlsHostname,
        [Parameter(Mandatory=$false, HelpMessage='A description may be entered here for administrative reference (not parsed).')] [string] $Description
    )
    Begin{
        $Object = (New-Object -TypeName "PFUnboundDomain")
    }
    process{
        $PFObject = Get-PFunboundDomain -Server $InputObject
        # Test UserInput
        if($Address -match "@"){
            [ipaddress]$testIpAddress = $Address.split("@")[0]
            [int64]$port = $Address.split("@")[1]
            if($port -gt 65535) {throw "A valid IP address and port must be specified, for example 192.168.100.10@5353."}
        }
        else{[ipaddress]$testIpAddress = $Address.split("@")[0]}

        <# Find a way to check the characters #>
        if(($Domain.StartsWith("-")) -or ($Domain.EndsWith("-")) <# Find a way to check the characters #>){throw "The hostname can only contain the characters A-Z, 0-9, '_' and '-'. It may not start or end with '-'."}

        # Create a new Object
        $Properties = @{}
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $NewObject = New-Object -TypeName "PFUnboundDomain" -Property $Properties
        $PFObject += $NewObject
        Set-PFUnboundDomain -InputObject $PFserver -NewObject $PFObject
    }
}

Function Delete-PFUnboundDomain{
    <#
    .SYNOPSIS
    The Delete-PFUnboundDomain function Delete's a dns override zone on the unbound DNS Deamon of the PFSense.

    .DESCRIPTION
    The Delete-PFUnboundDomain function Delete's a dns override zone on the unbound DNS Deamon of the PFSense.

    .PARAMETER Domain
    Domain

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverDomain -action Delete -Domain domainoverride -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='The Domain')] [string] $Domain
    )
    Begin{}
    process{
        $PFObject = Get-PFunboundDomain -Server $InputObject
        # Test UserInput
        if($Domain -NotIn $PFObject.domain){Throw "This DomainOverride: {0}  could not be found." -f $Domain}
        # Create new PFObject 
        $PFObject = $PFObject | Where-Object {($_.Domain -ne $Domain)}
        Set-PFUnboundDomain -InputObject $PFserver -NewObject $PFObject
    }
}

Function Delete-PFUnboundHost{
    <#
    .SYNOPSIS
    The Edit-PFUnboundHost function Edit's a unbound host on the PFSense.

    .DESCRIPTION
    The Edit-PFUnboundHost function Edit's a unbound host on the PFSense.

    .PARAMETER HostName
    HostName

    .PARAMETER Domain
    Domain

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverHost -action Delete -Hostname one_host_override  -Domain nl -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='Hostname')] [string] $HostName,
        [Parameter(Mandatory=$True, HelpMessage='The Domain')] [string] $Domain
    )
    Begin{
        $Object = (New-Object -TypeName "PFUnboundHost")
    }
    process{
        $PFObject = Get-PFunboundHost -Server $InputObject
        # Test UserInput
        $ThrowError = $true
        foreach($hostoverride in $PFObject){
            if(($hostoverride.Hostname -eq $HostName) -and ($hostoverride.Domain -eq $domain)){
                $ThrowError = $false
            }
        }
        if($ThrowError){Throw "This host/domain override combination could not be found. please check or add instead."}
        # Create new PFObject 
        $PFObject = $PFObject | Where-Object {($_.Hostname -ne $HostName) -or ($_.Domain -ne $Domain)}
        Set-PFUnboundHost -InputObject $PFserver -NewObject $PFObject
    }
}

Function Delete-PFUnboundHostAlias{
    <#
    .SYNOPSIS
    add-PFUnboundHostAlias Function add's a alias to a host of the unbound deamon

    .DESCRIPTION
    add-PFUnboundHostAlias Function add's a alias to a host of the unbound deamon

    .PARAMETER HostName
    HostName

    .PARAMETER Domain
    Domain

    .PARAMETER HostNameAlias / _AliasesHost
    Hostname of the Alias

    .PARAMETER DomainAlias / _AliasesDomain
    The Domain of the Alias

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverHost -action AliasDelete -Hostname host_override_with_alias -Domain com -HostNameAlias aliashost_1 -DomainAlias com -DescriptionAlias 'To add a alias true xmlrpc' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='Hostname')] [string] $HostName,
        [Parameter(Mandatory=$True, HelpMessage='Hostname of the Alias')][Alias('HostNameAlias')] [string]$_AliasesHost,
        [Parameter(Mandatory=$True, HelpMessage='The Domain')] [string] $Domain,
        [Parameter(Mandatory=$True, HelpMessage='The Domain of the Alias')][Alias('DomainAlias')] [string]$_AliasesDomain
    )
    Begin{
        $Object = (New-Object -TypeName "PFUnboundHostEntry")
    }
    process{
        $PFObject = Get-PFunboundHost -Server $InputObject
        # Test UserInput
        $ThrowErrorHost = $true
        $ThrowErrorAlias = $true
        foreach($hostoverride in $PFObject){
            if(($hostoverride.Hostname -eq $HostName) -and ($hostoverride.Domain -eq $domain)){
                $ThrowErrorHost = $false
                foreach($Alias in $hostoverride.alias){
                    if(($Alias._AliasesHost -eq $_AliasesHost) -and ($Alias._AliasesDomain -eq $_AliasesDomain)){
                        $ThrowErrorAlias = $false
                    }
                }
            }
        }
        if($ThrowErrorHost){Throw "This host/domain override combination could not be found. please check or add instead."}
        if($ThrowErrorAlias){Throw "The Alias could not be found."}
        # Delete the alias entry
        foreach($hostoverride in $PFObject){
            if(($hostoverride.Hostname -eq $HostName) -and ($hostoverride.Domain -eq $domain)){
                $hostoverride.alias = $hostoverride.alias | Where-Object {($_._AliasesHost -ne $_AliasesHost) -or ($_._AliasesDomain -ne $_AliasesDomain)}
            }
        }
        Set-PFUnboundHost -InputObject $PFserver -NewObject $PFObject
    }
}

Function Edit-PFUnboundDomain{
    <#
    .SYNOPSIS
    add-PFUnboundDomain Function add's a Domain override to the unbound deamon

    .DESCRIPTION
    add-PFUnboundDomain Function add's a Domain override to the unbound deamon.
    This page is used to specify domains for which the resolver's standard DNS lookup process will be overridden,
    and the resolver will query a different (non-standard) lookup server instead. 
    It is possible to enter 'non-standard', 'invalid' and 'local' domains such as 'test', 'mycompany.localdomain', or '1.168.192.in-addr.arpa', 
    as well as usual publicly resolvable domains such as 'org', 'info', or 'google.co.uk'. 
    The IP address entered will be treated as the IP address of an authoritative lookup server for the domain (including all of its subdomains), 
    and other lookup servers will not be queried.
    
    .PARAMETER Domain
    Domain whose lookups will be directed to a user-specified DNS lookup server.

    .PARAMETER Address
    IPv4 or IPv6 address of the authoritative DNS server for this domain. e.g.: 192.168.100.100
    To use a non-default port for communication, append an '@' with the port number.
    
    .PARAMETER TLSQueries
    When set, queries to all DNS servers for this domain will be sent using SSL/TLS on the default port of 853.

    .PARAMETER TlsHostname
    An optional TLS hostname used to verify the server certificate when performing TLS Queries.

    .PARAMETER Description
    A description may be entered here for administrative reference (not parsed)

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverDomain -action add -Domain EU -Address 192.168.0.2888 -TLSQueries $True -TlsHostname TestServer -Description 'This is a xmlrpc test entry' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='Domain whose lookups will be directed to a user-specified DNS lookup server.')] [string] $Domain,
        [Parameter(Mandatory=$false, HelpMessage='IPv4 or IPv6 address of the authoritative DNS server for this domain. e.g.: 192.168.100.100 To use a non-default port for communication, append an "@" with the port number.')] [string] $Address,
        [Parameter(Mandatory=$false, HelpMessage='When set, queries to all DNS servers for this domain will be sent using SSL/TLS on the default port of 853.')] [Bool] $TLSQueries,
        [Parameter(Mandatory=$false, HelpMessage='An optional TLS hostname used to verify the server certificate when performing TLS Queries.')] [string] $TlsHostname,
        [Parameter(Mandatory=$false, HelpMessage='A description may be entered here for administrative reference (not parsed).')] [string] $Description
    )
    Begin{
        $Object = (New-Object -TypeName "PFUnboundDomain")
    }
    process{
        $PFObject = Get-PFunboundDomain -Server $InputObject
        # Test UserInput
            if($address){
            if($Address -match "@"){
                [ipaddress]$testIpAddress = $Address.split("@")[0]
                [int64]$port = $Address.split("@")[1]
                if($port -gt 65535) {throw "A valid IP address and port must be specified, for example 192.168.100.10@5353."}
            }
            else{[ipaddress]$testIpAddress = $Address.split("@")[0]}
        }

        <# Find a way to check the characters #>
        if(($Domain.StartsWith("-")) -or ($Domain.EndsWith("-")) <# Find a way to check the characters #>){throw "The hostname can only contain the characters A-Z, 0-9, '_' and '-'. It may not start or end with '-'."}

        #check if domain excists, other throw error and exit
        if($domain -NotIn $PFObject.domain){
            throw {"Could not find domain {0}, please check input or add instead" -f $domain} 
        }

        # Edit the Object with the same Domain
        $WorkingObject = $PFObject | Where-Object {$_.domain -eq $domain}
        $WorkingObject | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
            # Only set if variable is set
            if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
                $WorkingObject.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
            }
        }
        
        Set-PFUnboundDomain -InputObject $PFserver -NewObject $PFObject
    }
}
Function Edit-PFUnboundHost{
    <#
    .SYNOPSIS
    The Edit-PFUnboundHost function Edit's a unbound host on the PFSense.

    .DESCRIPTION
    The Edit-PFUnboundHost function Edit's a unbound host on the PFSense.

    .PARAMETER HostName
    HostName

    .PARAMETER Domain
    Domain

    .PARAMETER Address
    Address
    
    .PARAMETER Description
    Description

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service dnsResolverHost -action Edit -Hostname host_override_with_alias -Domain com -Address 1.2.3.4 -Description This is a xmlrpc test entry -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$True, HelpMessage='Hostname')] [string] $HostName,
        [Parameter(Mandatory=$True, HelpMessage='The Domain')] [string] $Domain,
        [Parameter(Mandatory=$false, HelpMessage='Address')] [string] $Address,
        [Parameter(Mandatory=$false, HelpMessage='The Description')] [string] $Description
    )
    Begin{
        $Object = (New-Object -TypeName "PFUnboundHost")
    }
    process{
        $PFObject = Get-PFunboundHost -Server $InputObject
        # Test UserInput
        $ThrowError = $true
        foreach($hostoverride in $PFObject){
            if(($hostoverride.Hostname -eq $HostName) -and ($hostoverride.Domain -eq $domain)){
                $ThrowError = $false
            }
        }
        if($ThrowError){Throw "This host/domain override combination could not be found. please check or add instead."}


        try{[ipaddress]$testIpAddress = $Address}
        catch{ throw "{0}" -f $_ }
        <# Find a way to check the characters #>
        # Create a new Object
        foreach($hostoverride in $PFObject){
            if(($hostoverride.Hostname -eq $HostName) -and ($hostoverride.Domain -eq $domain)){
                $hostoverride | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                    # Only set if variable is set
                    if(-not [string]::IsNullOrWhiteSpace($(get-variable $_.name -valueOnly -ErrorAction Ignore))){ # Only set object if variable is set. don't override with empty value's
                    $hostoverride.$($_.name) = $(get-variable $_.name -valueOnly -ErrorAction Ignore)
                    }
                }
            }
        }
        Set-PFUnboundHost -InputObject $PFserver -NewObject $PFObject
    }
}

Function Add-PFVlan{
    <#
    .SYNOPSIS
    The Add-PFVlan function Add's a vlan on the PFSense. 

    .DESCRIPTION
    The Add-PFVlan function Add's a vlan on the PFSense.  

    .parameter interface
    VLAN capable interface

    .parameter Tag
    802.1Q VLAN tag (between 1 and 4094).

    .parameter Priority
    802.1Q VLAN Priority (between 0 and 7).

    .parameter Description
    A group description may be entered here for administrative reference (not parsed).

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service vlan -action Add -interface em2 -Tag 151 -Priority 3 -Description 'This is a XML RPC Test' -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='VLAN capable interface')][string]$interface,
        [Parameter(Mandatory=$false, HelpMessage='802.1Q VLAN tag (between 1 and 4094).')][int]$Tag,
        [Parameter(Mandatory=$false, HelpMessage='802.1Q VLAN Priority (between 0 and 7).')][int]$Priority,
        [Parameter(Mandatory=$false, HelpMessage='A group description may be entered here for administrative reference (not parsed).')][string]$Description
        )
    Begin{
    }
    process{
        # Get excisiting vlan's and Interfaces
        $VlanObject = get-PFVlan -Server $InputObject
        $InterfaceObject = get-pfinterface -Server $InputObject
        # Check UserInput
        if(($tag -gt 4094) -or ($tag -lt 1)){throw "The 802.1Q VLAN tag must be between 1 and 4094"}
        if(($Priority -gt 7) -or ($Priority -lt 0)){throw "The 802.1Q VLAN Priority must be between 0 and 7"}
        if($interface -NotIn $InterfaceObject.Interface){Throw "Could not find Interface {0}. please use the Physical interface name like em0" -f $Interface}
        foreach($Vlan in $VlanObject){
            if(($interface -eq $vlan.interface) -and ($tag -eq $vlan.Tag)){Throw "Interface {0} already has a vlan with tag {1}" -f $interface,$tag}
        }
        # create vlanif variable
        $vlanif = "{0}.{1}" -f $interface,$tag
        # Create a new Object
        $Object = New-Object -TypeName "PFVlan" 
        $Properties = @{}
        $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object{
                $Properties.add($_.name,$(get-variable $_.name -valueOnly -ErrorAction Ignore)) # The -erroraction Ignore is used because not all properties are variable's 
        }
        $NewObject = New-Object -TypeName "PFVlan" -Property $Properties
        $VlanObject += $NewObject
        set-pfvlan -InputObject $PFserver -NewObject $VlanObject
    }
}

Function Delete-PFVlan{
    <#
    .SYNOPSIS
    The Delete-PFVlan function deletes a vlan on the PFSense. 

    .DESCRIPTION
    The Delete-PFVlan function deletes a vlan on the PFSense. 

    .parameter interface
    VLAN capable interface

    .parameter Tag
    802.1Q VLAN tag (between 1 and 4094).

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service vlan -action Delete -interface em2 -Tag 150 -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='VLAN capable interface')][string]$interface,
        [Parameter(Mandatory=$false, HelpMessage='802.1Q VLAN tag (between 1 and 4094).')][int]$Tag
        )
    Begin{
    }
    process{
        # Get excisiting vlan's and Interfaces
        $VlanObject = get-PFVlan -Server $InputObject
        # Check UserInput
        if(($tag -gt 4094) -or ($tag -lt 1)){throw "The 802.1Q VLAN tag must be between 1 and 4094"}
        $throwError = $true
        foreach($Vlan in $VlanObject){
            if(($interface -eq $vlan.interface) -and ($tag -eq $vlan.Tag)){$throwError = $false}
        }
        if($throwError){Throw "could not find a vlan with tag {0} on Interface {1} " -f $tag,$interface}
        # Delete the VlanObject from the array
        $VlanObject = $VlanObject | Where-Object {($_.interface -ne $interface) -or ($_.tag -ne $tag)}
        set-pfvlan -InputObject $PFserver -NewObject $VlanObject
    }
}

Function Write-PFVlan{
    <#
    .SYNOPSIS
    The Write-PFVlan function Prints all the vlan's of the PFSense. 

    .DESCRIPTION
    The Write-PFVlan function Prints all the vlan's of the PFSense. 

    .EXAMPLE
    ./pfsense.ps1 -Server 192.168.0.1 -Username admin -InsecurePassword pfsense -SkipCertificateCheck -Service vlan -action print -notls

    .LINK
    https://github.com/RaulGrayskull/PFSense_Powershell
   
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-PFVlan -Server $InputObject
        $PFObject | Format-table Interface,Tag,Priority,Description
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

    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Flow.$Service.$Action)) -ArgumentList $PFServer,$path,$file,$Network,$Gateway,$Description,$Interface,$From,$To,$netmask,$Domain,$DNSServer,$NTPServer,$Alias,$Type,$Address,$Detail,$HostName,$ClientID,$MacAddr,$Protocol,$SourceAddress,$DestAddress,$DestPort,$NatIp,$NatPort,$Weight,$Monitor,$Name,$IpProtocol,$IsLogged,$IsQuick,$IsFloating,$tracker,$OldLineNumber,$NewLineNumber,$IPv4Address,$IPv4Subnet,$IPv4Gateway,$IPv6Address,$IPv6Subnet,$IPv6Gateway,$blockpriv,$BlockBogons,$ActiveInt,$OutgoingInterface,$dnssec,$sslport,$CustomOptions,$sslcertref,$port,$HostNameAlias,$DomainAlias,$DescriptionAlias,$TLSQueries,$TlsHostname,$Tag,$Priority,$DHCPReg,$DHCPRegstatic,$Dhcpfirst,$DomainNeeded,$StrictOrder,$NoPrivateReverse,$Strictbind
 
} catch { 
    Write-Error $_.Exception.Message
    exit 1
}

