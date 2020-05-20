Param
    (
    [Parameter(Mandatory=$true, HelpMessage='The pfSense network address (DNS or IP)')] [string] $Server,
    [Parameter(Mandatory=$false, HelpMessage='The Username')] [string] $Username,
    [Parameter(Mandatory=$false, HelpMessage='The Password')] [string] $InsecurePassword,
    [Parameter(Mandatory=$false, HelpMessage='The service you would like to talke to')] [string] $Service,
    [Parameter(Mandatory=$false, HelpMessage='The action you would like to do on the service')] [string] $Action,
    [Parameter(Mandatory=$false, HelpMessage='The Network value')] [string] $Network,
    [Parameter(Mandatory=$false, HelpMessage='The Gateway name')] [string] $Gateway,
    [Parameter(Mandatory=$false, HelpMessage='The Description')] [string] $Description,
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

Function Write-PFDHCPd{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
    }
    process{
        $PFObject = get-pfdhcpd -Server $InputObject
        $exclude = ("ddnsdomainkeyalgorithm","ddnsdomainprimary","domainsearchlist","filename64","ddnsdomainkey","ddnsdomainkeyname","nextserver","tftp","maxleasetime","ddnsdomain","ldap","failover_peerip","filename","enable","pool","filename32","mac_allow","numberoptions","dhcpleaseinlocaltime","defaultleasetime","ddnsclientupdates","mac_deny","staticmap","rootpath")
        $PFObject | Select-Object -ExcludeProperty $exclude | Format-table *
    }
}
Function Write-PFDHCPstaticmap{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject)
    Begin{
        $Collection = New-Object System.Collections.ArrayList
        $Object = (New-Object -TypeName "PFdhcpStaticMapWrite")
    }
    process{
        $PFObject = get-PFDHCPStaticMap -Server $InputObject
        foreach($Staticmap in $PFObject){
            $indexStaticMap = 0 
            $Properties = @{}
            # Here we loop true all the entry's of the array's of the same interface, I use the MACaddr because this is a mandatory entry.
            while($Staticmap.MACaddr[$indexStaticMap]){
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                    $Property = $_.Name
                    if($Property -eq "interface"){$PropertyValue = $Staticmap.interface}
                    else{
                        try {$PropertyValue = $Staticmap.$Property[$indexStaticMap]}
                        catch{$PropertyValue = $Staticmap.$Property}
                    }
                    $Properties.$Property = $PropertyValue
                }
                $Object = New-Object -TypeName "PFdhcpStaticMapWrite" -Property $Properties
                $Collection.Add($Object) | Out-Null
                $indexStaticMap++
            } 

        }
        $Collection | format-table
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
    Process{
        $PFObject = Get-PFStaticRoute -Server $PFserver
        $Properties = @{
            Network = $Network
            Gateway = $($InputObject | Get-PFGateway -Name $Gateway)
            Description = $Description
        }
        $new = New-Object -TypeName "PFStaticRoute" -Property $Properties
        $PFObject = $PFObject + $new
        ConvertFrom-PFObject -InputObject $PFserver -PFObject $PFObject
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

$PFServer = New-Object PFServer -Property @{
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

    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Flow.$Service.$Action)) -ArgumentList $PFServer,$Network,$Gateway,$Description 
 
} catch { 
    Write-Error $_.Exception 
    exit 1
}

