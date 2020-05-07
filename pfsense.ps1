Param
    (
    [Parameter(Mandatory=$true, HelpMessage='The pfSense network address (DNS or IP)')] [string] $Server,
    [Parameter(Mandatory=$false, HelpMessage='The Username')] [string] $Username,
    [Parameter(Mandatory=$false, HelpMessage='The Password')] [string] $InsecurePassword,
    [Parameter(Mandatory=$false, HelpMessage='The service you would like to talke to')] [string] $Service,
    [Parameter(Mandatory=$false, HelpMessage='The action you would like to do on the service')] [string] $Action,
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


Function Write-PFObject{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$true)]$PFObjectType
        )
    begin{
        $Collection = New-Object System.Collections.ArrayList
    }
    process {
        if($PFObjectType -eq "PFdhcpStaticMap"){
            $Object = (New-Object -TypeName "PFdhcpStaticMapWrite")
            $PFObject = &"get-$PFObjectType" -Server $InputObject
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
        elseif($PFObjectType -eq "PFUnbound"){
            $PFObject = &"get-$PFObjectType" -Server $InputObject
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
        elseif(($PFObjectType -eq "PFFirewallRule") -or ($PFObjectType -eq "PFNATRule")){
            $PFObject = &"get-$PFObjectType" -Server $InputObject
            $PFObject | Select-Object -ExcludeProperty Source, Destination | Format-table *
        }
        
        else{
            $PFObject = &"get-$PFObjectType" -Server $InputObject
            $PFObject | format-table *
        }
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
#       obviously creating a Write-PFFirewallRule function would be an even better idea :)
#       DO NOT change it in the ConvertTo-PFObject function, since that will really complicate the reverse operation (changing and uploading the rule)
$PFServer | Get-PFFirewallRule | Select-Object -ExcludeProperty Source, Destination | Format-table *

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



<# execute requested flow #> 
try{
    if(-not $Flow.ContainsKey($Service)){  Write-Host "Unknown service '$Service'" -ForegroundColor red; exit 2 }
    if(-not $Flow.$Service.ContainsKey($Action)){ Write-Host "Unknown action '$Action' for service '$Service'" -ForegroundColor red; exit 3 }

    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Flow.$Service.$Action)) -ArgumentList $PFServer


} catch {
    Write-Error $_.Exception
    exit 1
} 