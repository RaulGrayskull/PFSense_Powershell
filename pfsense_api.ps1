<#

.SYNOPSIS
This powershell script uses the xml-rpc feature of the pfsense to modify it.

.DESCRIPTION
This powershell script uses the xml-rpc feature of the pfsense to connect. It needs a the server addres, username and password to connect. 
Afther the connection has been made it uses the service and action variable's to modify the pfsense. 
NoTLS switch make's the script use a not secure connection
SkipCertificateCheck switch uses a secure connection, but does not check if the certificate is trusted 
At this moment the following services are suported: 
    -interface       print, 
    -Alias           print, 
    -Gateway         print,
    -staticroute     print,
    -firewall        print,
    -portfwd         print,
    -dnsResolver     print,

.PARAMETER Server
the ip/host address of the pfsense XML-RPC listener

.PARAMETER Username
the username of the account u want to use to connect to the pfsense

.PARAMETER InsecurePassword
The password of the account you want to use to connect to the pfSense. 
Be careful when using this as a script argument, since it might end up in terminal logs, SIEM's etc.

.PARAMETER Service
The service of the pfsense you want to use

.PARAMETER Action
The action you want to performe on the Service

.PARAMETER NoTLS
This switch tells the script to use an insecure connection

.PARAMETER SkipCertificateCheck
This switch tells the script to accept self-signed TLS certificates as valid TLS certificate

.EXAMPLE
Print a Service, in this case the Interface's:
./pfsense_api.ps1 -Server 192.168.0.1 admin pfsense -service Interface -action print -notls -SkipCertificateCheck

.EXAMPLE
./pfsense_api.ps1 -Server 192.168.0.1 admin pfsense -service alias -action print -notls -SkipCertificateCheck

.NOTES
Styling and best practises used from Posh: https://poshcode.gitbooks.io/powershell-practice-and-style/content/
This is a work in progress though and we're not so versed in it yet that we remember every detail.
And as usual, some personal preferences apply.

.LINK
https://github.com/RaulGrayskull/PFSense_Powershell

#>
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

# dotsource the classes
. .\classes.ps1
function ConvertToPFObject{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]$InputObject,
        [Parameter(Mandatory=$false)]$PFObjectType
    )
    begin{
        $Object = (New-Object -TypeName $PFObjectType)
        $PropertyMapping = $Object::PropertyMapping
        $Collection = New-Object System.Collections.ArrayList

        $Properties = @{}
    } 
    process { 
        $ObjectToParse = $InputObject.PFconfig
        foreach($XMLPFObj in ($Object::section).Split("/")){
            $ObjectToParse = $ObjectToParse.$XMLPFObj
        } 
        $PropertyValue = $null
        $index = 0 
        # This IF statement is to see if the $ObjectToParse is a array of object (this happens with the interface), if it is a array, we need to loop to each item to get it's value's
        if ($ObjectToParse[$Index]){
            write-host "IF"
            while($ObjectToParse[$index]){
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                    $Property = $_.Name
                    $XMLProperty = ($PropertyMapping.$Property) ? $PropertyMapping.$Property : $Property.ToLower()
                    $PropertyValue = $ObjectToParse[$index]
                    foreach($XMLProp in $XMLProperty.Split("/")){                    
                        $PropertyValue = $PropertyValue.$XMLProp
                    }

                    
                    If($PropertyValue -and ($PropertyValue.GetType() -eq [System.Xml.XmlElement])){
                        $PropertyValue = $PropertyValue.InnerText
                    }
                    # The else if is for when a propertyvalue is a array of strings
                    elseif($PropertyValue -and ($PropertyValue.GetType() -eq [System.Object[]])){
                        $PropertyArray = New-Object System.Collections.ArrayList
                        foreach($value in $PropertyValue){
                            $PropertyArray.add($value.Innertext) | out-null
                        }
                        $PropertyValue = $PropertyArray
                    }

                    # if($PropertyValue.string){$PropertyValue = $PropertyValue.string}
                    
                    $PropertyDefinition = ($Object | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $Property }).Definition
                    $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                    $PropertyIsCollection = $PropertyDefinition.Contains("[]")
 
                    # TODO: make the typed conversion work with non-collections too :)
                    if($PropertyIsCollection -and $PropertyValue){
                        if($Property -eq "Detail"){$PropertyValue = $PropertyValue.Split("||")}
                        elseif($Property -eq "Address"){$PropertyValue = $PropertyValue.Split(" ")}
                        else{$PropertyValue = $PropertyValue.Split(",")}
                    
                        $PropertyTypedValue = New-Object System.Collections.ArrayList
                        ForEach($Item in $PropertyValue){
                            switch($PropertyType){
                                "PFInterface" {
                                    $PropertyTypedValue.Add(
                                        ($PFconfig.Interfaces | Where-Object { $_.Name -eq $Item })
                                    ) | Out-Null
                                }
                            }
                        }
                    }
                    $Properties.$Property = $PropertyValue
                }
                $Object = New-Object -TypeName $PFObjectType -Property $Properties
                $Collection.Add($Object) | Out-Null
                $index++
            }
        }
        # If $ObjectToParse isn't a array we use a slightily different way to get it's value's
        else{
            write-host "Else"
#            foreach($key in $PFconfig.($Object::section).keys){
            foreach($key in $ObjectToParse.keys){
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                    $Property = $_.Name
                    $XMLProperty = ($PropertyMapping.$Property) ? $PropertyMapping.$Property : $Property.ToLower()
                    $PropertyValue = $null
                    if($XMLProperty -eq $key){
                        $PropertyValue = $ObjectToParse
                    }
                    else{
                        $PropertyValue = $ObjectToParse.$key
                    }
                    foreach($XMLProp in $XMLProperty.Split("/")){
                        if($XMLProp -eq 'name'){
                            $PropertyValue = $key
                        }
                        else{
                            $PropertyValue = $PropertyValue.$XMLProp
                        }
                    }
                    
                    If($PropertyValue -and ($PropertyValue.GetType() -eq [System.Xml.XmlElement])){
                        $PropertyValue = $PropertyValue.InnerText
                    }
                    elseif($PropertyValue -and ($PropertyValue.GetType() -eq [System.Object[]])){
                        $PropertyArray = New-Object System.Collections.ArrayList
                        foreach($value in $PropertyValue){
                            $PropertyArray.add($value.Innertext) | out-null
                        }
                        $PropertyValue = $PropertyArray 
                    }
                    
                    $PropertyDefinition = ($Object | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $Property }).Definition
                    $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                    $PropertyIsCollection = $PropertyDefinition.Contains("[]")
                    
                    # TODO: make the typed conversion work with non-collections too :)
                    if($PropertyIsCollection -and $PropertyValue){
                        if($Property -eq "Detail"){$PropertyValue = $PropertyValue.Split("||")}
                        elseif($Property -eq "Address"){$PropertyValue = $PropertyValue.Split(" ")}
                        else{$PropertyValue = $PropertyValue.Split(",")}
                    
                        $PropertyTypedValue = New-Object System.Collections.ArrayList
                        ForEach($Item in $PropertyValue){
                            switch($PropertyType){
                                "PFInterface" {
                                    $PropertyTypedValue.Add(
                                        ($PFconfig.Interfaces.keys | Where-Object { $_ -eq $Item }) 
                                    ) | Out-Null
                                } 
                            }
                        }
                    }
                    
                    If($PropertyValue -and ($PropertyValue.GetType() -eq [System.Xml.XmlElement])){
                        $PropertyValue = $PropertyValue.InnerText
                    }
                    $Properties.$Property = $PropertyValue
                    
                }
            $Object = New-Object -TypeName $PFObjectType -Property $Properties
            $Collection.Add($Object) | Out-Null
            }
        }
        $InputObject.WorkingObject = $Collection 
        return $InputObject

    }
}

function FormatXml {
    <#
    .SYNOPSIS
    Pretty-print an XML object
    #>
        param(
            ## Text of an XML document. Enhance so that also XML nodes can be pretty printed, not only complete documents.
            [Parameter(ValueFromPipeline = $true)]
                [XML]$XML
        )
    
        begin {
            Write-Debug "Attach debugger here."
        }

        process {
            $StringWriter = New-Object System.IO.StringWriter;
            $XmlWriter = New-Object System.Xml.XmlTextWriter $StringWriter;
            $XmlWriter.Formatting = "indented";
            $xml.WriteTo($XmlWriter);
            $XmlWriter.Flush();
            $StringWriter.Flush();
            return $StringWriter.ToString();
        }
}

function GetPFConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('Server')]
            [PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage="The section of the configuration you want, e.g. interfaces or system/dnsserver")]
            [string]$Section        
    )
    
    begin {
        # Due to some changes, this whole section thing isn't very relevant anymore and might introduce extra bugs.
        # TODO: consider removing this section thing support
        if(-not [string]::IsNullOrWhiteSpace($Section)){
            $Section = $Section -split "/" | Join-String -Separator "']['" -OutputPrefix "['" -OutputSuffix "']"
        }
    }
    
    process {
        $XMLConfig = $null

        if($InputObject.XMLConfig -and $InputObject.XMLConfig.GetType() -eq [XML] -and [string]::IsNullOrWhiteSpace($Section)){             
            $XMLConfig = $InputObject.XMLConfig
        
        } else {
            $XMLConfig = InvokePFXMLRPCRequest -Server $InputObject -Method 'exec_php' -MethodParameter ('global $config; $toreturn=$config{0};' -f $Section)
        }
        
        #TODO: fetch only the relevant section if contains other sections too. Low prio.
        $InputObject.XMLConfig = $XMLConfig
        $InputObject.PFconfig = (ConvertFrom-Xml -InputObject $XMLConfig)
        return $InputObject
    }    
}

function GetPFInterface {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)   
    process { 
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFInterface" | out-null
        return $InputObject | out-null
    }
        
}
function GetPFAlias {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFAlias" | out-null
        return $InputObject | out-null
    }
}

function GetPFdhcpd {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFdhcpd" | out-null
        return $InputObject | out-null
    }
} 

function GetPFdhcpStaticMap {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFdhcpStaticMap" | out-null
        return $InputObject | out-null
    }
}
function PrintPFdhcpStaticMap {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $Object = (New-Object -TypeName "PFdhcpStaticMap")
        $Collection = New-Object System.Collections.ArrayList
        foreach($Staticmap in $InputObject.WorkingObject){
            $indexStaticMap = 0 
            $Properties = @{}
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
                    $Object = New-Object -TypeName "PFdhcpStaticMap" -Property $Properties
                    $Collection.Add($Object) | Out-Null
                    $indexStaticMap++
                }
        }
        $InputObject.WorkingObject = $Collection
        return $InputObject | out-null
    }
}

function GetPFFirewallRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFfirewallRule" | out-null
        return $InputObject | out-null
    }
}
function PrintPFFirewallRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
            foreach($Rule in $InputObject.WorkingObject){
                ("Source","Destination") | foreach {
                    $Rule.$($_+"Port") = ($Rule.$_.Port) ? $Rule.$_.Port.InnerText : "any"

                    if($Rule.$_.Contains("any")){
                        $Rule.$($_+"address") = "any"

                    } elseif($Rule.$_.Contains("address")) {
                        $Rule.$($_+"address") = $Rule.$_.address.InnerText

                    } elseif($Rule.$_.Contains("network")){
                    if($($Rule.$_.network.InnerText).endswith("ip")){
                        $Rule.$($_+"address") = ("{0} address" -f $Rule.$_.network.InnerText.split("ip")[0])
                    }
                        else{$Rule.$($_+"address") = ("{0} network" -f $Rule.$_.network.InnerText)}
                    }
                }
            }
        return $InputObject | out-null
    }
}


function GetPFGateway {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFGateway" | out-null
        return $InputObject | out-null
    }
}
function GetPFNATRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFnatRule" | out-null
        return $InputObject | out-null
    }

}

function PrintPFNATRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
            foreach($Rule in $InputObject.WorkingObject){
                ("Source","Destination") | foreach {
                    $Rule.$($_+"Port") = ($Rule.$_.Port) ? $Rule.$_.Port.InnerText : "any"

                    if($Rule.$_.Contains("any")){
                        $Rule.$($_+"address") = "any"

                    } elseif($Rule.$_.Contains("address")) {
                        $Rule.$($_+"address") = $Rule.$_.address.InnerText

                    } elseif($Rule.$_.Contains("network")){
                    if($($Rule.$_.network.InnerText).endswith("ip")){
                        $Rule.$($_+"address") = ("{0} address" -f $Rule.$_.network.InnerText.split("ip")[0])
                    }
                        else{$Rule.$($_+"address") = ("{0} network" -f $Rule.$_.network.InnerText)}
                    }
                }
            }
        return $InputObject | out-null
    }
}

function GetPFStaticRoute {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process {
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFStaticRoute" | out-null
        return $InputObject | out-null
    }
}

function GetPFUnbound {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process {
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFUnbound" | out-null
        return $InputObject | out-null
    }
} 

function PrintPFUnbound {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process {
        $Properties = @{}
        $Object = New-Object -TypeName "PFUnbound" -Property $Properties
        foreach($Rule in $InputObject.WorkingObject){
            $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                if($Rule.($_.name)){$Properties.($_.name) = $Rule.($_.name)}
            }
        }
        if(-not $Properties.port){$Properties.port = "53"}
        if(-not $Properties.sslport){$Properties.sslport = "853"}
        $Object = New-Object -TypeName "PFUnbound" -Property $Properties
        $InputObject.WorkingObject = $Object 
        return $InputObject | out-null
    }
} 


function GetPFunboundHost {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process { 
        ConvertToPFObject -InputObject $InputObject -PFObjectType "PFunboundHost" | out-null
        return $InputObject | out-null
    }
}

function InvokePFXMLRPCRequest {
    <#
    .DESCRIPTION
        https://github.com/pfsense/pfsense/blob/master/src/usr/local/www/xmlrpc.php
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('InputObject')]
            [PFServer]$Server,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [ValidateSet('host_firmware_version', 'exec_php', 'exec_shell', 
                         'backup_config_section', 'restore_config_session', 'merge_installedpackages_section', 
                         'merge_config_section', 'filter_configure', 'interfaces_carp_configure', 'reboot')]
            [string]$Method,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [psobject]$MethodParameter,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [switch]$Passthru
    )
    
    begin {
        # templates to construct the request body
        $XMLRequestTemplate =   
        "<?xml version='1.0' encoding='iso-8859-1'?>" +
        "   <methodCall>" +
        "       <methodName>pfsense.##METHOD##</methodName>" +
        "       <params>" +
        "           ##PARAMS##" +                 
        "        </params>" +
        "    </methodCall>"

        $XMLMethodParamTemplate = 
        "            <param>" +
        "                <value>" +
        "                   <##TYPE##>##VALUE##</##TYPE##>" +
        "                </value>" +
        "            </param>"
    }
    
    process {
        # TODO: implement more extensive parameter support, mostly supporting multiple parameters/xml structures
        #       currently only one parameter with type int or string (default) is supported
        if($MethodParameter){
            $XMLMethodParamType = ($MethodParameter.GetType() -eq [int]) ? 'int' : 'string'
            $XMLMethodParam = $XMLMethodParamTemplate `
                                    -replace '##TYPE##', $XMLMethodParamType `
                                    -replace '##VALUE##', $MethodParameter
                                                            
        }

        $XMLRequest = $XMLRequestTemplate `
                        -replace '##PARAMS##', $XMLMethodParam `
                        -replace'##METHOD##', $Method
        
        $URL = $Server.ToString()

        $RequestParams = @{
            ContentType                     = 'text/xml'
            uri                             = $URL
            Method                          = "post"
            Body                            = $XMLRequest
            Credential                      = $Server.Credential
            Authentication                  = "basic"
            AllowUnencryptedAuthentication  = $Server.NoTLS
            SkipCertificateCheck            = $Server.SkipCertificateCheck
            UseBasicParsing                 = $true     # just to make sure it works even when internet explorer isn't installed on the system
        }

        Write-Debug "Sending XML-RPC request to $($URL), asking the server to execute the action '$($Method)'"
        Write-Debug ($XMLRequest | FormatXml ) -Verbose 

        try{
            $Response = Invoke-Webrequest @RequestParams
            $XMLResponse = [XML]$Response
            $FaultCode = ($XMLResponse | Select-Xml -XPath '//member[name="faultCode"]/value/int').Node.InnerText
            $FaultReason = ($XMLResponse | Select-Xml -XPath '//member[name="faultString"]/value/string').Node.InnerText

        # most likely reason for this error is that the returened message was invalid XML, probably because you messed up ;)
        } catch [System.Management.Automation.RuntimeException] {
            if(-not $Response){
                throw [System.TimeoutException]::new("Unable to contact the pfSense XML-RPC server at $URL")

            } else {
                Write-Debug "The returned content-type was: $($Response.Headers.'Content-Type')"
                Write-Debug "The message from the server could not be converted to XML. This is what the server returned: $($Response.Content)" 
                Write-Debug "Your message to the server was: $($XMLRequest)"
            }

        # unknow exception, let the user know
        } catch {
            Write-Error $_.Exception.Message
            Write-Error $_.ScriptStackTrace
        }

        if([string]::IsNullOrWhiteSpace($FaultCode) -and [string]::IsNullOrWhiteSpace($FaultReason)){
            return ($Passthru) ? $Response : $XMLResponse

        } else {
            switch($FaultReason){
                'Authentication failed: Invalid username or password' {
                    throw [System.Security.Authentication.InvalidCredentialException]::New("Invalid credentials to access XML-RPC at $URL")
                }
                'Authentication failed: not enough privileges' {
                    throw [System.Security.AccessControl.PrivilegeNotHeldException]::New("Insuffucient privileges to access XML-RPC at $URL")
                }
                'Unable to parse request XML' {
                    throw [System.Xml.XmlException]::New('The server was unable to parse the XML-RPC request message.')
                }
                default {
                    Write-Debug "Sent request: $($XMLRequestTemplate)"
                    Write-Debug "Server response: $($Response.Content)"                
                    throw "Server returned fault code $FaultCode with reason '$FaultReason'"
                }
            }                
        }
    }
}

function TestPFCredential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('InputObject')]
            [psobject]$Server
    )
    
    process {
        try {
            if(-not $Server.Credential -or $Server.Credential.GetType() -ne [pscredential]){
                throw [System.Security.Authentication.InvalidCredentialException]::New('Server object has no stored credential')
            }
            
            Write-Debug "Trying credentials for user '$($Server.Credential.UserName)'"
            InvokePFXMLRPCRequest -Server $Server -Method 'host_firmware_version' | Out-Null

        # catch when use of the system is not possible with this credentials
        } catch [System.Security.Authentication.InvalidCredentialException],
                [System.Security.AccessControl.PrivilegeNotHeldException] {
            Write-Debug $_.Exception.Message
            Write-Output "ERROR: $($_.Exception.Message)" -ForegroundColor red
            return $false

        # catch connection timeout, quit the program when this is detected
        } catch [System.TimeoutException] {
            throw $_.Exception

        # maybe something happened, but we are able to use the system
        } catch {
            Write-Debug $_.Exception.Message
            Write-Debug $_.ScriptStackTrace
        }

        return $true
    }    
}

## BEGIN OF CONTROLLER LOGIC, should be moved to a different script later in order to be able to dotsource this file in your own scripts.
# since debugging dotsourced files s*, leave it here for now until we're ready for a first release
# TODO: create a switch for the program to skip this contoller logic and be able to test dotsourcing this file in your own scripts too.
Clear-Host

$PFServer = [PFServer]@{
    Credential = $null 
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

# Get all config information so that we can see what's inside
$PFServer = GetPFConfiguration -Server $PFServer -Section  "" 
if(-not $PFServer.XMLConfig -or $PFServer.XMLConfig.GetType() -ne [XML]){ 
    Write-Error "Unable to fetch the pfSense configuration."
    exit 1
}

# We will have frequent reference to the [PFInterface] objects, to make them readily available
GetPFInterface -Server $PFServer
$PFServer.Config.Interfaces = $PFServer.WorkingObject

# add the IPv6 LinkLocal name and description so these can be translated
foreach($interface in $PFServer.Config.Interfaces){
    $Properties = @{}
    if($interface.DESCRIPTION){
        # If the interface has a description set it as part of it's ipv6 linklocal name
        $Properties.Name = "_lloc{0}" -f $interface.name
        $Properties.Description = "{0}IpV6LinkLocal" -f $interface.DESCRIPTION
    }
    else{
        # else use the name as part of the ipv6 linklocal name
        $Properties.Name = "_lloc{0}" -f $interface.name
        $Properties.Description = "{0}IpV6LinkLocal" -f $interface.name
    }
    $Object = New-Object -TypeName PFInterface -Property $Properties
    $PFServer.Config.Interfaces = $PFServer.Config.Interfaces + $Object     
}
# add some default name translations to the interface's like "all" and "Loopback"
$StaticInterface = @{
    all = 'all'
    lo0 = 'Loopback'
}
$StaticInterface.keys | %{
    $Properties = @{}
    $Properties.name = $_
    $Properties.Description = $StaticInterface.Item($_)
    $Object = New-Object -TypeName PFInterface -Property $Properties
    $PFServer.Config.Interfaces = $PFServer.Config.Interfaces + $Object 
}

# test objects
# make a clear visual distinction between this run and the previous run
<#
1..30 | ForEach-Object { Write-Host "" } 

Write-Host "Registered aliases:" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | GetPFAlias | Format-table *

Write-Host "Registered DHCPd servers" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | GetPFdhcpd | Format-table *

Write-Host "Registered static DHCP leases" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFDHCPStaticMap | Format-table *

Write-Host "All firewall rules" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
# TODO: if you want to convert System.Collections.Hashtable into something more meaningful (display only), do it here
#       obviously creating a Write-PFFirewallRule function would be an even better idea :)
#       DO NOT change it in the ConvertToPFObject function, since that will really complicate the reverse operation (changing and uploading the rule)
$PFServer | GetPFFirewallRule | Select-Object -ExcludeProperty Source, Destination | Format-table *

Write-Host "Registered gateways" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | GetPFGateway | Format-table *

Write-Host "Available interfaces" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | GetPFInterface | Format-table *

Write-Host "All NAT rules" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | GetPFNATRule | Format-table *

Write-Host "All static routes" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | GetPFStaticRoute | Format-table *

Write-Host "DNS server settings" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | GetPFUnbound | Format-table *

Write-Host "DNS host overrides" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | GetPFunboundHost | Format-table *

Write-Host "THE END" -BackgroundColor Gray -ForegroundColor DarkGray
exit;
#>

# define the possible execution flows
$Flow = @{
    "alias" = @{
        "print" = "param(`$InputObject); `$InputObject | GetPFAlias; `$InputObject.WorkingObject | Format-Table *"#the star makes the format table show more than 10 column's
    }

    "gateway" = @{
        "print" = "param(`$InputObject); `$InputObject | GetPFGateway; `$InputObject.WorkingObject | Format-Table *"
    }

    "interface" = @{
        "print" = "param(`$InputObject); `$InputObject | GetPFInterface; `$InputObject.WorkingObject | Format-Table *"
    }

    "StaticRoute" = @{
        "print" = "param(`$InputObject); `$InputObject | GetPFStaticRoute; `$InputObject.WorkingObject | Format-table *"
    }

    "dnsResolver" = @{
        "print" = "param(`$InputObject); `$InputObject | GetPFUnbound; `$InputObject | PrintPFUnbound; `$InputObject.WorkingObject | Format-table *"
    }    

    "dnsResolverHost" = @{
        "print" = "param(`$InputObject); `$InputObject | GetPFunboundHost; `$InputObject.WorkingObject | Format-table *"
    }   

    "portfwd" = @{
        "print" = "param(`$InputObject); `$InputObject | GetPFNATRule; `$InputObject | PrintPFNatRule; `$InputObject.WorkingObject | Select-Object -ExcludeProperty Source, Destination | Format-table *"
    }    
    "Firewall" = @{
        "print" = "param(`$InputObject); `$InputObject | GetPFFirewallRule; `$InputObject | PrintPFFirewallRule; `$InputObject.WorkingObject | Select-Object -ExcludeProperty Source, Destination | Format-table *" 
    } 
    "dhcpd" = @{
        "print" = "param(`$InputObject); `$InputObject | GetPFdhcpd; `$InputObject.WorkingObject | Format-table *" 
    } 
    "dhcpStaticMap" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFdhcpStaticMap; `$InputObject | PrintPFdhcpStaticMap; `$InputObject.WorkingObject | Format-table * -autosize" 
    } 

}

# execute requested flow  
try{
    if(-not $Flow.ContainsKey($Service)){  Write-Host "Unknown service '$Service'" -ForegroundColor red; exit 2 }
    if(-not $Flow.$Service.ContainsKey($Action)){ Write-Host "Unknown action '$Action' for service '$Service'" -ForegroundColor red; exit 3 }

    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Flow.$Service.$Action)) -ArgumentList $PFServer


} catch {
    Write-Error $_.Exception
    exit 1    
}