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


# dotsource the classes
. .\classes.ps1
       
function ConvertTo-PFObject {
    [CmdletBinding()]
    param (
        ## The XML-RPC response message
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [Alias('server')]
            [PFServer]$InputObject,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName = $true)]
            [XML]$XMLConfig,
        # The object type (e.g. PFInterface, PFStaticRoute, ..) to convert to
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [ValidateSet('PFInterface','PFStaticRoute','PFGateway','PFAlias',
                         'PFUnbound','PFNATRule','PFFirewallRule','PFFirewallSeparator',
                         'PFdhcpd')]
            [string]$PFObjectType
    )
    
    begin {
        # a supplied XML-RPC message has precedence, but if none is given, the XMLConfig stored in the PFServer object is used
        $XMLConfig = ($XMLConfig) ? $XMLConfig : $InputObject.XMLConfig
        $Collection = New-Object System.Collections.ArrayList
        $Object = (New-Object -TypeName "$PFObjectType")
        $Section = $Object::Section
        $PropertyMapping = $Object::PropertyMapping

        if(-not $PropertyMapping){
            throw [System.Data.NoNullAllowedException]::new("Object of type $($PFObjectType) is missing the static 'PropertyMapping' property")
        }

        if(-not $Section){
            throw [System.Data.NoNullAllowedException]::new("Object of type $($PFObjectType) is missing the static 'Section' property")
        }
    }
    
    process {
        # select the root of the object. This is the node that contains all the individual objects.
        # we have three choices basically: 
        # 1) we have the whole system configuration
        #       XPath to section: /methodResponse/params/param/value/struct/member[name=$section]/value
        # 2) we have the parent section of this object
        #       XPath to section: /methodResponse/params/param/value/struct/member[name=$section]/value
        # 3) we have only the very specific (sub)section
        #       XPath to section: /methodResponse/params/param/value
        $XMLSection = Select-Xml -Xml $XMLConfig -XPath '/methodResponse/params/param/value'
        ForEach($Subsection in $($Section -split '/')){
            $XMLSubsection = Select-Xml -XML $XMLSection.Node -XPath "./struct/member[name='$Subsection']/value"
            if($XMLSubsection){ $XMLSection = $XMLSubsection }
        }

        # Two XPath to get each individual item:
        #   XPath: ./struct/member (for associative array in the original PHP code)
        #   XPath: ./array/data/value (for index-based array in the original PHP code)
        #
        # $XMLObjects represent a collection of PF* objects, whereas $XMLObject is the XML representation of one PF* object.
        # we need to convert the XML into a PowerShell object in order to easily compare it with a baseline configuration or create/update/delete objects.
        # after making the required adjustments (if any), we can translate the PowerShell objects back into XML-RPC message and upload it to apply the change.
        $XMLObjects = Select-Xml -XML $XMLSection.Node -XPath "./struct/member | ./array/data/value"
        ForEach($XMLObject in $XMLObjects){    
            $XMLObject = [XML]$XMLObject.Node.OuterXML # weird that it's necessary, but as its own XML object it works           
            $Properties = @{}   # hashtable with this object's properties, used for splatting them when actually creating the object.

            # loop through each property of $Object. We're interesed in the name only in order to populate the hashtable $Properties
            $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                # the $Property is the property name, by default that is the same property name as in the XML document.
                # however, that is not always the case and those exceptions are defined in the [PF...]::PropertyMapping hashtable
                # if there is such an exception (e.g. $PropertyMapping.$Property has a value), we will use its value instead of the default
                # the XML has only lowercase property names, so that's why we convert $Property to lowercase
                $Property = $_.Name
                $XMLProperty = ($PropertyMapping.$Property) ? $PropertyMapping.$Property : $Property.ToLower()
                $PropertyValue = $null
                $PropertyTypedValue = $null

                # Property Name is a bit special, it can be
                # 1) the key in the associative array
                #       XPath: ./member/name
                # 2) a normal property value in the property array
                #       XPath: //member[name='name']/value/string
                #
                # Only situation 1 requires handling that differs from other properties, so we'll do it first
                if($XMLProperty -eq "Name"){ # Changed this to XMLProperty so that in dhcpd interface can be rewritten to name
                    $PropertyValueXPath = "./member/name"
                    $PropertyValue = (Select-Xml -XML $XMLObject -XPath $PropertyValueXPath).Node.InnerText
                }

                # TODO: detect if there is a / in the xml property name
                #       if there is one (and only one), then split on the slash and find a nice XPath to extract the requested value
                #       intended purpose is to fetch items that in the PHP source config are an associative array in a universal way, e.g.
                #       source/type or source/address
                #       in the firewall rules source => Array( "type" => "network"; "address" => "1.1.1.0/8"; "port" => "8888")
                #       in the XML, this is translated to:
                #
                #   <member>
                #     <name>source</name>
                #     <value>
                #       <struct>
                #         <member>
                #           <name>address</name>
                #           <value>
                #             <string>1.1.1.0/8</string>
                #            </value>
                #         </member>
                #         <member>
                #           <name>port</name>
                #           <value>
                #             <string>8888</string>
                #           </value>
                #         </member>
                #       </struct>
                #     </value>
                # </member>
                #
                #   Possible code flow, written pretty verbose to make all steps explicit and to avoid magic numbers
                #   $ParentIndex = 0
                #   $ChildIndex = 1
                #   $XMLProperty = "parent/child"
                #   $XMLPropertySplit = $XMLProperty -split "/"
                #   $XMLPropertyParent = $XMLPropertySplit[$ParentIndex]
                #   $XMLPropertyChild = $XMLPropertySplit[$ChildIndex]
                #
                #   e.g. //member[name='$($XMLPropertyParent)']//member[name='$($XMLPropertyChild)']/value/string
                #   or   //member[name='$($XMLPropertyParent)']/value/struct/member[name='$($XMLPropertyChild)']/value/string
                #
                #   benefit of the former over the latter is that it's very easy to (re)write it in a loop in order to support (grand)(grand)grandchildren too if necessary.
                #
                #   can make it one logic too:
                #   $PropertyValueXPath = '/value/string'
                #   ForEach($PropertyLevel in ([array]::Reverse($XMLProperty -split "/"))){
                #       $PropertyValueXPath = "//member[name='$($PropertyLevel)']$PropertyValueXPath"
                #   }
                #   $PropertyValue = (Select-Xml -XML $XMLObject -XPath $PropertyValueXPath).Node.InnerText
                #
                #

                # TODO: if possible, integrate this logic in the if-statement block below (if(-not $PropertyValue){...}) to make the changes as minimal as possible

                # the special cases above didn't apply (or they didn't yield any value)
                # let's try the method for getting the property value the "normal" way
                if(-not $PropertyValue){
                    if($(Select-String -InputObject $XMLProperty -Pattern "/" -AllMatches).Matches.count -eq 2){
                        # i'm using 2 / in the class so i can point to the correct name if multiple excist
                        $PropertyValueXPathname = "//member[name='$($XMLProperty.split("/")[0])']/value/struct/member"
                        if($XMLProperty.split("/")[2] -eq "name"){
                            $PropertyValue = $(Select-Xml -XML $XMLObject -XPath $PropertyValueXPathname)[$($XMLProperty.split("/")[1])].Node.$($XMLProperty.split("/")[2])
                        } 
                        else{
                            $PropertyValue = $(Select-Xml -XML $XMLObject -XPath $PropertyValueXPathname)[$($XMLProperty.split("/")[1])].Node.$($XMLProperty.split("/")[2]).string
                        } 
                    } 
                    Else{  
                        $PropertyValueXPath = "//member[name='$($XMLProperty)']/value/string"
                        $PropertyValue = (Select-Xml -XML $XMLObject -XPath $PropertyValueXPath).Node.InnerText
                    }
                    if(-not $PropertyValue){ # for nested array/data/value like in the dhcpd or loadbalancer pools
                        $PropertyValueXPath = "//member[name='$($XMLProperty)']/value/array/data/value/string"
                        $PropertyValue = (Select-Xml -XML $XMLObject -XPath $PropertyValueXPath).Node.InnerText
                    }
                }

                # let's inspect the property definition to see if we need to make any adjustments. Some adjustment that might be required:
                # - create a collection from a comma/pipe/space-separated string
                # - explicitly cast the value to a different object type
                $PropertyDefinition = ($Object | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $Property }).Definition
                $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                $PropertyIsCollection = $PropertyDefinition.Contains("[]")
                
                # if the property type is a collection, make sure the $PropertyValue is actually a collection. 
                # In the XML message, things we want to have as collection are separated by comma, a || or a space (as far as we know now)
                
                # This does not work because the detail field is split with || but has spaces as well
                #if($PropertyIsCollection){
                #    if($PropertyValue -like "*||*"){$PropertyValue = $PropertyValue.Split("||")}
                #    elseif($PropertyValue -like "* *"){$PropertyValue = $PropertyValue.Split(" ")}
                #    elseif($PropertyValue -like "*,*"){$PropertyValue = $PropertyValue.Split(",")}
                #} 
                
                if($PropertyIsCollection){
                    if($Property -eq "detail"){$PropertyValue = $PropertyValue.Split("||")}
                    elseif($Property -eq "address"){$PropertyValue = $PropertyValue.Split(" ")}
                    else{$PropertyValue = $PropertyValue.Split(",")}
                }



                # handle the conversion to our custom objects. For all other objects, we assume that the split
                # was sufficient. We might improve upon this later if necessary.
                # for now we support a few types only, but this might increase and might need to be refactored if that's the case.
                $PropertyTypedValue = New-Object System.Collections.ArrayList
                ForEach($Item in $PropertyValue){
                    switch($PropertyType){
                        "PFInterface" {
                            $PropertyTypedValue.Add(
                                ($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item })
                            ) | Out-Null
                        }
                    }
                }
                
                # add the property value to the hashtable. 
                # If there is a typed (converted) value, prefer that over the unconverted value
                $Properties.$Property = ($PropertyTypedValue) ? $PropertyTypedValue : $PropertyValue
            }

            # create the new object of type $PFObjectType (e.g. PFInterface, PFFirewallRule, ...)
            # We instantiate the object with values by splatting the properties hashtable
            # that we created before. 
            $Object = New-Object -TypeName $PFObjectType -Property $Properties
            $Collection.Add($Object) | Out-Null
        }

        return $Collection
    }
    
    end {}
}
function Format-Xml {
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

function ConvertSourceDestinationAddress{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Rules')][psobject]$SourceDestinationHasTable,
           [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        # I have kept the name conversion for the source and destination address out of the ConvertTo-PFObject because this is only used for two services
        ForEach($Item in $SourceDestinationHasTable){
            if($Item.SourceType -eq "network"){
                if($Item.SourceAddress.endswith("ip")){
                    $Item.SourceAddress= "{0} Adress" -f $($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item.SourceAddress.split("ip")[0]})}
                else{$Item.SourceAddress= "{0} Net" -f $($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item.SourceAddress})}
                }
            if($Item.DestType -eq "network"){
                if($Item.DestAddress.endswith("ip")){$Item.DestAddress= "{0} Adress" -f $($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item.DestAddress.split("ip")[0]})}
                else{$Item.DestAddress= "{0} Net" -f $($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item.DestAddress})}
                }
        
        }
    }
}

function Get-PFConfiguration {
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
            $XMLConfig = Invoke-PFXMLRPCRequest -Server $InputObject -Method 'exec_php' -MethodParameter ('global $config; $toreturn=$config{0};' -f $Section)
        }
        
        #TODO: fetch only the relevant section if contains other sections too. Low prio.
        $InputObject.XMLConfig = $XMLConfig
        return $InputObject
    }    
}

function Get-PFInterface {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)   
    process { return $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFInterface -Server $InputObject }
}

function Get-PFStaticRoute {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process { return $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFStaticRoute }
}

function Get-PFGateway {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process { return $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFGateway }
}


function Get-PFAlias {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $Aliases = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFalias
        return $Aliases
    }
}

function Get-PFUnbound {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)

    process {
        $Unbound = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFunbound

        return $Unbound
    }
}


function Get-PFNATRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $NatRules = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFnatRule
        ConvertSourceDestinationAddress -SourceDestinationHasTable $NatRules -InputObject $InputObject
        return $NatRules
    }

}

function Get-PFFirewallRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)

    process {
        $FirewallRules = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFfirewallRule
        ConvertSourceDestinationAddress -SourceDestinationHasTable $FirewallRules -InputObject $InputObject
        return $FirewallRules
        # $FirewallSeperator = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFFirewallseparator
        # return $FirewallSeperator
    }
}

function Get-PFdhcpd {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process { return $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFdhcpd }
}

function Invoke-PFXMLRPCRequest {
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
        Write-Debug ($XMLRequest | Format-Xml ) -Verbose 

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

function Test-PFCredential {
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
            Invoke-PFXMLRPCRequest -Server $Server -Method 'host_firmware_version' | Out-Null

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
    while(-not (Test-PFCredential -Server $PFServer)){ $PFServer.Credential = Get-Credential }

} catch [System.TimeoutException] {
    Write-Error -Message $_.Exception.Message
    exit 4

} finally {
    Write-Progress -Activity "Testing connection and your credentials" -Completed
}

# Get all config information so that we can see what's inside
$PFServer = Get-PFConfiguration -Server $PFServer -Section  "" 
if(-not $PFServer.XMLConfig -or $PFServer.XMLConfig.GetType() -ne [XML]){ 
    Write-Error "Unable to fetch the pfSense configuration."
    exit 1
}

# We will have frequent reference to the [PFInterface] objects, to make them readily available
$PFServer.Config.Interfaces = $PFServer | Get-PFInterface

# define the possible execution flows
$Flow = @{
    "alias" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFAlias | Format-Table *"#the star makes the format table show more than 10 column's
    }

    "gateway" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFGateway | Format-Table *"
    }

    "interface" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFInterface | Format-Table *"
    }

    "StaticRoute" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFStaticRoute | Format-table *"
    }

    "dnsResolver" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFunbound | Format-table *"
    }    
    "portfwd" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFnatRule | Format-table *"
    }    
    "Firewall" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFfirewallRule | Format-table *" 
    } 
    "dhcpd" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFdhcpd | Format-table *" 
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
