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


<#
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


#>
# dotsource the classes
. .\classes.ps1
function ConvertTo-PFObject{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)][PFServer]$InputObject,
        [Parameter(Mandatory=$true)]$PFObjectType,
        [Parameter(Mandatory=$False)]$SectionOverride
    )

    begin{
        # to make the names a bit clearer, use PFType, PFTypeProperties and PFTypePropertyMapping
        # this because in the parsing, it otherwise gets confusing since there are a lot of variables refering to some $object... thing
        $PFType = (New-Object -TypeName $PFObjectType)
        $PFTypeProperties = ($PFType | Get-Member -MemberType properties).Name
        $PFTypePropertyMapping = $PFType::PropertyMapping
        $PFTypeDelimeterMapping = $PFType::Delimeter
        if($SectionOverride){$PFSection = $SectionOverride}
        else{$PFSection = $PFType::section}

        # container for the resulting PF* objects
        $Collection = New-Object System.Collections.ArrayList        
    } 

    process { 
        # make double sure the PFServer $inputObject has the configuration stored inside. It most likely already has the configuration,
        # which makes it scenario 2 for Get-PFConfiguration and it will return the $InputObject unaltered.
        $InputObject = $InputObject | Get-PFConfiguration
        
        $ObjectToParse = $InputObject.PSConfig
        foreach($XMLPFObj in $PFSection.Split("/")){
            $ObjectToParse = $ObjectToParse.$XMLPFObj
        }
        if(-not $ObjectToParse){ return }

        # To enable a single and structured approach, we need to make the hashtable key (often the Name property, but not always) 
        # available in the value (value always is a hashtable). This makes sure we can use one iterable function to iterate over all objects. 
        # The idea is that one entry in the array/hashtable equals to one PF* object, so after this, we can loop through the array and do the conversion.
        # The hashtable key will be made available in the array as "_key" 
        if($ObjectToParse.GetType() -eq [hashtable]){
            $ObjectToParse.GetEnumerator() | ForEach-Object {
                if($_.Value."_key"){ return } # this is how to simulate "continue" in a ForEach-Object block, see http://stackoverflow.com/questions/7760013/ddg#7763698
                if($_.Value.PSObject.Methods.Name -notcontains "Add" ){ return }
#                if($_.Value.gettype() -ne [Hashtable]){return} # to make dnsresolver not crash, now we need te get the value's we need
                $_.Value.Add("_key", $_.Key)
            } 
        }
 
        # now iterate over all objects and convert them
        $ObjectToParse.GetEnumerator() | ForEach-Object {
            # the last step of the process will be to create a new object. We need a container with the property values for the PF* object
            # so that we can splat them into the New-Object cmdlet later
            $PFObjectProperties = @{} 

            # iterate over all properties that are defined in the PF* object. 
            # find the property value based on the property mapping (if that exists) or assume the property name in $ObjectToParse is the 
            # same as in the PF* object if no mapping is defined, i.e. $PFTypeProperty
            foreach($PFTypeProperty in $PFTypeProperties){
                # set the default property value: null. We have:
                # - $PropertyValue: the uncasted property value
                # - $PropertyTypedValue: $PropertyValue casted to another PF* object, like PFInterface or PFGateway
                $PropertyValue = $PropertyValues = $PropertyTypedValue = $PropertyTypedValues = $null

                # do the mapping from PFTypeProperty to $ObjectToParse property. Retain the XML in the name to indicate clearly it refers
                # to the property name as returned by the XML-RPC request. 
                # if no mapping exists, assume the propertyname in the $ObjectToParse is the same as in the PF* object
                $XMLProperty = ($PFTypePropertyMapping.$PFTypeProperty) ? $PFTypePropertyMapping.$PFTypeProperty : $PFTypeProperty.ToLower()

                # assign the uncasted property value. If there is a / in the property name, it means that it should be iterated one level deeper.
                # unlimited deep nesting levels are supported.
                # if $_ is a hashtable, the value is in $_.Value.$XMLProperty, when it's an array it's in $_.$XMLProperty
                $XMLPropertyTree = $XMLProperty.Split("/")
                $XMLPropertyRoot = $XMLPropertyTree | Select-Object -First 1

                # first handle the root. We need to separate this because it's value comes form the array/hashtable $_
                $PropertyValues = ($_.Value) ? $_.Value.$XMLPropertyRoot : $_.$XMLPropertyRoot

                # now handle all lower levels (if none exists this step will be effectively skipped)
                foreach($XMLProperty in ($XMLPropertyTree | Select-Object -Skip 1)){
                    if(-not ($PropertyValues -and $PropertyValues.$XMLProperty)) { break }

                    $PropertyValues = $PropertyValues.$XMLProperty
                }
                
                # if the $PropertyValue equals $null, we do not have to process anything. It doesn't need to be added to the 
                # $PFObjectProperties hashtable, since $null is the implicit default value. no need to make that explicit.
                if([string]::IsNullOrEmpty($PropertyValues)){ continue }

                # since the $ObjectToParse is the parsed XML-RPC message, all the values are (supposed to) XMLElements.
                # we need to replace the XMLElement by its (string) actual value. All other adjustments can be done here as well.
                $PropertyValues = $PropertyValues | ForEach-Object { ($_.PSObject.Properties.Name -contains "InnerText") ? $_.InnerText : $_ }

                # we need to support two scenario's now: one where the $PropertyValue is a single item and one where it's an array of items
                # in order to maintain only one workflow, we will make sure it is an array of items (or array of one item). 
                # after typecasting the propertyvalues later in this cmdlet, we will convert again to single item if necessary.
                if(($PropertyValues.GetType()).BaseType -ne [array]){ $PropertyValues = @($PropertyValues) }

                # next step is to cast the $PropertyValue to the required type as specified in the PF* object
                # if we omit this step, we will get an exception when trying to instantiate the object
                # to enable that, let's gather the property definition to see where to cast to
                $PropertyDefinition = ($PFType | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $PFTypeProperty }).Definition
                $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                $PropertyIsCollection = $PropertyDefinition.Contains("[]")

                # TODO: the || and space splitted items will be not necessary anymore after PFAlias has been refactored to contain PFAliasEntries
                #       known issue: PFAlias property Detail is split on space, which should not happen. BUT, properties Address/Detail need to be in their own object anyway
                # If the property is (should be) a collection but contains only one item, we might need to split them.
                if($PropertyIsCollection -and ($PropertyValues.Count -eq 1)){ 
                    $PropertyValue = $PropertyValues | Select-Object -First 1
                    if(-not $PFTypeDelimeterMapping.$PFTypeProperty){}
                    elseif($Null -eq $PFTypeDelimeterMapping.$PFTypeProperty){$PFTypeDelimeterMapping.$PFTypeProperty = ","}
                    $PropertyValues = $PropertyValue.split($PFTypeDelimeterMapping.$PFTypeProperty)
                }   

                $PropertyTypedValues = New-Object System.Collections.ArrayList
                foreach($PropertyValue in $PropertyValues){
                    switch($PropertyType){
                        "PFGateway"     { $PropertyTypedValue = $InputObject | Get-PFGateway -Name $PropertyValue } 
                        "PFInterface"   { $PropertyTypedValue = $InputObject | Get-PFInterface -Name $PropertyValue }
                        "PFFirewall"    { if($PropertyValue){$PropertyTypedValue = $InputObject | Get-PFFirewall -associatedruleid $PropertyValue }} # If Propertyvalue is empty, no associated rule is created and it is a empty field, get-pffirewall then try's to return all the rule's and that crashes the script
                        "bool"          { $PropertyTypedValue = ([bool]$PropertyValue -or ($PropertyValue -in ('yes', 'true', 'checked', ''))) }
                        default         { $PropertyTypedValue = $PropertyValue }
                    }

                    $PropertyTypedValues.Add($PropertyTypedValue) | Out-Null
                }

                # at this point, the:
                #   - $PropertyTypedValues contains an array with all the $PropertyTypedValue items
                #   - $PropertyTypedValue contains the casted version of the last $Item
                #
                # if $PropertyIsCollection we will add the array to the $PFObjectProperties hashtable
                # if the value should be singular (e.g. $PropertyIsCollection is false), we will add the $PropertyTypedValue
                # this behavior mimics that the last item overwrites earlier items (if any). 
                $PFObjectProperties.$PFTypeProperty = ($PropertyIsCollection) ? $PropertyTypedValues : $PropertyTypedValue
            } # end loop through all PFTypeProperties

            # create the instance of PFType and add it to the collection
            $PFTypeInstance = New-Object -TypeName $PFObjectType -Property $PFObjectProperties
            $Collection.Add($PFTypeInstance) | Out-Null
        }
        
        # return the collection with PF* objects
        return $Collection
    }
}

function ConvertFrom-PFObject{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)][PFServer]$InputObject,
        [Parameter(Mandatory=$true)]$PFObject,
        [Parameter(Mandatory=$true)]$PFObjectType
        
    )
    begin{
        # Check if PFObject is as expected, thus a array
        $PFType = (New-Object -TypeName $PFObjecttype)
        $PFTypePropertyMapping = $PFType::PropertyMapping
        $PFTypeDelimeterMapping = $PFType::Delimeter
        $PFSection = $PFType::section
        $ReturnObject = $InputObject.PSConfig
    }
    process{
#        $PFHashValue = New-Object -TypeName "System.Collections.ArrayList" #It needs to be a array and not a ArrayList
        $PFHashTableName = "" # Make sure the PFHashTableName is empty
        [string]$PFHashValue = "" # Make the $PFHashvalue a string
        $PFTypePropertyMapping.GetEnumerator() | foreach { # If the hashtable has a entry with the value _key, retype $PFHashValue as a hashtable
            if($_.value -eq "_key"){
                [Hashtable]$PFHashValue = @{}
            }
        }
        if($PFHashValue.gettype() -ne [hashtable]){[array]$PFHashValue = ""} # If $PFHashValue is not a hashtable, it should be a array.
        foreach($PFObjectEntry in $PFObject){
            [Hashtable]$PFHashValueEntry = @{}
            Foreach($Property in $PFObjectEntry.psobject.Properties){
                [string]$PropertyTypedValue = ""
                $XMLProperty = $PFTypePropertyMapping.$($Property.name) ? $PFTypePropertyMapping.$($Property.name) : $Property.name.ToLower()
                switch($Property.TypeNameOfValue){
                    "PFGateway"     { $PropertyTypedValueConverted = $Property.value.name } 
                    "PFInterface"   { $PropertyTypedValueConverted = $Property.value.Description}
#                    "PFFirewall"    {}
                    default         { $PropertyTypedValueConverted = $Property.value}
                }
                if($XMLProperty -match "/"){
                    [hashtable]$PropertyTypedValue = @{}
                    $PropertyTypedValue.add($($XMLProperty.Split("/"))[-1],$PropertyTypedValueConverted)

#                    [array]$PropertyTypedValueArray = $PropertyTypedValue
                    if($PFHashValueEntry.$($($XMLProperty.Split("/"))[-2])){$PFHashValueEntry.$($($XMLProperty.Split("/"))[-2]) = $PFHashValueEntry.$($($XMLProperty.Split("/"))[-2]) + $PropertyTypedValue}# $PropertyTypedValueArray}
                    else{$PFHashValueEntry.add($($XMLProperty.Split("/"))[-2],$PropertyTypedValue)}
                }
                else{
                    $PFHashValueEntry.add($XMLProperty,$PropertyTypedValueConverted)
                }
                
            }
            if($PFHashValue.gettype() -ne [hashtable]){ # If $PFHashValue is a array add $PFHashValueEntry (In most cases)
                if([string]::IsNullOrWhitespace($PFHashValue)){$PFHashValue = $PFHashValueEntry} # If the Array is empty (First round), we fill it with the hashtable of $PFHashValueEntry
                # Using a Array and not a Array list because ConvertTo-XmlRpcType does not take arraylist
                else{$PFHashValue += $PFHashValueEntry} # If the Array has a value (Second or more), we add the $PFHashValueEntry
            }
            elseif($PFHashValue.gettype() -eq [hashtable]){ # If $PFHashValue is a hashtable, add $PFHashValueEntry as value to the _key as key
                $PFTypePropertyMapping.GetEnumerator() | foreach {
                    if($_.value -eq "_key"){
                        $PFHashTableName = $PFObjectEntry.$($_.name).name
                        $PFHashValue.add($PFHashTableName,$PFHashValueEntry)
                    }
                }
            }
        }
        # ToDo: This only works for 1 or 2 layers deep for now and only if the 1 layer has _key in the propertymapping
        if($PFSection.Split("/")[1]){
            $PFHashTableName = $($PFSection.Split("/")[-1])
            $PFXMLSection = $($PFSection.Split("/")[-2])
            $ReturnObject.$PFXMLSection = @{$PFHashTableName = $PFHashValue}
        }
        else{
            $ReturnObject.$PFSection = $PFHashValue
        }
        # Take out the _key value's
        Remove-_Key -Hashtable $ReturnObject

        [xml]$XMLToUpload = ConvertTo-XmlRpcType -InputObject $ReturnObject
        $XMLToUpload.Save("NewAll.xml") # Temporary save to easaly open the xml file in a more visual editor, This should be the command to upload to the PFsense 
       return $XMLToUpload
    }
}

Function Remove-_Key{
    <#
    This function remove's the _key value's from the return object
    #>
    param([Parameter(ValueFromPipeline = $true)][hashtable]$Hashtable)
    process{
        foreach($Key in $Hashtable.keys){
            try{ # it can happen that $hashtable.Item($key) is a $Null value, this creates a error on the gettype(), we catch those and can continue with the code. this is not a hashtable
                if($hashtable.Item($Key).gettype() -eq [hashtable]){
                    Remove-_Key -Hashtable $hashtable.Item($Key) # if it is a hashtable in a hashtable, we go tru that hashtable as well
                }
            }catch{}
            if("_key" -eq $Key){ # if the $key is _key, we use that internally in the script, there have to be removed from the hashtables
                $Hashtable.Remove($Key)
                return
            }
        }
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

function Get-PFConfiguration {
    <#
    .SYNOPSIS
        Fetch the current configuration from a pfSense server via XML-RPC. Convert the XML-RPC answer to a Powershell object.
    
    .DESCRIPTION
        This function takes a PFServer object and adds to it the configuration for this server. 
        
        There are three scenario's which are supported by this function:
        1) The PFServer object has no XMLConfig saved
        2) The PFServer object has a XMLConfig saved already
        3) The PFServer object has a XMLConfig saved already but the user wants to have it refreshed

        Ad 1: 
        If there is no XML configuration in the PFServer object, it will be fetched from the pfSense as defined in the PFServer object.
        After fetching and validating the XML, it will be converted into a Powershell object for easier parsing by other functions.

        Ad 2:
        The supplied PFServer object already has a configuration stored inside. Do nothing and just return the PFServer object.

        Ad 3:
        For some reason the user suspects the saved configuration (if any) might be stale so it should be refreshed. It can do do so by setting
        the -NoCache flag to force scenario 1 to be executed after clearing the currently saved configuration.
    
    .PARAMETER Server
        The PFServer object to act on. This value can be passed by pipeline and multiple PFServer objects can be passed that way at once.

    .PARAMETER NoCache
        Switch to indicate that any saved configuration MUST be refreshed by querying the pfSense server

    #>
    [CmdletBinding()]
    [OutputType('PFServer')] 
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('Server')]
            [PFServer]$InputObject,
        [Parameter(Mandatory=$false)]
            [switch]$NoCache
    )
    
    process {
        # check for scenario 3, i.e. forced refresh of possibly stale cached configuration. 
        # Set both the XMLConfig and PSConfig properties to $null to force the Invoke-PFXMLRPCRequest to be executed
        if($NoCache){ $InputObject.XMLConfig = $InputObject.PSConfig = $null }

        # check if the XML configuration has been saved and is valid (scenario 2). If this is NOT the case (i.e. scenario 1), update the configuration.
        if((-not $InputObject.XMLConfig) -or ($InputObject.XMLConfig.GetType() -ne [XML])){
            try{
                $InputObject.XMLConfig = Invoke-PFXMLRPCRequest -InputObject $InputObject -Method 'exec_php' -MethodParameter 'global $config; $toreturn=$config;'
                $InputObject.PSConfig = ConvertFrom-Xml -InputObject $InputObject.XMLConfig

            } catch {
                # TODO: do some proper error handling here. Need to handle the exceptions that Invoke-PFXMLRPCRequest or ConvertFrom-XML can throw
                Write-Error $_.Exception.Message
                Write-Error $_.Exception
                exit 1
            }
        }

        return $InputObject
    }    
}

Function Save-PFAll{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='The Path where the xml file is to be stored')] [string] $Path,
        [Parameter(Mandatory=$false, HelpMessage='The File name of the xml file')] [string] $File
        )
    Process{
        # check if the file enterd has a .xml extention, if not, add it.
        if(-not $file.EndsWith(".xmlrpc")){$file = "{0}.xmlrpc" -f $File}
        if(!(Test-Path $Path)){
            New-Item -ItemType Directory -Force -Path $Path
        }
        $InputObject.XMLConfig.Save("$path\$file")
    }
}

Function Restore-PFAll{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage='The Path where the xml file is to be stored')] [string] $Path,
        [Parameter(Mandatory=$false, HelpMessage='The File name of the xml file')] [string] $File
        )
    Process{
        # check if the file enterd has a .xml extention, if not, add it.
        if(-not $file.EndsWith(".xmlrpc")){$file = "{0}.xmlrpc" -f $File}
        if(!(Test-Path $Path)){
            Write-Error "Could not find path"
        }
        [xml]$RestoreXML = Get-Content "$path\$file"
        $InputObject.XMLConfig = $RestoreXML # should be the invoke xml-rpc function, but for now this works for testing
    }
}

function Get-PFInterface {
    <#
    .SYNOPSIS 
        Get a PFInterface object for each of the interfaces that are available in the pfSense

    .DESCRIPTION
        Get-PFInterface is one of the more extensive Get-PF* functions, since there are a couple of special things that need to happen
        First, it gets the interfaces as defined in the pfSense configuration. So far, that's very standard behavior.
        Secondly, it adds some interfaces that are not explicitly defined but nonetheless exist in the pfSense server, e.g. lo0 (local loopback)

    .PARAMETER Server
        Alias for InputObject, accepts the pipeline input. This should be a PFServer object.

    .PARAMETER Name
        Optional parameter to filter by interface name. 
    #>
    [CmdletBinding()]
    [OutputType([PFInterface[]])]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false)][string]$Name,
        [Parameter(Mandatory=$false)][string]$Description
    )   
    process { 
        # TODO: for performance reasons, you might want to consider a check if the interfaces exist already. In that case, you can simply return the existing version already.
        #       without that addition is might perform a few extra steps every time, but it's very unlikely that it will be a bottleneck.

        # Since we will add some ephemeral interfaces later on, the $Interfaces array needs to be extensible and hence be explictly defined as ArrayList first
        $Interfaces = New-Object System.Collections.ArrayList

        # Retrieve the explicitly defined interfaces from the pfSense configuration and add them to the $Interfaces collection.  
        $InterfacesFromConfig = $InputObject |  ConvertTo-PFObject -PFObjectType "PFInterface"
        $InterfacesFromConfig | ForEach-Object { $Interfaces.Add($_) | Out-Null }
        
        # Invert the Enable Bool, if the interface is enabled it has a enable with no value, if the interface is disabled it has no enbale field in the xml field. The default value in de class is $true, if no enable field is found it stay's true and thus disabled
        $Interfaces | ForEach-Object {$_.Enable = -not $_.Enable}

        # add the IPv6 LinkLocal name and description so these can be translated
        $InterfacesFromConfig.GetEnumerator() | ForEach-Object {
            $Properties = @{
                Name = "_lloc{0}" -f $_.Name
                Description = "{0}IpV6LinkLocal" -f (($_.Description) ? $_.Description : $_.Name)
            }
             
            $EphemeralInterface = New-Object -TypeName "PFInterface" -Property $Properties
            $Interfaces.Add($EphemeralInterface) | Out-Null    
        }

        # there is also a number of implicitly defined interfaces that do not appear in the configuration
        # these are the Link Local, loopback and the IPv6 interfaces. 
        # there is also a special interface All, which is a reference to all interfaces. This one is used for example in service configurations
        # that should listen on all interfaces and is functionally equivalent to :: . 
        # However, in the configuration for these services (e.g. DNS server) it appears as string "all"
        # We need to manually create these "static interfaces" to satisfy the type definition/conversion on the PF* where an interface is defined
        # as [PFInterface]$Interface (or [PFInterface[]]$Interface in some cases.)
        (@{ all = 'All'; lo0 = 'Loopback'; '(self)' = "ThisFirewall" }).GetEnumerator() | ForEach-Object {
            $EphemeralInterface =  New-Object -TypeName "PFInterface" -Property @{ Name = $_.Key; Description = $_.Value }
            $Interfaces.Add($EphemeralInterface) | Out-Null
        }

        # return section
        # return all the interfaces if no $Name parameter was given
        if(([string]::IsNullOrWhitespace($Name)) -and ([string]::IsNullOrWhitespace($Description))){
            return $Interfaces
        }
        elseif($Name){# return the $Interfaces, filtered by Name -eq $Name
            if($Name -in $Interfaces.Name){ #This does work to check if the name exists.
                return ($Interfaces | Where-Object { $_.Name -eq $Name })
            }
            else{return $Null}
        }
        elseif($Description){
            if($Description -in $Interfaces.Description){ #This does work to check if the Description exists.
                return ($Interfaces | Where-Object { $_.Description -eq $Description })
            }
            else{return $Null}
        }
    }
}
function Get-PFAlias {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $Lines = ConvertTo-PFObject -PFObjectType "PFAlias" -InputObject $InputObject
        foreach($Line in $Lines){
            $index = 0
            $Properties = @{}
            $Object = New-Object -TypeName "PFAliasEntry" -Property $Properties
            while($Line._address[$Index]){
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                    $Property = $_.Name
                    try {$PropertyValue = $Line.$Property[$index]}
                    catch{$PropertyValue = $Line.$Property}
    
                    $Properties.$Property = $PropertyValue
                }
                $Object = New-Object -TypeName "PFAliasEntry" -Property $Properties
                $line.Entry = $line.Entry + $Object
                $index++
            }
        }
        return $Lines
    }
}

function Set-PFAlias {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject,
        [Parameter(Mandatory=$true)][psobject]$PFObject
    )
    Begin{
        $UploadObjects = New-Object System.Collections.ArrayList 
    }
    process{
        # Split Entry back into alias and detail array's
        foreach($Object in $PFObject){
            $index = 0
            while($Object.Entry[$index]){
                if($index -eq 0){ # first entry we replace the _address and _detail
                    $_Address = $Object.Entry[$index]._Address.ToString()
                    $_Detail = $Object.Entry[$index]._Detail.ToString()
                }
                else{   # all the others we add
                    $_Address += (" {0}" -f $Object.Entry[$index]._Address)
                    $_Detail += ("||{0}" -f $Object.Entry[$index]._Detail)
                }
                $Index++
            }
            $UploadObject = [PSCustomObject]@{
                _Detail = $_Detail
                _Address = $_Address
                Name = $Object.name
                Type = $Object.Type
                Description = $Object.Description
            }
            $UploadObjects.add($UploadObject)    
        }
        ConvertFrom-PFObject -InputObject $InputObject -PFObject $UploadObjects -PFObjectType "PFAlias"
    }    
}




function Get-PFDHCPd {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $DHCPD = $InputObject | ConvertTo-PFObject -PFObjectType "PFDHCPd"
        foreach($Entry in $DHCPD){
            $SectionOverride = "dhcpd/{0}/staticmap" -f $Entry.Interface.name
            $DHCPStaticmap = $InputObject | ConvertTo-PFObject -PFObjectType "PFdhcpStaticMap" -SectionOverride $SectionOverride
            $Entry.staticmaps = $DHCPStaticmap
        }
        return $DHCPD
    }
}

function Set-PFDHCPd {
    <#
    Make the PFobject ready to send to the ConvertFrom-PFObject.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject,
        [Parameter(Mandatory=$False)][psobject]$NewObject)
    Begin{
        $UploadObjects = New-Object System.Collections.ArrayList 
    }
    process{
        $PFObject = Get-PFdhcpd -Server $PFserver
        if($NewObject.Interface.Description -in $PFObject.Interface.Description){
            $Index = 0
            While($PFObject[$index]){
                if($PFObject[$index].Interface.Description -eq $NewObject.Interface.Description){$PFObject[$index] = $NewObject}
                $index++
            }
        }
        else{$PFObject = $PFObject + $NewObject}
        foreach($Object in $PFObject){
            if($Object.staticmaps){
                $Object._staticmaps = @{}
                $Object.staticmaps | foreach{
                    $StaticmapHashtable = @{}
                    $_.psobject.properties | foreach{
                        if($_.name -eq "Interface"){ # The Interface is a internal object and does not need to be uploaded
                            return
                        }
                        else{
                            $StaticmapHashtable[$_.Name] = $_.Value
                        }
                    }
                    if([string]::IsNullOrWhitespace($Object._staticmaps.Macaddr)){$Object._staticmaps = $StaticmapHashtable}
                    else{$Object._staticmaps += $StaticmapHashtable}
                }
            }
            $UploadObjects.add($($Object | Select-Object -Property * -ExcludeProperty "staticmaps"))
        }
        ConvertFrom-PFObject -InputObject $InputObject -PFObject $UploadObjects -PFObjectType "PFDHCPd"
    }    
}

function Get-PFFirewall {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false)][string]$associatedruleid
        )
    process {
        $Rules = ConvertTo-PFObject -PFObjectType "PFFirewall" -InputObject $InputObject
        foreach($Rule in $Rules){
            ("Source","Destination") | foreach {
                $Rule.$($_+"Port") = ($Rule.$_.Port) ? $Rule.$_.Port.InnerText : "any"

                if($Rule.$_.Contains("any")){
                    $Rule.$($_+"address") = "any"

                } elseif($Rule.$_.Contains("address")) {
                    $Rule.$($_+"address") = $Rule.$_.address.InnerText

                } elseif($Rule.$_.Contains("network")){
                if($($Rule.$_.network.InnerText).endswith("ip")){
                    $Rule.$($_+"address") = ("{0} address" -f (get-pfinterface -name ($Rule.$_.network.InnerText.split("ip")[0]) -server $InputObject))
                }
                    else{$Rule.$($_+"address") = ("{0} network" -f (get-pfinterface -name ($Rule.$_.network.InnerText.split("ip")[0]) -server $InputObject))}
                }
            }
        }
        if([string]::IsNullOrWhitespace($associatedruleid)){
            return $Rules
        } else {
            if($associatedruleid -in $Rules.associatedruleid){
                return ($Rules | Where-Object { $_.associatedruleid -eq $associatedruleid })
            }
            else{return $Null}
        }
    }
}

function Set-PFGateway {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject,
        [Parameter(Mandatory=$true)][psobject]$NewObject)
    process{
        $UploadObject = $NewObject | Where-Object {$_.interface}
        ConvertFrom-PFObject -InputObject $InputObject -PFObject $UploadObject -PFObjectType "PFGateway"
    }    
}

function Get-PFGateway {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false)][string]$Name
        )
    process {
        $Gateways = ConvertTo-PFObject -PFObjectType "PFGateway" -InputObject $InputObject
        $Interfaces = get-pfinterface -server $InputObject
        $Object = (New-Object -TypeName "PFGateway")
        foreach($interface in $interfaces){
            $Properties = @{}
            ("DHCP","DHCP6") | foreach{
                if($_ -in ($interface.IPv4Address,$interface.IPv6Address)){
                    $Properties.name = "{0}_{1}" -f $interface.Description,$_
                    $Properties.Description = "Interface {0}_{1} Gateway" -f $interface.Description,$_
                    $Properties.Interface = $interface
                    $Object = New-Object -TypeName "PFGateway" -Property $Properties
                    # If the dhcp gateway is eddited by the users, it already excists in the gatewayobjects if it is not in there we neet to add it, the name is a unique identifier
                    if($gateways.name -NotContains $object.name){$Gateways = $Gateways + $Object}
                }
            }
        }
        (@{ Null4 = 'Null4'; Null6 = 'Null6' }).GetEnumerator() | ForEach-Object {
            $EphemeralGateway =  New-Object -TypeName "PFGateway" -Property @{ Name = $_.Key; Description = $_.Value }
            $Gateways = $Gateways + $EphemeralGateway
        }
        if([string]::IsNullOrWhitespace($Name)){
            return $Gateways
        } else {           
            if($Name -in $Gateways.Name){
                return ($Gateways | Where-Object { $_.Name -eq $Name })
            }
            else{return $Null}
        }
    }
}

function Get-PFNATRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $Rules = ConvertTo-PFObject -PFObjectType "PFnatRule" -InputObject $InputObject
        foreach($Rule in $Rules){
            ("Source","Destination") | foreach {
                $Rule.$($_+"Port") = ($Rule.$_.Port) ? $Rule.$_.Port.InnerText : "any"

                if($Rule.$_.Contains("any")){
                    $Rule.$($_+"address") = "any"

                } elseif($Rule.$_.Contains("address")) {
                    $Rule.$($_+"address") = $Rule.$_.address.InnerText

                } elseif($Rule.$_.Contains("network")){
                    if($($Rule.$_.network.InnerText).endswith("ip")){
                        $Rule.$($_+"address") = ("{0} address" -f (get-pfinterface -name ($Rule.$_.network.InnerText.split("ip")[0]) -server $InputObject))
                    }
                    else{$Rule.$($_+"address") = ("{0} network" -f (get-pfinterface -name ($Rule.$_.network.InnerText.split("ip")[0]) -server $InputObject))}
                }
            }
        }
    return $Rules
    }
} 

function Set-PFNATRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$False)][psobject]$NewObject
    )
    begin{
        $UploadObjects = New-Object System.Collections.ArrayList 
        $Interface = get-pfinterface -server $InputObject
        $Alias = Get-PFAlias -server $InputObject
    }
    process {
        foreach($Object in $NewObject){
            foreach($SourceDestination in "Source","Destination") {
                [hashtable]$hashtable = @{}
                if($Object.$($SourceDestination+"Port")){
                    $hashtable.add("Port",$Object.$($SourceDestination+"Port"))
                }
                if($object.$($SourceDestination+"Address") -eq "any"){
                    $hashtable.add("Any","")
                }
                elseif($object.$($SourceDestination+"Address").split(" ")[0] -in $interface.Description){
                    if ($object.$($SourceDestination+"Address").split(" ")[1] -eq "Address"){
                        $NetworkValue = ((Get-PFInterface -InputObject $InputObject -Description $($object.$($SourceDestination+"Address").split(" ")[0])).name)+"ip"
                        }
                    else{$NetworkValue = ((Get-PFInterface -InputObject $InputObject -Description $($object.$($SourceDestination+"Address").split(" ")[0])).name)}
                    $hashtable.add("network",$NetworkValue)
                }
                else{# if $object.$($_+"Address").split(" ")[0] is not a interface description value, it must be a ip address or a alias value
                    try{ # we try to convert the $object.$($_+"Address") to a ip address, if this fails it must be a alias 
                        if($object.$($SourceDestination+"Address") -match "/"){ # here we see if it is a subnetted address
                            if(([ipaddress]$object.$($SourceDestination+"Address").split("/")[0]) -and ($object.$($SourceDestination+"Address").split("/")[1] -in 1..128)){
                                $NetworkValue = $object.$($SourceDestination+"Address")
                            }
                        }
                        else{ # or a host address
                            if([ipaddress]$object.$($SourceDestination+"Address")){
                                $NetworkValue = $object.$($SourceDestination+"Address")
                            }
                        }
                    }
                    catch{ # 
                        if($object.$($SourceDestination+"Address") -in $alias.name){
                            $NetworkValue = $object.$($SourceDestination+"Address")
                        }
                        else{
                            throw "Could not find $($object.$($SourceDestination+"Address")) as a internal network or a alias"
                        }
                    }
                    $hashtable.add("Address",$NetworkValue)
                }
                $Object.$($SourceDestination) = $hashtable
            }
            $UploadObjects.add($($Object | Select-Object -Property * -ExcludeProperty "SourceAddress","SourcePort","DestinationAddress","DestinationPort")) | out-null
        }
        ConvertFrom-PFObject -InputObject $InputObject -PFObject $UploadObjects -PFObjectType "PFNATRule"
    }
}

function Get-PFStaticRoute {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType  "PFStaticRoute"
    }
}

function Set-PFStaticRoute {
    <#
    Make the PFobject ready to send to the ConvertFrom-PFObject.
    In this case it is already done, but in other cases we need to do some tweaking just like the get-pf functions.
    to keep the flows the same i still choise to add this function and not send it to the ConfertFrom-PFObject directly.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject,
        [Parameter(Mandatory=$true)][psobject]$NewObject)
    process{
        ConvertFrom-PFObject -InputObject $InputObject -PFObject $NewObject -PFObjectType "PFStaticRoute"
    }    
}

function Get-PFUnbound {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType  "PFUnbound"
    }
}


function Get-PFunboundHost {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process { 
        $InputObject | ConvertTo-PFObject -PFObjectType "PFunboundHost"
    }
}

function Get-PFVlan {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType "PFVlan"
    }
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
