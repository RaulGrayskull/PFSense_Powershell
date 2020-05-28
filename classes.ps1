class PFAlias {
    [string]$Name
    [string]$Type
    [string[]]$_Address
    [string]$Description
    [string[]]$_Detail
    [PFAliasEntry[]]$Entry
 
    static [string]$Section = "aliases/alias"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Description = "descr"
        _Detail = "Detail"
        _Address = "Address"
    }
    static $Delimeter = @{
        _Detail = "||"
        _Address = " "
    }   
}

class PFAliasEntry {
    [string]$_Detail
    [string]$_Address

    [string] ToString(){
        return ("{0} : {1}" -f $this._Detail,$this._Address)
    }
}


class PFDHCPd{
    [PFInterface]$Interface
    [string]$RangeFrom
    [string]$RangeTo
    [string]$netmask
    [string]$Domain
    [string]$Gateway # This can be a inividual gateway and does not have to be a pfgateway object
    [string]$DNSServer
    [string]$NTPServer
#   New Lines
    [string]$ddnsdomainkeyalgorithm
    [string]$ddnsdomainprimary              
    [string]$domainsearchlist               
    [string]$filename64                     
    [string]$ddnsdomainkey                  
    [string]$ddnsdomainkeyname              
    [string]$nextserver                     
    [string]$tftp
    [string]$maxleasetime                                      
    [string]$ddnsdomain                     
    [string]$ldap                           
    [string]$failover_peerip                                         
    [string]$filename                       
    [string]$enable                         
    [string]$pool                           
    [string]$filename32                     
    [string]$mac_allow                      
    [string]$numberoptions                  
    [string]$dhcpleaseinlocaltime           
    [string]$defaultleasetime               
    [string]$ddnsclientupdates              
    [string]$mac_deny
    [hashtable[]]$staticmap
    [PFdhcpStaticMap[]]$staticmaps
#    [string]$staticmap
    [string]$rootpath
    # From here they are used for the static map
    [string[]]$_StaticHostname
    [string[]]$_StaticDomain
    [string[]]$_StaticClientID
    [string[]]$_StaticMACaddr
    [string[]]$_StaticIPaddr
    [string[]]$_StaticDescription
    [string[]]$_StaticGateway
    [string[]]$_StaticDNSserver
    [string[]]$_StaticNTPServer
    [string[]]$_Staticrootpath
    [string[]]$_Staticldap
    [string[]]$_Statictftp
    [string[]]$_Staticfilename
    [string[]]$_Staticmaxleasetime
    [string[]]$_Staticdomainsearchlist
    [string[]]$_Staticddnsdomainkey
    [string[]]$_Staticddnsdomainprimary
    [string[]]$_Staticdefaultleasetime
    [string[]]$_Staticddnsdomainkeyname
    [string[]]$_Staticddnsdomain                       



    static [string]$Section = "dhcpd"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Interface = "_key"
        RangeFrom = "range/from"
        RangeTo = "range/to"
        netmask = "netmask"
        Domain = "Domain"
        Gateway = "Gateway"
        DNSServer = "DNSServer"
        NTPServer = "NTPServer"
#        staticmap = "Static_map" # This does not excist in the xml, but will be filled by the get function
        # From here they are used for the static map
        _StaticHostname = "staticmap/Hostname"
        _StaticDomain = "staticmap/Domain"
        _StaticClientID = "staticmap/CID"
        _StaticIPaddr = "staticmap/IPaddr"
        _StaticDescription  = "staticmap/descr"
        _StaticMACaddr  = "staticmap/mac"
        _StaticGateway = "staticmap/Gateway"
        _StaticDNSserver = "staticmap/DNSserver"
        _StaticNTPServer = "staticmap/NTPServer"
        _Staticrootpath = "staticmap/rootpath"
        _Staticldap = "staticmap/ldap"
        _Statictftp = "staticmap/tftp"
        _Staticfilename = "staticmap/filename"
        _Staticmaxleasetime = "staticmap/maxleasetime"
        _Staticdomainsearchlist = "staticmap/domainsearchlist"
        _Staticddnsdomainkey = "staticmap/ddnsdomainkey"
        _Staticddnsdomainprimary = "staticmap/ddnsdomainprimary"
        _Staticdefaultleasetime = "staticmap/defaultleasetime"
        _Staticddnsdomainkeyname = "staticmap/ddnsdomainkeyname"
        _Staticddnsdomain = "staticmap/ddnsdomain"
    }
}

class PFdhcpStaticMap{
    [string]$Interface
    [string]$Hostname
    [string]$Domain
    [string]$ClientID
    [string]$MACaddr
    [string]$IPaddr
    [string]$Description
    [string[]]$Gateway
    [string[]]$DNSserver
    [string[]]$NTPServer
    [string]$rootpath
    [string]$ldap
    [string]$tftp
    [string]$filename
    [string]$maxleasetime
    [string]$domainsearchlist
    [string]$ddnsdomainkey
    [string]$ddnsdomainprimary
    [string]$defaultleasetime
    [string]$ddnsdomainkeyname
    [string]$ddnsdomain

    static [string]$Section = "dhcpd"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Hostname = "_StaticHostname"
        Domain = "_StaticDomain"
        ClientID = "_StaticClientID"
        MACaddr = "_StaticMACaddr"
        IPaddr = "_StaticIPaddr"
        Description = "_StaticDescription"
        Gateway = "_StaticGateway"
        DNSserver = "_StaticDNSserver"
        NTPServer = "_StaticNTPServer"
        rootpath  = "_Staticrootpath"
        ldap = "_Staticldap"
        tftp = "_Statictftp"
        filename = "_Staticfilename"
        maxleasetime = "_Staticmaxleasetime"
        domainsearchlist = "_Staticdomainsearchlist"
        ddnsdomainkey = "_Staticddnsdomainkey"
        ddnsdomainprimary = "_Staticddnsdomainprimary"
        defaultleasetime = "_Staticdefaultleasetime"
        ddnsdomainkeyname = "_Staticddnsdomainkeyname"
        ddnsdomain = "_Staticddnsdomain"
    }
}

# This class is only used to write the value's to the display, here the value's are in strings and not in a array of strings to improve the estatics
class PFdhcpStaticMapWrite{
    [PFInterface]$Interface
    [string]$Hostname
    [string]$Domain
    [string]$ClientID
    [string]$MACaddr
    [string]$IPaddr
    [string]$Description
    [string]$Gateway
    [string[]]$DNSserver
    [string]$NTPServer

    static [string]$Section = "dhcpd"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{}
}

class PFFirewall {
    [bool]$IsFloating = $false
    [bool]$IsQuick = $false
    [bool]$IsDisabled = $false
    [bool]$IsLogged = $false
    [ValidateSet('pass', 'block', 'reject', '')]
        [string]$Type
    [ValidateSet('inet', 'inet6', 'inet46')]
        [string]$IPProtocol
    [PFInterface[]]$interface
    [ValidateSet('tcp', 'udp', 'tcp/udp', 'icmp', 'esp', 'ah', 'gre', 'ipv6', 
                 'igmp', 'pim', 'ospf', 'tp', 'carp', 'pfsync', '')]
        [string]$Protocol
    [hashtable]$Source
    [string]$SourceAddress
    [string]$SourcePort
    [hashtable]$Destination
    [string]$DestinationAddress
    [string]$DestinationPort
    [string]$Description
# new lines
    [string]$statetype
    [string]$direction
    [string]$os
    [string]$tag
    [string]$maxsrcstates
    [string]$icmptype
    [string]$created
    [string]$tracker
    [string]$max
    [string]$updated
    [string]$tagged
    [string]$statetimeout
    [string]$maxsrcnodes
    [string]$maxsrcconn
    [string]$associatedruleid

    static [string]$Section = "filter/rule"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        IsFloating = "floating"
        IsQuick = "quick"
        IsDisabled = "disabled"
        IsLogged = "log"
        Description = "descr"
        Source = "source" 
        SourceAddress= $null
        SourcePort = $null
        Destination = "destination"
        DestAddress= $null
        DestPort = $null
        # New lines
        maxsrcstates = "max-src-states"
        maxsrcnodes = "max-src-nodes"
        maxsrcconn = "max-src-conn"
        associatedruleid = "associated-rule-id"
    }
    static $Delimeter = @{
        interface = ","
    }
    [string] ToString(){
        return ("{0}:{1} -> {2}:{3}" -f $this.SourceAddress,$this.SourcePort,$this.DestAddress,$this.DestPort)
    }
    
}

class PFFirewallSeparator {
    [string]$row
    [string]$text
    [string]$color
    [PFInterface[]]$interface

    static [string]$Section = "filter/separator"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        interface = "if"
    }
}

class PFGateway {
    [string]$Name    
    [PFInterface]$Interface
    [string]$Gateway
    [string]$Monitor
    [string]$Weight
    [string]$IPProtocol
    [string]$Description

    static [string]$Section = "gateways/gateway_item"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Description = "descr"
    }
    [string] ToString(){
        return $this.Name
    }
}

class PFInterface {
    [bool]$Enable = $True
    [ValidateNotNullOrEmpty()][string]$Name
    [string]$Description
    [string]$Interface
    [string]$Spoofmac
    [string]$IPv4Address    # should be [ipaddress] object, but that's for later, a interface can have dhcp as ipaddress and that crashes the internal ipaddress class
#    [IPAddress]$IPv4Address
    [string]$IPv4Subnet
    [string]$IPv4Gateway    # should be [PFGateway] object, but that's for later; this creates a loop because we need the interfaces to create the dhcp gateway's 
    [string]$IPv6Address    # should be [ipaddress] object, but that's for later
    [string]$IPv6Subnet
    [string]$IPv6Gateway    # should be [PFGateway] object, but that's for later
    [string]$Trackv6Interface
    [string]$Trackv6PrefixId
    [bool]$BlockBogons
    [string]$Media
    [string]$MediaOpt
    [string]$DHCPv6DUID
    [string]$DHCPv6IAPDLEN
    
    

    static [string]$Section = "interfaces"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Name = "_key"
        Interface = "if"
        Description = "descr"
        IPv4Address = "ipaddr"
        IPv4Subnet = "subnet"
        IPv4Gateway = "gateway"
        IPv6Address = "ipaddrv6"
        IPv6Subnet = "subnetv6"
        IPv6Gateway = "gatewayv6"
        Trackv6Interface = "track6-interface"
        Trackv6PrefixId = "track6-prefix-id"
        DHCPv6DUID = "dhcp6-duid"
        DHCPv6IAPDLEN = "dhcp6-ia-pd-len"
    }

    [string] ToString(){
        return ([string]::IsNullOrWhiteSpace($this.Description)) ? $this.Name : $this.Description
    }
}

class PFNATRule {
    [hashtable]$Source
    [string]$SourceAddress
    [string]$SourcePort
    [hashtable]$Destination
    [string]$DestinationAddress
    [string]$DestinationPort
    [string]$protocol
    [string]$target
    [string]$LocalPort
    [PFinterface]$interface
    [string]$Description
    [String]$updated
    [PFFirewall]$FirewallRule
#    [String]$FirewallRule # could be a PFFirewall object
    [String]$created

    static [string]$Section = "nat/rule"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        LocalPort = "local-port"
        Description = "descr"
        Source = "source" 
        SourceAddress= $null
        SourcePort = $null
        Destination = "destination"
        DestAddress= $null
        DestPort = $null
        FirewallRule = "associated-rule-id"
    }
}

class PFServer {
    [string]$Address
    [pscredential]$Credential
    [bool]$NoTLS
    [bool]$SkipCertificateCheck = $false
    [System.Xml.XmlDocument]$XMLConfig     # XML-RPC answer when requesting the current configuration
    [psobject]$PSConfig # $this.XMLConfig parsed to powershell objects by the XmlRpc library
    
    [string] ToString(){        
        $Schema = ($this.NoTLS) ? "http" : "https"
        return ("{0}://{1}/xmlrpc.php" -f $Schema, $this.Address)
    }
}

class PFStaticRoute {
    [string]$Network
    [PFGateway]$Gateway
    [string]$Description
    
    static [string]$Section = "staticroutes/route"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        Description = "descr"
    }
}

class PFUnbound {
    [string]$ActiveInterface
    [string]$OutgoingInterface
    [bool]$dnssec
    [bool]$enable
    [int]$port
    [int]$sslport

    static [string]$Section = "unbound"
    static $PropertyMapping = @{
        ActiveInterface = "active_interface"
        OutgoingInterface = "outgoing_interface"
    }
}

class PFUnboundHost {
    [string]$Hostname
    [string]$Domain
    [string]$IPaddr
    [string]$AliasesHost
    [string]$AliasesDomain
    [string]$AliasesDescription

    static [string]$Section = "unbound/hosts"
    static $PropertyMapping = @{ 
        Hostname = "host"
        Domain = "Domain"
        IPaddr = "IP"
        aliasesHost = "aliases/item/host"
        AliasesDomain = "aliases/item/domain"
        AliasesDescription = "aliases/item/Description"
    }
}


class PFVlan {
    [string]$interface
    [string]$Tag
    [string]$vlanif
    [string]$Priority
    [string]$Description

    static [string]$Section = "vlans/vlan"
    static $PropertyMapping = @{
        interface = "if"
        Tag = "tag"
        Description = "descr"
        Priority = "pcp"
    }
}