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

class pfbind {
    [string]$BindRamLimit
    [bool]$EnableBind
    [string]$BindDnssecValidation
    [string]$BindGlobalSettings
    [string[]]$LogOptions
    [ValidateSet('critical', 'error', 'warning', 'notice', 'info', 'debug 1', 'debug 3', 'debug 5', 'dynamic')][string]$LogSeverity
    [bool]$BindHideVersion
    [string]$RateEnabled
    [pfinterface[]]$listenon
    [string]$controlport
    [bool]$BindNotify
    [bool]$BindForwarder
    [bool]$BindLogging
    [string]$RateLimit
    [string]$BindIpVersion
    [string]$LogOnly
    [string]$listenport
    [string]$BindForwarderIps
    [string]$BindCustomOptions

    static [string]$Section = "installedpackages/bind/config"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        BindRamLimit = "bind_ram_limit"
        EnableBind = "enable_bind"
        BindDnssecValidation = "bind_dnssec_validation"
        BindGlobalSettings = "bind_global_settings"
        LogOptions = "log_options"
        LogSeverity = "log_severity"
        BindHideVersion = "bind_hide_version"
        RateEnabled = "rate_enabled"
        BindNotify = "bind_notify"
        BindForwarder = "bind_forwarder"
        BindLogging = "bind_logging"
        RateLimit = "rate_limit"
        BindIpVersion = "bind_ip_version"
        LogOnly = "log_only"
        BindForwarderIps = "bind_forwarder_ips"
        BindCustomOptions = "bind_custom_options"
    } 
}


class pfbindacls {
    [string[]]$row
    [string]$acl
    [string]$description
    [string[]]$_value
    [string[]]$_description
    [PFBindAclsEntry[]]$RangeBlock

    static [string]$Section = "installedpackages/bindacls/config"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        acl = "name"
        _Value = "row/value"
        _description = "row/description"
    } 
}

class PFBindAclsEntry{
    [string]$_value
    [String]$_Description

    [string] ToString(){
        return ("{0}: {1}" -f $this._value,$this._Description)
    }
}


class pfbindviews {
    [string]$recursion
    [string]$description
    [string]$BindCustomOptions
    [PFInterface[]]$MatchClients
    [PFInterface[]]$AllowRecursion
    [string]$temp
    [string]$name

    static [string]$Section = "installedpackages/bindviews/config"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        BindCustomOptions = "bind_custom_options"
        MatchClients = "Match-Clients"
        AllowRecursion = "allow-recursion"
    } 
}

class pfbindZone {
    [hashtable[]]$row
    [string]$dnssec
    [string]$allowquery
    [string]$tll
    [string]$disabled
    [string]$temp01
    [string]$regdhcpstatic
    [string]$serial
    [string]$backupkeys
    [string]$type
    [string]$resultconfig
    [string]$expire
    [string]$reversv6o
    [string]$temp04
    [string]$minimum
    [string]$ipns
    [string]$temp03
    [string]$rpz
    [string]$description
    [string]$allowtransfer
    [string]$reverso
    [string]$allowupdate
    [string]$slaveip
    [string]$enable_updatepolicy
    [string]$updatepolicy
    [string]$nameserver
    [string]$customzonerecords
    [string]$view
    [string]$retry
    [string]$dsset
    [string]$forwarders
    [string]$name
    [string]$refresh
    [string]$custom
    [string]$temp02
    [string]$mail

    static [string]$Section = "installedpackages/bindzone/config"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
    } 
}

class PFCert {
    [string]$ReferenceID
    [string]$Description
    [string]$Private
    [string]$crt
    [string]$Cert

    static [string]$Section = "cert"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        ReferenceID = "refid"
        Description = "descr"
        Private = "prv"
        Cert = "crt"
    }
}


class PFDHCPd{
    [Bool]$enable
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
    [string]$pool                           
    [string]$filename32                     
    [string]$mac_allow                      
    [string]$numberoptions                  
    [string]$dhcpleaseinlocaltime           
    [string]$defaultleasetime               
    [string]$ddnsclientupdates              
    [string]$mac_deny
    [hashtable[]]$_staticmaps
    [PFdhcpStaticMap[]]$staticmaps
    [string]$rootpath             

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
        _staticmaps = "staticmap"
    }
}

class PFdhcpStaticMap{
    [PFInterface]$Interface
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
        ClientID = "cid"
        MACaddr = "mac"
        Description = "desc"
    }
}

class PFDnsMasq{
    [string]$Port
    [bool]$DHCPReg
    [bool]$Enable
    [bool]$Dhcpfirst
    [bool]$StrictOrder
    [bool]$DomainNeeded
    [bool]$NoPrivateReverse
    [string]$CustomOptions
    [PFInterface[]]$ActiveInterface
    [hashtable[]]$Hosts
    [hashtable[]]$domainoverrides
    [bool]$Strictbind
    [bool]$DHCPRegstatic

    static [string]$Section = "dnsmasq"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        StrictOrder = "strict_order"
        DomainNeeded = "domain_needed"
        NoPrivateReverse = "no_private_reverse"
        CustomOptions = "custom_options"
        DHCPRegstatic = "Regdhcpstatic"
        ActiveInterface = "Interface"
    }
}

class PFDnsMasqDomain {
    [string]$Domain
    [string]$Address
    [string]$Description

    static [string]$Section = "dnsmasq/domainoverrides"
    static $PropertyMapping = @{ 
        Address = "IP"
        Description = "descr"
    }
}

class PFDnsMasqHost{
    [PFDnsHostEntry[]]$Alias
    [string]$Description
    [string]$domain
    [string]$Hostname
    [string]$Address
    [string[]]$_AliasesDescription
    [string[]]$_AliasesDomain
    [string[]]$_AliasesHost
    $aliases # If aliases is set to [hashtable[]] and it is empty, it crashes the script

    static [string]$Section = "dnsmasq/hosts"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Description = "descr"
        Hostname = "host"
        Address = "ip"
        _AliasesDescription = "aliases/item/description"
        _AliasesDomain = "aliases/item/domain"
        _AliasesHost = "aliases/item/host"
    }
}

class PFDnsHostEntry{
    [string]$_AliasesHost
    [string]$_AliasesDomain
    [String]$_AliasesDescription

    [string] ToString(){
        return ("{0}.{1}: Description= {2}" -f $this._AliasesHost,$this._AliasesDomain,$this._AliasesDescription)
    }
}


class PFFirewall {
    [int]$lineNumber
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
    [hashtable]$created
    [string]$tracker
    [string]$max
    [hashtable]$updated
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
    [bool]$Enable = $False
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
    [bool]$blockpriv
    [string]$Media
    [string]$MediaOpt
    [string]$DHCPv6DUID
    [string]$DHCPv6IAPDLEN
    [string]$dhcphostname
    [string]$dhcprejectfrom
    [string]$AliasAddress
    [string]$AliasSubnet
    [string]$AdvDhcpPtTimeout
    [string]$AdvDhcpPtRetry
    [string]$AdvDhcpPtSelectTimeout
    [string]$AdvDhcpPtReboot
    [string]$AdvDhcpPtBackoffCutoff
    [string]$AdvDhcpPtInitialInterval
    [string]$AdvDhcpPtValues
    [string]$AdvDhcpSendOptions
    [string]$AdvDhcpRequestOptions
    [string]$AdvDhcpRequiredOptions
    [string]$AdvDhcpOptionModifiers
    [string]$AdvDhcpConfigAdvanced
    [string]$AdvDhcpConfigFileOverride
    [string]$AdvDhcpConfigFileOverride_path
    [string]$AdvDhcp6PrefixSelectedInterface


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
        aliasaddress = "alias-address"
        AliasSubnet = "alias-subnet"
        AdvDhcpPtTimeout = "adv_dhcp_pt_timeout"
        AdvDhcpPtRetry = "adv_dhcp_pt_retry"
        AdvDhcpPtSelectTimeout = "adv_dhcp_pt_select_timeout"
        AdvDhcpPtReboot = "adv_dhcp_pt_reboot"
        AdvDhcpPtBackoffCutoff = "adv_dhcp_pt_backoff_cutoff"
        AdvDhcpPtInitialInterval = ""
        AdvDhcpPtValues = "adv_dhcp_pt_initial_interval"
        AdvDhcpSendOptions = "adv_dhcp_pt_values"
        AdvDhcpRequestOptions = "adv_dhcp_send_options"
        AdvDhcpRequiredOptions = "adv_dhcp_request_options"
        AdvDhcpOptionModifiers = "adv_dhcp_option_modifiers"
        AdvDhcpConfigAdvanced = "adv_dhcp_config_advanced"
        AdvDhcpConfigFileOverride = "adv_dhcp_config_file_override"
        AdvDhcpConfigFileOverride_path = "adv_dhcp_config_file_override_path"
        AdvDhcp6PrefixSelectedInterface = "adv_dhcp6_prefix_selected_interface"
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
    [hashtable]$updated
    [PFFirewall]$FirewallRule
#    [String]$FirewallRule # could be a PFFirewall object
    [hashtable]$created

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
    [PFInterface[]]$ActiveInterface
    [PFInterface[]]$OutgoingInterface
    [bool]$dnssec
    [bool]$enable
    [int]$port
    [int]$sslport
    [string]$CustomOptions
    [string]$hideidentity
    [string]$hideversion
    [string]$dnssecstripped
    [string]$sslcertref
    [string]$SystemDomainLocalZoneType
    [hashtable[]]$hosts
    [hashtable[]]$domainoverrides


    static [string]$Section = "unbound"
    static $PropertyMapping = @{
        CustomOptions = "custom_options"
        SystemDomainLocalZoneType = "system_domain_local_zone_type"
        ActiveInterface = "active_interface"
        OutgoingInterface = "outgoing_interface"
    }
}

class PFUnboundHost {
    [string]$Hostname
    [string]$Domain
    [string]$Address
    [string]$Description
    [string[]]$_AliasesHost
    [string[]]$_AliasesDomain
    [string[]]$_AliasesDescription
    [PFDnsHostEntry[]]$Alias
    $aliases # If aliases is set to [hashtable[]] and it is empty, it crashes the script

    static [string]$Section = "unbound/hosts"
    static $PropertyMapping = @{ 
        Hostname = "host"
        Domain = "Domain"
        Address = "IP"
        Description = "descr"
        _AliasesHost = "aliases/item/host"
        _AliasesDomain = "aliases/item/domain"
        _AliasesDescription = "aliases/item/Description"
    }
}


class PFUnboundDomain {
    [string]$Domain
    [string]$Address
    [string]$Description
    [string]$TlsHostname
    [bool]$TLSQueries

    static [string]$Section = "unbound/domainoverrides"
    static $PropertyMapping = @{ 
        Address = "IP"
        Description = "descr"
        TlsHostname = "tls_hostname"
        TLSQueries = "forward_tls_upstream"
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