The use of this script is "pfsense_api -server '' -username '' -Password '' -service '' -action '' arguments -NoTest -NoTLS'"<br/>
-NoTLS switch is used to set the connection protocol to http, default is https.<br/>
-NoTest switch is used to not test if the pfsense is online.<br/>
This script is tested on PFSense 2.4.4-RELEASE-p3<br/>
<br/>
the services suported are:<br/>
<br/>
Service						Help message<br/>
------------------------------------------------------------<br/>
Help:						Prints this text<br/>
<br/>
Route:						to mange static routes on the pfsense<br/>
Route Print:				Print all the static routes<br/>
Route Add:					Add a static route<br/>
Route Delete:				Delete a static route<br/>
<br/>
Interface:					to mange the interface's on the pfsense<br/>
Interface print:			Print the interface's<br/>
<br/>
Gateway:					to mange the Gateways on the pfsense<br/>
Gateway print:				Print the Gateways<br/>
Gateway add:				add a Gateway<br/>
Gateway delete:				delete a Gateway<br/>
<br/>
dnsresolver:				to mange the dnsresolver on the pfsense<br/>
dnsresolver print:			print the dnsresolver<br/>
dnsresolver uploadcostum:	upload a custom config to the dnsresolver<br/>
dnsresolver addhost:    	Add a host override<br/>
dnsresolver deletehost:    	delete a host override<br/>
dnsresolver adddomain:    	Add a domain override<br/>
dnsresolver deletedomain:  	delete a domain override<br/>
<br/>
Portfwd:                    To manage portforwarder on the pfsense<br/>
Portfwd Print:              print the port forwarder rules<br/>
Portfwd Add:                add a port forwarder rules<br/>
Portfwd Delete:             delete a port forwarder rules<br/>
<br/>
Alias:                      To manage the aliases on the pfsense<br/>
Alias Print:                Print the aliases<br/>
Alias PrintSpecific:        Print the specific's of a alias<br/>
Alias Add:                  Add a new alias<br/>
Alias Delete:               Delete a alias<br/>
Alias Addvalue:             add a value to a Alias<br/>
Alias Deletevalue:          delete a value from a Alias<br/>
<br/>

