The use of this script is "pfsense_api -server '' -username '' -Password '' -service '' -action '' argument1 argument2 argument3 argument4 argument5 -NoTest -NoTLS'"
the services suported are:

Service                  Help message                                 Example                                                                                                                                                      
-------                  ------------                                 -------                                                                                                                                                      
Help                     Prints this text                                                                                                                                                                                          
                                                                                                                                                                                                                                   
Route                    to mange static routes on the pfsense                                                                                                                                                                     
Route Print              Print all the static routes                  pfsense_api -server '' -username '' -Password '' -service Route -action print                                                                                
Route Add                Add a static route                           pfsense_api -server '' -username '' -Password '' -service Route -action Add network_addr Subnet(CIDR method) Gateway_name "Description this must be betwee...
                                                                      pfsense_api -server '' -username '' -Password '' -service Route -action Add 192.168.0.0 24 WAN_DHCP "Description this must be between quotation marks"       
Route Delete             Delete a static route                        pfsense_api -server '' -username '' -Password '' -service Route -action Delete network_addr Subnet(CIDR method) Gateway_name                                 
                                                                      pfsense_api -server '' -username '' -Password '' -service Route -action Delete 192.168.0.0 24 WAN_DHCP                                                       
                                                                                                                                                                                                                                   
Interface                to mange the interface's on the pfsense                                                                                                                                                                   
Interface                Print the interface's                        pfsense_api -server '' -username '' -Password '' -service Interface -action print                                                                            
                                                                                                                                                                                                                                   
Gateway                  to mange the Gateways on the pfsense                                                                                                                                                                      
Gateway                  Print the Gateways                           pfsense_api -server '' -username '' -Password '' -service Gateway -action print                                                                              
Gateway add              add a Gateway                                pfsense_api -server '' -username '' -Password '' -service Gateway -action add Name GW_address Monito_addr interface "Description this must be between quot...
                                                                      pfsense_api -server '' -username '' -Password '' -service Gateway -action add new_gateway 192.168.0.2 192.168.0.2 WAN "Description this must be between qu...
Gateway delete           delete a Gateway                             pfsense_api -server '' -username '' -Password '' -service Gateway -action delete Name                                                                        
                                                                      pfsense_api -server '' -username '' -Password '' -service Gateway -action delete new_gateway                                                                 
                                                                                                                                                                                                                                   
dnsresolver              to mange the dnsresolver on the pfsense                                                                                                                                                                   
dnsresolver print        to print the dnsresolver                     pfsense_api -server '' -username '' -Password '' -service dnsresolver -action print                                                                          
dnsresolver uploadcostum to upload a custom config to the dnsresolver pfsense_api -server '' -username '' -Password '' -service dnsresolver -action UploadCustom "Custom File"                                                     
                                                                      pfsense_api -server '' -username '' -Password '' -service dnsresolver -action UploadCustom CustomOptions.txt                                                 
                                                                                                                                                                                                                                   


