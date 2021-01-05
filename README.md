# F5 SSL Orchestrator External Layered Architecture
A configuration scheme and toolset to deploy SSL Orchestrator in an external layered (load balanced) architecture.

### Version support
This utility works on BIG-IP 14.1 and above, SSL Orchestrator 5.x and above.

### Description 
In the traditional SSL Orchestrator model, a single or HA pair of F5 devices is inserted inline of the traffic flow, and security services attach directly (or indirectly) to these. At the very least, this dictates the size of appliances used to facilitate the full traffic load requirement. And as with any such deployment, if your requirements increase beyond this capacity, you're forced to forklift upgrade. An alternative, scalable approach is to insert SSL Orchestrator appliances in a load balanced configuration (behind a separate L4 load balancer). The frontend appliance is handling L4-only traffic, so its throughput will naturally be much higher, while SSL Orchestrator devices can be added at will as throughput requirements increase.

![SSL Orchestrator External Layered Architecture](images/images1.png)

An added benefit is that a separate "escape" path can be created in the event of a catastrophic failure in the security stack, to maintain availability (if required). This approach does have a disadvantage though, as it becomes more complex to share the security devices between these now standalone SSL Orchestrator appliances. Layer 2 devices require a smart switch fabric between them and the F5 to offload 802.1Q tagged traffic, and layer 3 devices must support policy routing (all to ensure routing back to the correct F5 appliance). Further, as these are standalone SSL Orchestrator appliances, they do not have insight into the load balancing states of the other devices, so may unintentionally overtask security devices.

Another option exists, however, by taking greater advantage of the powerful L4 BIG-IP. In this architecture, the L4 appliance load balances encrypted traffic to the SSL Orchestrator appliance, and these pass decrypted traffic (across different internal VLANs) back to the L4. The L4 then more capably handles load balancing of decrypted traffic to the shared security devices.

![SSL Orchestrator External Layered Architecture - improved](images/images2.png)

This architecture greatly simplifies the SSL Orchestrator configurations, enhances availability, and removes any need for smart switches or policy routing on security devices. But, while this reduced complexity elsewhere, it significantly increases complexity at the L4 appliance. SSL Orchestrator in and of itself is a complex thing. Its guided configuration design obfuscates the creation of an abundance of network objects (VLANs, self-IPs, route domains, VIPs, pools, rules, profiles, etc.). In this external layered design, the SSL Orchestrator appliances need only configure ONE device for each service - a listening instance on the L4, while the L4 must now manually handle all of the wiring that the guided config used to hide. 

In this repository, that complex per-service-type wiring will be thoroughly explained should you want to build it by hand. Otherwise, a toolset is also provided that will do all of this work for you.


### Toolset
The toolset consists of a central Python application and a set of YAML-based configuration files. The YAML files constitute a single source-of-truth for each security device deployed, and defines both sides - how SSL Orchestrator speaks to the service, and how the L4 speaks to the respective devices. Otherwise, the toolset abstracts away as much of the complexity as possible. The individual security service definitions are independent and atomic, allowing for fast creation, modification, and deletion of configurations. In the remaining portion of this README, details of the toolset and YAML file syntax will be described.


### How to install
The Python application can either run on your local system (targeting remote BIG-IPs), or directly on the L4 BIG-IP (targeting localhost). Copy the Python application to the desired path and provide it a configuration YAML file.

`python sslo-tier-tool.py --file layer3service1.yml`

The tool will validate the YAML configuration and then push the required settings to the L4 BIG-IP. This tool supports standalone and HA L4 configurations, generally by including separate IPs, interfaces, tags, and floating IPs for each appliance. Also note that updates are disruptive. To facilitate quick and complete updates to network objects, any existing objects for this service are first removed and then rebuilt. This will cause a momentary lapse in traffic flow to this service. It is therefore recommended that the service be taken out of active SSL Orchestrator service chains before performing any management actions.

The following is the detailed YAML configuration syntax for service mapping and each supported security device type:
- Service mapping
- Layer 3 security service
- Layer 2 security service
- HTTP explicit security service
- HTTP transparent security service
- ICAP security service


### Service mapping
The 


### Layer 3 security service YAML definition
The 


### Layer 2 security service YAML definition
The 


### HTTP explicit security service YAML definition
The 


### HTTP transparent security service YAML definition
The 


### ICAP security service YAML definition
The 

