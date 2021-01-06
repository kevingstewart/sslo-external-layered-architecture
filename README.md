# F5 SSL Orchestrator External Layered Architecture (DRAFT)
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
To understand mapping, it is first critical to understand how traffic flows through this architecture. Encrypted traffic from a load balancer (could be the same L4 LB) is distributed to SSL Orchestrator instances. Each SSLO instance is configured roughly the same, only that the service definitions use slightly offset entry and return self-IPs (in the same subnets). As decrypted traffic passes to a service in the service chain, SSLO passes this to a corresponding listener on the L4 LB. This F5 then appropriately load balances the traffic to the set of security devices. These devices will pass the traffic back to the L4 LB, and the L4 LB must then pass the traffic back to the correct SSLO instance. The L4 LB cannot take advantage of split-session signaling as SSL Orchestrator does, so must use a different method to ensure proper return routing to an SSL Orchestrator instance.

![SSL Orchestrator data flow](images/images3a.png)

For each security service, the L4 LB effectively straddles two networks:
- An "SSLO-side" network - the side that the SSLO instances communicates with
- A "SVC-side" network - the side that the L4 LB communicates with the security devices

In order to return traffic to the correct SSLO instance, the LB uses a tracking mechanism based on the incoming MAC address (the SSLO entry MAC). This MAC address (A) is statically mapped to the destination IP on the SSLO return side (B). As traffic enters the L4 LB on the SSLO-side, the SSLO MAC address is captured. When it is time to return traffic to SSLO, the MAC address is mapped to the correct destination (route) IP and forwarded. Thus a mapping table is required for each security service, for each SSLO instance. The following table and example illustrate the syntax of this mapping table. Note that any time a service is created on the L4 LB, the mapping table must be updated accordingly.

**Details**:
| field               | required | Description                                                                                           |
|---------------------|----------|-------------------------------------------------------------------------------------------------------|
| name                | yes      | value: arbitrary string - provide a name for this document                                            |
| host                | yes      | value: Host, IP, localhost                                                                            |
| user                | yes      | value: admin username                                                                                 |
| password            | yes      | value: admin password                                                                                 |
| service             | yes      | value: none - service start block                                                                     |
|   type              | yes      | value: mapping                                                                                        |
|   mapping           | yes      | value: none - mapping start block                                                                     |
|                     |          |                                                                                                       |
|     - service       | yes      | value: service name                                                                                   |
|       maps          | yes      | value: none - service map start block                                                                 |
|         - name      | yes      | value: arbitrary name of the SSLO appliance instance                                                  |
|           srcmac    | yes      | value: MAC address from which traffic will arrive from this SSLO appliance to the LB service instance |
|           dstip     | yes      | value: destination IP to send traffic back to this SSLO appliance                                     |

**Example**:
```
name: service mapping
host: localhost
user: admin
password: admin
service:
  type: mapping
  mapping:
    
    - service: paloalto
      maps:
        - name: sslo1
          srcmac: "52:54:00:11:a4:42"
          destip: "198.19.2.245"
        - name: sslo2
          srcmac: "52:54:00:db:cb:98"
          destip: "198.19.2.244"
    
    - service: fireeye
      maps:
        - name: sslo1
          srcmac: "52:54:00:11:a4:42"
          destip: "198.9.64.245"
        - name: sslo2
          srcmac: "52:54:00:db:cb:98"
          destip: "198.9.64.244"
```


### Layer 3 security service YAML definition
Each "inline" service instance type will minimally define SSLO-side settings (how SSLO communicates with this listener), and SVC-side settings (how this F5 communicates with the security devices). This supports both single and HA-type deployments.

*Note in the above image, it is most appropriate to use a single VLAN tagged interface on the SSLO side to save on physical ports.*

**Details**:
| field                      | required | Description                                                                                           |
|----------------------------|----------|-------------------------------------------------------------------------------------------------------|
| name                       | yes      | value: arbitrary string - provide a name for this document                                            |
| desc                       | no       | value: arbitrary string                                                                               |
| host                       | yes      | value: Host, IP, localhost                                                                            |
| user                       | yes      | value: admin username                                                                                 |
| password                   | yes      | value: admin password                                                                                 |
| service                    | yes      | value: none - service start block                                                                     |
|   type                     | yes      | value: layer3                                                                                         |
|   name                     | yes      | value: the name of this service instance                                                              |
|   state                    | yes      | value: 'present' or 'absent' - allows you define create/update state, or deletion                     |
|                            |          |                                                                                                       |
|     sslo-side-net          | yes      | value: none - sslo-side configuration start block                                                     |
|       entry-interface      | yes      | value: the physical interfaces for incoming traffic from SSLO instances                               |
|       entry-self           | yes      | value: the self-IP for this interface                                                                 |
|       entry-float          | yes (HA) | value: the floating self-IP for this interface in an HA config                                        |
|       entry-tag            | no       | value: if present, represents the 802.1Q VLAN tag for this interface.                                 |
|       return-interface     | yes      | value: the physical interfaces for outgoing traffic to SSLO instances.                                |
|       return-self          | yes      | value: the self-IP for this interface                                                                 |
|       return-tag           | no       | value: if present, represents the 802.1Q VLAN tag for this interface.                                 |
|                            |          |                                                                                                       |
|     svc-side-net           | yes      | value: none - svc-side configuration start block                                                      |
|       entry-interface      | yes      | value: the physical interfaces for incoming traffic from SSLO instances                               |
|       entry-self           | yes      | value: the self-IP for this interface                                                                 |
|       entry-float          | yes (HA) | value: the floating self-IP for this interface in an HA config                                        |
|       entry-tag            | no       | value: if present, represents the 802.1Q VLAN tag for this interface.                                 |
|       return-interface     | yes      | value: the physical interfaces for outgoing traffic to SSLO instances.                                |
|       return-self          | yes      | value: the self-IP for this interface                                                                 |
|       return-float         | yes (HA) | value: the floating self-IP for this interface in an HA config                                        |
|       return-tag           | no       | value: if present, represents the 802.1Q VLAN tag for this interface.                                 |
|                            |          |                                                                                                       |
|     svc-members            | yes      | value: none - security device IP list start block                                                     |
|       - [ip]               | yes      | value: IP of layer 3 security device.                                                                 |
|       - [ip]               | yes      | value: IP of layer 3 security device.                                                                 |

**Standalone example**:

```
name: layer3a service
desc: Layer 3 service (b)
host: localhost
user: admin
password: admin
service:
  type: layer3
  name: layer3b
  state: present
  
  sslo-side-net:
    entry-interface: 1.2
    entry-self: 198.19.2.50/25
    entry-tag: 100
    return-interface: 1.2
    return-self: 198.19.2.140/25
    return-tag: 101
  
  svc-side-net:
    entry-interface: 1.3
    entry-self: 198.19.64.7/25
    entry-tag: 10
    return-interface: 1.3
    return-self: 198.19.64.245/25
    return-tag: 20
  
  svc-members:
    - 198.19.64.65
```

**HA example**: (a separate configuration YAML file is needed for each L4 LB peer)

*Also note that the SSLO-side return interface does not require a floating self-IP*

```
name: layer3a service
desc: Layer 3 service (b)
host: localhost
user: admin
password: admin
service:
  type: layer3
  name: layer3b
  state: absent
  
  sslo-side-net:
    entry-interface: 1.2
    entry-self: 198.19.2.40/25
    entry-float: 198.19.2.50/25 
    entry-tag: 100
    return-interface: 1.2
    return-self: 198.19.2.140/25
    return-tag: 101
  
  svc-side-net:
    entry-interface: 1.3
    entry-self: 198.19.64.6/25
    entry-float: 198.19.64.7/25
    entry-tag: 10
    return-interface: 1.3
    return-self: 198.19.64.240/25
    return-float: 198.19.64.245/25
    return-tag: 20
  
  svc-members:
    - 198.19.64.65
```


### Layer 2 security service YAML definition
The 


### HTTP explicit security service YAML definition
The 


### HTTP transparent security service YAML definition
The 


### ICAP security service YAML definition
The 

