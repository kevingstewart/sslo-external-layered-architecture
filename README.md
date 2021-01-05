# F5 SSL Orchestrator External Layered Architecture
A configuration scheme and toolset to deploy SSL Orchestrator in an external layered (load balanced) architecture.

### Version support
This utility works on BIG-IP 14.1 and above, SSL Orchestrator 5.x and above.

### Description 
In the traditional SSL Orchestrator model, a single or HA pair of F5 devices is inserted inline of the traffic flow, and security services attach directly (or indirectly) to these. At the very least, this dictates the size of appliances used to facilitate the full traffic load requirement. And as with any such deployment, if your requirements increase beyond this capacity, you're forced to forklift upgrade. An alternative, scalable approach is to insert SSL Orchestrator appliances in a load balanced configuration (behind a separate L4 load balancer). The frontend appliance is handling L4-only traffic, so its throughput will naturally be much higher, while SSL Orchestrator devices can be added at will as throughput requirements increase.

![SSL Orchestrator External Layered Architecture](images/images1.png)

An added benefit is that a separate "escape" path can be created in the event of a catastrophic failure in the security stack, to maintain availability (if required). This approach does have a disadvantage though, as it becomes more complex to share the security devices between these now standalone SSL Orchestrator appliances. Layer 2 devices require a smart switch fabric between them and the F5 to offload 802.1Q tagged traffic, and layer 3 devices must support policy routing (all to ensure routing back to the correct F5 appliance).

Another option exists, however, by 

![SSL Orchestrator External Layered Architecture - improved](images/images2.png)

### Toolset
- Edit the configu
