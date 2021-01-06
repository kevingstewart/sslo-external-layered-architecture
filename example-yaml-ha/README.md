Please find included example YAML files for each service type. Note that the primary difference between these and their counterpart standalone configurations is the addition of floating self-IPs.

Also note that in an HA environment, all of the respective self-IPs must be unique between the L4 LB HA peers. The floating IPs should however be the same.
