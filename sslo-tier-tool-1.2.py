#!/usr/bin/python2.7

#### SSL Orchestrator External Tiered Architecture Helper Utility #########
#### Author: Kevin Stewart, Sr. SSA, F5 Networks
#### Date: 12/2020
#### Version: 1.2
#### Purpose: This tool automates the creation of service objects on a BIG-IP LTM to act as a "proxy" for SSLO security services in an 
####    external tiered architecture (physical LTM in front of load balanced standalone SSLO instances). The tool creates appropriate 
####    "sslo-side" (SSLO-to-LTM) and "svc-side" (LTM-to-services) VLANs, self-IPs, pools, VIPs, rules, etc. SSLO service configurations 
####    need only define a single device that is the sslo-side interface of this BIG-IP LTM. The LTM then handles traffic distribution
####    to the respective security devices. Configuration state for each security service is maintained in YAML source-of-truth files.
####    Note that updating a security service configuration is a volatile action that may interrupt traffic (momentarily).
####
#### Updates:
####    1.2: support for interface lists
####
#### Instructions: execute the command with a "--file" option followed by the name of a service configuration YAML file
####    ex. python sslo-tier-tool.py --file icapservice1.yml
####
####    Please refer to (https://github.com/kevingstewart/sslo-external-layered-architecture) for detailed information on the use of this tool and service configuration YAML syntax.


## Imports
from yaml import load, safe_load, dump
from argparse import ArgumentParser
import sys, json, requests, time, logging, random


## Disable certificate warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


## Enabled logging to file
#logging.basicConfig(filename='/var/log/sslo.log', encoding='utf-8', level=logging.INFO)


## Set global variables
global configs


## error routine
def error_exit(msg):
    print(msg)
    print("\nExiting\n\n")
    sys.exit()


## create sslo-tier-datagroup (mapping table)
def sslo_datagroup(user, password, host):    
    s = requests.session()
    s.auth = (user, password)
    s.verify = False
    s.headers.update({'Content-Type':'application/json'})
    resp = s.get("https://" + host + "/mgmt/tm/ltm/data-group/internal/sslo-tier-datagroup").json()
    if "selfLink" not in resp:
        datastr = {"name":"sslo-tier-datagroup","type":"string"}
        s.post("https://" + host + "/mgmt/tm/ltm/data-group/internal", data=json.dumps(datastr))


## create library rule
def sslo_library_rule(user, password, host):    
    s = requests.session()
    s.auth = (user, password)
    s.verify = False
    s.headers.update({'Content-Type':'application/json'})
    resp = s.get("https://" + host + "/mgmt/tm/ltm/rule/sslo-tier-library").json()
    if "selfLink" not in resp:
        #datastr = {"name":"sslo-tier-library","apiAnonymous":"proc set_data { service } { table set \"${service}_[IP::client_addr]:[TCP::client_port]:[IP::local_addr]:[TCP::local_port]\" [LINK::lasthop] 10 }\nproc get_data { service } { set tuple \"${service}_[IP::client_addr]:[TCP::client_port]:[IP::local_addr]:[TCP::local_port]\" ; if { ${tuple} contains \"%\" } { set filter [findstr ${tuple} \"%\" 1 \":\"] ; set tuple [string map [list \"%${filter}\" \"\"] ${tuple}] } ; if { [set flowkey [class lookup \"${service}:[table lookup ${tuple}]\" sslo-tier-datagroup]] ne \"\" } { return ${flowkey} }}"}
        datastr = {"name":"sslo-tier-library","apiAnonymous":"proc set_data { service value } { table set \"${service}_${value}\" [LINK::lasthop] 10 }\nproc get_data { service value } { set tuple \"${service}_${value}\" ; if { ${tuple} contains \"%\" } { set filter [findstr ${tuple} \"%\" 1 \":\"] ; set tuple [string map [list \"%${filter}\" \"\"] ${tuple}] } ; if { [set flowkey [class lookup \"${service}:[table lookup ${tuple}]\" sslo-tier-datagroup]] ne \"\" } { return ${flowkey} }}"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))


## reset/delete objects procedure
def reset_objects(host, user, password, name):
    ## set number of iterations (number of times to try to delete objects - transactions will otherwise fail if objects exist)
    itertask = 5

    ## set number of seconds to pause after deleting an object (might be useful to tweak for BIG-IPs under heavy load)
    pause = 1
    
    s = requests.session()
    s.auth = (user, password)
    s.verify = False
    s.headers.update({'Content-Type':'application/json'})

    ## virtual servers
    counter = 1
    while counter < itertask:
        resp = s.get("https://" + host + "/mgmt/tm/ltm/virtual").json()
        obj_exists = 0
        for j in resp["items"]:
            if "svc-" + name + "-" in j["name"]:
                obj_exists = 1
                s.delete("https://" + host + "/mgmt/tm/ltm/virtual/" + j["name"])
        if not obj_exists:
            break
        time.sleep(pause)
        counter += 1

    ## pools
    counter = 1
    while counter < itertask:
        resp = s.get("https://" + host + "/mgmt/tm/ltm/pool").json()
        obj_exists = 0
        for j in resp["items"]:
            if "svc-" + name + "-" in j["name"]:
                obj_exists = 1
                s.delete("https://" + host + "/mgmt/tm/ltm/pool/" + j["name"])
        if not obj_exists:
            break
        time.sleep(pause)
        counter += 1

    ## snatpools
    counter = 1
    while counter < itertask:
        resp = s.get("https://" + host + "/mgmt/tm/ltm/snatpool").json()
        obj_exists = 0
        for j in resp["items"]:
            if "svc-" + name + "-" in j["name"]:
                obj_exists = 1
                s.delete("https://" + host + "/mgmt/tm/ltm/snatpool/" + j["name"])
        if not obj_exists:
            break
        time.sleep(pause)
        counter += 1

    ## monitors
    counter = 1
    while counter < itertask:
        resp = s.get("https://" + host + "/mgmt/tm/ltm/monitor/gateway-icmp").json()
        obj_exists = 0
        for j in resp["items"]:
            if "svc-" + name + "-" in j["name"]:
                obj_exists = 1
                s.delete("https://" + host + "/mgmt/tm/ltm/monitor/gateway-icmp/" + j["name"])
        if not obj_exists:
            break
        time.sleep(pause)
        counter += 1

    ## rules
    counter = 1
    while counter < itertask:
        resp = s.get("https://" + host + "/mgmt/tm/ltm/rule").json()
        obj_exists = 0
        for j in resp["items"]:
            if "svc-" + name + "-" in j["name"]:
                obj_exists = 1
                s.delete("https://" + host + "/mgmt/tm/ltm/rule/" + j["name"])
        if not obj_exists:
            break
        time.sleep(pause)
        counter += 1

    ## self-ips
    counter = 1
    while counter < itertask:
        resp = s.get("https://" + host + "/mgmt/tm/net/self").json()
        obj_exists = 0
        for j in resp["items"]:
            if "svc-" + name + "-" in j["name"]:
                obj_exists = 1
                s.delete("https://" + host + "/mgmt/tm/net/self/" + j["name"])
        if not obj_exists:
            break
        time.sleep(pause)
        counter += 1

    ## vlans
    counter = 1
    while counter < itertask:
        resp = s.get("https://" + host + "/mgmt/tm/net/vlan").json()
        obj_exists = 0
        for j in resp["items"]:
            if "svc-" + name + "-" in j["name"]:
                obj_exists = 1
                s.delete("https://" + host + "/mgmt/tm/net/vlan/" + j["name"])
        if not obj_exists:
            break
        time.sleep(pause)
        counter += 1

    ## route-domains
    counter = 1
    while counter < itertask:
        resp = s.get("https://" + host + "/mgmt/tm/net/route-domain").json()
        obj_exists = 0
        for j in resp["items"]:
            if "svc-" + name + "-" in j["name"]:
                obj_exists = 1
                s.delete("https://" + host + "/mgmt/tm/net/route-domain/" + j["name"])
        if not obj_exists:
            break
        time.sleep(pause)
        counter += 1


## vlan descriptor function - returns POST data string value for VLAN creation
def vlan_descriptor(configs, name, side, entry_return, vname):
    ## configs = configs object
    ## name = service name
    ## side = "sslo-side-net" or "svc-side-net"
    ## entry_return = "entry" or "return"
    ## vname = vlan name suffix

    ## format input strings
    tag = entry_return + "-tag"
    interfaces = entry_return + "-interface"
    vlan_name = "svc-" + name + "-" + vname

    ## check if config contains tag value
    if tag in configs["service"][side].keys():
        this_tag = configs["service"][side][tag]
    else:
        this_tag = 0

    ## create an interface list
    if isinstance(configs["service"][side][interfaces], list):
        interface_list = []
        for x in configs["service"][side][interfaces]:
            if this_tag == 0:
                interface_list.append({"name":"" + str(x) + "","tagged":False})
            else:
                interface_list.append({"name":"" + str(x) + "","tagged":True})

    else:
        interface_list = []
        entry_interface = configs["service"][side][interfaces]
        if this_tag == 0:
            interface_list.append({"name":"" + str(entry_interface) + "","tagged":False})
        else:
            interface_list.append({"name":"" + str(entry_interface) + "","tagged":True})

    ## create the full datastr
    if this_tag == 0:
        datastr = {"name":"" + vlan_name + "","interfaces":interface_list}
    else:
        datastr = {"name":"" + vlan_name + "","tag":"" + str(this_tag) + "","interfaces":interface_list}

    return datastr


## layer 3 service procedures
def service_layer3(configs):
    ## state value
    if "state" in configs["service"].keys():
        state = configs["service"]["state"]
    else:
        state = "present"

    ## name value
    if "name" in configs["service"].keys():
        name = configs["service"]["name"]
    else:
        error_exit("No service name supplied in YAML")

    ## host value
    if "host" in configs.keys():
        host = configs["host"]
    else:
        error_exit("No host name supplied in YAML")

    ## user value
    if "user" in configs.keys():
        user = configs["user"]
    else:
        error_exit("No username supplied in YAML")

    ## password value
    if "password" in configs.keys():
        password = configs["password"]
    else:
        error_exit("No password supplied in YAML")

    ## process state
    if state == "absent":
        #### Delete named objects
        print("Deleting Layer 3 Service Objects")

        ## reset any possible existing objects
        reset_objects(host, user, password, name)


    elif state == "present":
        #### Parse YAML values ####
        print("Creating Layer 3 Service Objects")

        ## sslo-side-net and svc-side-net base keys
        if "sslo-side-net" in configs["service"].keys() and "svc-side-net" in configs["service"].keys():
            pass
        else:
            error_exit("Missing sslo-side-net or svc-side-net keys.")

        ## sslo-side-net values
        if "entry-interface" in configs["service"]["sslo-side-net"].keys() and "entry-self" in configs["service"]["sslo-side-net"].keys() and "return-interface" in configs["service"]["sslo-side-net"].keys() and "return-self" in configs["service"]["sslo-side-net"].keys():
            sslo_side_net_entry_self = configs["service"]["sslo-side-net"]["entry-self"]
            sslo_side_net_return_self = configs["service"]["sslo-side-net"]["return-self"]
        else:
            error_exit("Missing entry and/or return sslo-side interface/self values.")

        ## svc-side-net values
        if "entry-interface" in configs["service"]["svc-side-net"].keys() and "entry-self" in configs["service"]["svc-side-net"].keys() and "return-interface" in configs["service"]["svc-side-net"].keys() and "return-self" in configs["service"]["svc-side-net"].keys():
            svc_side_net_entry_self = configs["service"]["svc-side-net"]["entry-self"]
            svc_side_net_return_self = configs["service"]["svc-side-net"]["return-self"]
        else:
            error_exit("Missing entry and/or return svc-side interface/self values.")
       
        ## svc-members values
        if "svc-members" in configs["service"].keys():
            mbrstr = []
            for x in configs["service"]["svc-members"]:
                mbrdict = {"name":"" + x + ":any","address":"" + x + ""}
                mbrstr.append(mbrdict)
        else:
            error_exit("Missing svc-members key.")


        #### Create or modify named objects ####
        
        ## make sure the data group exists
        sslo_datagroup(user, password, host)

        ## create the library iRules
        sslo_library_rule(user, password, host)

        ## create tmsh transaction to build network objects
        s = requests.session()
        s.auth = (user, password)
        s.verify = False
        s.headers.update({'Content-Type':'application/json'})

        ## reset any possible existing objects
        reset_objects(host, user, password, name)

        ## make sure nodes don't exist
        for x in configs["service"]["svc-members"]:
            vals = x.split(":")
            resp = s.get("https://" + host + "/mgmt/tm/node/" + vals[0] + "").json()
            if "kind" in resp:
                s.delete("https://" + host + "/mgmt/tm/node/" + vals[0] + "")

        ## build transaction
        tx = s.post("https://" + host + "/mgmt/tm/transaction", data=json.dumps({})).json()['transId']
        s.headers.update({'X-F5-REST-Coordination-Id': str(tx)})

        ## build objects - sslo-side entry vlan
        datastr = vlan_descriptor(configs, name, "sslo-side-net", "entry", "sslo-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## sslo-side return vlan
        datastr = vlan_descriptor(configs, name, "sslo-side-net", "return", "sslo-side-out")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## svc-side entry vlan
        datastr = vlan_descriptor(configs, name, "svc-side-net", "entry", "svc-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## svc-side return vlan
        datastr = vlan_descriptor(configs, name, "svc-side-net", "return", "svc-side-out")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## sslo-side entry self
        datastr = {"name":"svc-" + name + "-sslo-side-in","vlan":"svc-" + name + "-sslo-side-in","address":"" + sslo_side_net_entry_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## sslo-side return self
        datastr = {"name":"svc-" + name + "-sslo-side-out","vlan":"svc-" + name + "-sslo-side-out","address":"" + sslo_side_net_return_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## sslo-side entry float self
        if "entry-float" in configs["service"]["sslo-side-net"].keys():
            datastr = {"name":"svc-" + name + "-sslo-side-in-float","vlan":"svc-" + name + "-sslo-side-in","address":"" + configs["service"]["sslo-side-net"]["entry-float"] + "","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side entry self
        datastr = {"name":"svc-" + name + "-svc-side-in","vlan":"svc-" + name + "-svc-side-in","address":"" + svc_side_net_entry_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side return self
        datastr = {"name":"svc-" + name + "-svc-side-out","vlan":"svc-" + name + "-svc-side-out","address":"" + svc_side_net_return_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side entry float self
        if "entry-float" in configs["service"]["svc-side-net"].keys():
            datastr = {"name":"svc-" + name + "-svc-side-in-float","vlan":"svc-" + name + "-svc-side-in","address":"" + configs["service"]["svc-side-net"]["entry-float"] + "","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side return float self
        if "return-float" in configs["service"]["svc-side-net"].keys():
            datastr = {"name":"svc-" + name + "-svc-side-out-float","vlan":"svc-" + name + "-svc-side-out","address":"" + configs["service"]["svc-side-net"]["return-float"] + "","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## monitor
        datastr = {"name":"svc-" + name + "-monitor","interval":3,"timeout":7}
        s.post("https://" + host + "/mgmt/tm/ltm/monitor/gateway-icmp", data=json.dumps(datastr))

        ## service pool
        datastr = {"name":"svc-" + name + "-service-pool","monitor":"/Common/svc-" + name + "-monitor","members":mbrstr}
        s.post("https://" + host + "/mgmt/tm/ltm/pool", data=json.dumps(datastr))

        ## service rules
        #datastr = {"name":"svc-" + name + "-sslo-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { call sslo-tier-library::set_data \"" + name + "\" }"}
        datastr = {"name":"svc-" + name + "-sslo-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { call sslo-tier-library::set_data \"" + name + "\" \"[IP::client_addr]:[TCP::client_port]:[IP::local_addr]:[TCP::local_port]\" }"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        #datastr = {"name":"svc-" + name + "-svc-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { node [call sslo-tier-library::get_data \"" + name + "\"] }"}
        datastr = {"name":"svc-" + name + "-svc-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { catch { node [call sslo-tier-library::get_data \"" + name + "\" \"[IP::client_addr]:[TCP::client_port]:[IP::local_addr]:[TCP::local_port]\"] }}"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        ## monitor rule
        datastr = {"name":"svc-" + name + "-monitor-rule","apiAnonymous":"when FLOW_INIT { if { [active_members svc-" + name + "-service-pool] < 1 } {drop} }"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        ## service virtuals
        datastr = {"name":"svc-" + name + "-sslo-side","source":"0.0.0.0/0","destination":"0.0.0.0:0","mask":"any","pool":"svc-" + name + "-service-pool","profiles":"/Common/fastL4","rules":["svc-" + name + "-sslo-side-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        datastr = {"name":"svc-" + name + "-svc-side","source":"0.0.0.0/0","destination":"0.0.0.0:0","mask":"any","profiles":"/Common/fastL4","rules":["svc-" + name + "-svc-side-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-svc-side-out"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## monitor virtual
        if "entry-float" in configs["service"]["sslo-side-net"].keys():
            monitor_ip = configs["service"]["sslo-side-net"]["entry-float"].split("/")
        else:
            monitor_ip = configs["service"]["sslo-side-net"]["entry-self"].split("/")

        datastr = {"name":"svc-" + name + "-monitor","source":"0.0.0.0/0","destination":monitor_ip[0] + ":9999","mask":"255.255.255.255","profiles":"/Common/tcp","ip-protocol":"tcp","rules":["svc-" + name + "-monitor-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## commit transaction
        del s.headers['X-F5-REST-Coordination-Id']
        #result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()['state']
        result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()
        print(result)

    else:
        error_exit("Incorrect state value entered.")


## layer 2 service procedures
def service_layer2(configs):

    ## state value
    if "state" in configs["service"].keys():
        state = configs["service"]["state"]
    else:
        state = "present"

    ## name value
    if "name" in configs["service"].keys():
        name = configs["service"]["name"]
    else:
        error_exit("No service name supplied in YAML")

    ## host value
    if "host" in configs.keys():
        host = configs["host"]
    else:
        error_exit("No host name supplied in YAML")

    ## user value
    if "user" in configs.keys():
        user = configs["user"]
    else:
        error_exit("No username supplied in YAML")

    ## password value
    if "password" in configs.keys():
        password = configs["password"]
    else:
        error_exit("No password supplied in YAML")

    ## process state
    if state == "absent":
        print("Deleting Layer 2 Service Objects")
        
        ## reset any possible existing objects
        reset_objects(host, user, password, name)

    elif state == "present":
        print("Creating Layer 2 Service Objects")
        #### Parse YAML values ####

        ## sslo-side-net and svc-side-net base keys
        if "sslo-side-net" in configs["service"].keys() and "svc-side-net" in configs["service"].keys():
            pass
        else:
            error_exit("Missing sslo-side-net or svc-side-net keys.")

        ## sslo-side-net values
        if "entry-interface" in configs["service"]["sslo-side-net"].keys() and "entry-self" in configs["service"]["sslo-side-net"].keys() and "return-interface" in configs["service"]["sslo-side-net"].keys() and "return-self" in configs["service"]["sslo-side-net"].keys():
            sslo_side_net_entry_self = configs["service"]["sslo-side-net"]["entry-self"]
            sslo_side_net_return_self = configs["service"]["sslo-side-net"]["return-self"]
        else:
            error_exit("Missing entry and/or return sslo-side interface/self values.")

        ## svc-side-net values
        svc_side_net_list = []
        for x in configs["service"]["svc-side-net"]:
            if "entry-interface" in x and "return-interface" in x and "name" in x:
                svc_side_net_list.append(x)
            else:
                error_exit("Missing entry and/or return svc-side interface/self values.")

        #### Create or modify named objects ####
        
        ## make sure the data group exists
        sslo_datagroup(user, password, host)

        ## create the library iRules
        sslo_library_rule(user, password, host)

        ## create tmsh transaction to build network objects
        s = requests.session()
        s.auth = (user, password)
        s.verify = False
        s.headers.update({'Content-Type':'application/json'})

        ## reset any possible existing objects
        reset_objects(host, user, password, name)

        ## build transaction
        tx = s.post("https://" + host + "/mgmt/tm/transaction", data=json.dumps({})).json()['transId']
        s.headers.update({'X-F5-REST-Coordination-Id': str(tx)})

        ## build objects - sslo-side entry vlan
        datastr = vlan_descriptor(configs, name, "sslo-side-net", "entry", "sslo-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## sslo-side return vlan
        datastr = vlan_descriptor(configs, name, "sslo-side-net", "return", "sslo-side-out")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## sslo-side entry self
        datastr = {"name":"svc-" + name + "-sslo-side-in","vlan":"svc-" + name + "-sslo-side-in","address":"" + sslo_side_net_entry_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## sslo-side return self
        datastr = {"name":"svc-" + name + "-sslo-side-out","vlan":"svc-" + name + "-sslo-side-out","address":"" + sslo_side_net_return_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## sslo-side entry float self
        if "entry-float" in configs["service"]["sslo-side-net"].keys():
            datastr = {"name":"svc-" + name + "-sslo-side-in-float","vlan":"svc-" + name + "-sslo-side-in","address":"" + configs["service"]["sslo-side-net"]["entry-float"] + "","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## create source-side pool list
        svc_pool = []
        counter = 1

        ## define third octet (same for all devices in this service) as hash of the service name
        third_octet = (hash(name) % 252) + 1

        ## create svc-side objects
        for x in svc_side_net_list:
            ## We will algorithmically define the IP subnets, self-IPs, and route domains for each L2 device so that the user doesn't have to define them.
            ## The base subnet for all layer 2 devices is 198.18.0.0/16
            ## The third octet is defined (for all devices in a service) as a hash of the service name (mod 252 + 1) - ex. 198.18.1.y
            ## The route domain is defined (for each device) as a hash of the service name + device name (mod 50000 + 10000)
            ## The fourth octet is defined (for each device) from a /29 mapping table based on the order of the device in the list
            ## The active device in an HA pair (or single device) uses the first and second IPs in the /29 subnet as entry and return self IPs
            ## The standby device in an HA pair uses the third and fourth IPs in the /29 subnet as entry and return self IPs
            ## The last IP in the /29 subnet is used as the floating (return) self IP
            ## Using this hash method guarantees that each BIG-IP in an HA pair uses the same values (other than entry/return self offsets)

            ## define the route domain (per device) as hash of service name + device name
            route_domain = (hash(name + x["name"]) % 50000) + 10000

            ## determine if this is the active or standby box in HA config, or just active box in standalone - determines the IPs used in the selected subnet
            resp = s.get("https://" + host + "/mgmt/tm/cm/failover-status").json()["entries"]["https://localhost/mgmt/tm/cm/failover-status/0"]["nestedStats"]["entries"]["status"]["description"]
            ha_state = (1, 2)[resp == "ACTIVE"]

            ## select a /29 subnet range based on number of device in the list of devices (from counter)
            net_map = {1:"1:6",2:"9:14",3:"17:22",4:"25:30",5:"33:38",6:"41:46",7:"49:54",8:"57-62",9:"65:70",10:"73:78",11:"81:86",12:"89:94",13:"97:102",14:"104:110",15:"113:118"}
            subnet = net_map[counter]

            ## define the entry and return IPs based on third octet and ha_state
            ip_list = subnet.split(":")
            if ha_state == 1:
                entry_ip = "198.18." + str(third_octet) + "." + str(ip_list[0])
                return_ip = "198.18." + str(third_octet) + "." + str(int(ip_list[0]) + 1) 
            else:
                entry_ip = "198.18." + str(third_octet) + "." + str(int(ip_list[0]) + 2)
                return_ip = "198.18." + str(third_octet) + "." + str(int(ip_list[0]) + 3)

            ## floating (return) IP is the last number in the /29 subnet range
            float_ip = "198.18." + str(third_octet) + "." + str(ip_list[-1])

            ## pool member is the floating IP of each device
            svc_pool.append(float_ip)

            ## increment the counter
            counter += 1

            ## svc entry vlan
            if "entry-tag" not in x:
                datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-in","interfaces":"" + str(x["entry-interface"]) + ""}
                s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))
            else:
                datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-in","tag":"" + str(x["entry-tag"]) + "","interfaces":[{"name":"" + str(x["entry-interface"]) + "","tagged":True}]}
                s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

            ## svc return vlan
            if "return-tag" not in x:
                datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-out","interfaces":"" + str(x["return-interface"]) + ""}
                s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))
            else:
                datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-out","tag":"" + str(x["return-tag"]) + "","interfaces":[{"name":"" + str(x["return-interface"]) + "","tagged":True}]}
                s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

            ## svc return route domain
            datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-rd","parent":0,"id":str(route_domain),"vlans":["svc-" + name + "-" + x["name"] + "-svc-out"]}
            s.post("https://" + host + "/mgmt/tm/net/route-domain", data=json.dumps(datastr))

            ## svc entry self
            datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-in","vlan":"svc-" + name + "-" + x["name"] + "-svc-in","address":"" + str(entry_ip) + "/29","allowService":"default","trafficGroup":"traffic-group-local-only"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

            ## svc return self
            datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-out","vlan":"svc-" + name + "-" + x["name"] + "-svc-out","address":"" + str(return_ip) + "%" + str(route_domain) + "/29","allowService":"default","trafficGroup":"traffic-group-local-only"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

            ## svc return floating self
            datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-out-float","vlan":"svc-" + name + "-" + x["name"] + "-svc-out","address":"" + str(float_ip) + "%" + str(route_domain) + "/29","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

            ## svc return rule
            #datastr = {"name":"svc-" + name + "-svc-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { node [call sslo-tier-library::get_data \"" + name + "\"] }"}
            datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-out-rule","apiAnonymous":"when CLIENT_ACCEPTED { catch { node [call sslo-tier-library::get_data \"" + name + "\" \"[IP::client_addr]:[TCP::client_port]:[IP::local_addr]:[TCP::local_port]\"] }}"}
            s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

            ## svc return virtual
            datastr = {"name":"svc-" + name + "-" + x["name"] + "-svc-out","source":"0.0.0.0%" + str(route_domain) + "/0","destination":"0.0.0.0%" + str(route_domain) + ":0","mask":"any","profiles":"/Common/fastL4","rules":["svc-" + name + "-" + x["name"] + "-svc-out-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-" + x["name"] + "-svc-out"],"vlansEnabled":True}
            s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## svc entry rule
        #datastr = {"name":"svc-" + name + "-sslo-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { call sslo-tier-library::set_data \"" + name + "\" }"}
        datastr = {"name":"svc-" + name + "-svc-in-rule","apiAnonymous":"when CLIENT_ACCEPTED { call sslo-tier-library::set_data \"" + name + "\" \"[IP::client_addr]:[TCP::client_port]:[IP::local_addr]:[TCP::local_port]\" }"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        ## monitor
        datastr = {"name":"svc-" + name + "-monitor","interval":3,"timeout":7}
        s.post("https://" + host + "/mgmt/tm/ltm/monitor/gateway-icmp", data=json.dumps(datastr))

        ## svc entry pool
        mbrstr = []
        for ip in svc_pool:
            mbrdict = {"name":"" + ip + ":any","address":"" + ip + ""}
            mbrstr.append(mbrdict)

        datastr = {"name":"svc-" + name + "-svc-pool","monitor":"/Common/svc-" + name + "-monitor","members":mbrstr}
        #datastr = {"name":"svc-" + name + "-svc-pool","monitor":"/Common/gateway_icmp","members":mbrstr}
        s.post("https://" + host + "/mgmt/tm/ltm/pool", data=json.dumps(datastr))

        ## monitor rule
        datastr = {"name":"svc-" + name + "-monitor-rule","apiAnonymous":"when FLOW_INIT { if { [active_members svc-" + name + "-svc-pool] < 1 } {drop} }"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        ## svc entry vip
        datastr = {"name":"svc-" + name + "-svc-in","source":"0.0.0.0/0","destination":"0.0.0.0:0","mask":"any","pool":"svc-" + name + "-svc-pool","profiles":"/Common/fastL4","rules":["svc-" + name + "-svc-in-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## monitor virtual
        if "entry-float" in configs["service"]["sslo-side-net"].keys():
            monitor_ip = configs["service"]["sslo-side-net"]["entry-float"].split("/")
        else:
            monitor_ip = configs["service"]["sslo-side-net"]["entry-self"].split("/")

        datastr = {"name":"svc-" + name + "-monitor","source":"0.0.0.0/0","destination":monitor_ip[0] + ":9999","mask":"255.255.255.255","profiles":"/Common/tcp","ip-protocol":"tcp","rules":["svc-" + name + "-monitor-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## commit transaction
        del s.headers['X-F5-REST-Coordination-Id']
        result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()['state']
        #result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()
        print(result)

    else:
        error_exit("Incorrect state value entered.")


## http service procedures
def service_http_explicit(configs):
    ## state value
    if "state" in configs["service"].keys():
        state = configs["service"]["state"]
    else:
        state = "present"

    ## name value
    if "name" in configs["service"].keys():
        name = configs["service"]["name"]
    else:
        error_exit("No service name supplied in YAML")

    ## host value
    if "host" in configs.keys():
        host = configs["host"]
    else:
        error_exit("No host name supplied in YAML")

    ## user value
    if "user" in configs.keys():
        user = configs["user"]
    else:
        error_exit("No username supplied in YAML")

    ## password value
    if "password" in configs.keys():
        password = configs["password"]
    else:
        error_exit("No password supplied in YAML")

    ## process state
    if state == "absent":
        #### Delete named objects
        print("Deleting HTTP Explicit Proxy Service Objects")
        
        ## reset any possible existing objects
        reset_objects(host, user, password, name)

    elif state == "present":
        #### Parse YAML values ####
        print("Creating HTTP Explicit Proxy Service Objects")

        ## sslo-side-net and svc-side-net base keys
        if "sslo-side-net" in configs["service"].keys() and "svc-side-net" in configs["service"].keys():
            pass
        else:
            error_exit("Missing sslo-side-net or svc-side-net keys.")

        ## sslo-side-net values
        if "entry-interface" in configs["service"]["sslo-side-net"].keys() and "entry-self" in configs["service"]["sslo-side-net"].keys() and "entry-ip" in configs["service"]["sslo-side-net"].keys() and "return-interface" in configs["service"]["sslo-side-net"].keys() and "return-self" in configs["service"]["sslo-side-net"].keys():
            sslo_side_net_entry_self = configs["service"]["sslo-side-net"]["entry-self"]
            sslo_side_net_entry_ip = configs["service"]["sslo-side-net"]["entry-ip"]
            sslo_side_net_return_self = configs["service"]["sslo-side-net"]["return-self"]
        else:
            error_exit("Missing entry and/or return sslo-side interface/self values.")

        ## svc-side-net values
        if "entry-interface" in configs["service"]["svc-side-net"].keys() and "entry-self" in configs["service"]["svc-side-net"].keys() and "return-interface" in configs["service"]["svc-side-net"].keys() and "return-self" in configs["service"]["svc-side-net"].keys():
            svc_side_net_entry_self = configs["service"]["svc-side-net"]["entry-self"]
            svc_side_net_return_self = configs["service"]["svc-side-net"]["return-self"]
        else:
            error_exit("Missing entry and/or return svc-side interface/self values.")
        
        ## svc-members values
        if "svc-members" in configs["service"].keys():
            mbrstr = []
            for x in configs["service"]["svc-members"]:
                vals = x.split(":")
                mbrdict = {"name":"" + x + ":" + vals[1] + "","address":"" + vals[0] + ""}
                mbrstr.append(mbrdict)
        else:
            error_exit("Missing svc-members key.")


        #### Create or modify named objects ####
        
        ## make sure the data group exists
        sslo_datagroup(user, password, host)

        ## create the library iRules
        sslo_library_rule(user, password, host)

        ## create tmsh transaction to build network objects
        s = requests.session()
        s.auth = (user, password)
        s.verify = False
        s.headers.update({'Content-Type':'application/json'})

        ## reset any possible existing objects
        reset_objects(host, user, password, name)

        ## make sure nodes don't exist
        for x in configs["service"]["svc-members"]:
            vals = x.split(":")
            resp = s.get("https://" + host + "/mgmt/tm/node/" + vals[0] + "").json()
            if "kind" in resp:
                s.delete("https://" + host + "/mgmt/tm/node/" + vals[0] + "")

        ## build transaction
        tx = s.post("https://" + host + "/mgmt/tm/transaction", data=json.dumps({})).json()['transId']
        s.headers.update({'X-F5-REST-Coordination-Id': str(tx)})

        ## build objects - sslo-side entry vlan
        datastr = vlan_descriptor(configs, name, "sslo-side-net", "entry", "sslo-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## sslo-side return vlan
        datastr = vlan_descriptor(configs, name, "sslo-side-net", "return", "sslo-side-out")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## svc-side entry vlan
        datastr = vlan_descriptor(configs, name, "svc-side-net", "entry", "svc-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## svc-side return vlan
        datastr = vlan_descriptor(configs, name, "svc-side-net", "return", "svc-side-out")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## sslo-side entry self
        datastr = {"name":"svc-" + name + "-sslo-side-in","vlan":"svc-" + name + "-sslo-side-in","address":"" + sslo_side_net_entry_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## sslo-side return self
        datastr = {"name":"svc-" + name + "-sslo-side-out","vlan":"svc-" + name + "-sslo-side-out","address":"" + sslo_side_net_return_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side entry self
        datastr = {"name":"svc-" + name + "-svc-side-in","vlan":"svc-" + name + "-svc-side-in","address":"" + svc_side_net_entry_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side return self
        datastr = {"name":"svc-" + name + "-svc-side-out","vlan":"svc-" + name + "-svc-side-out","address":"" + svc_side_net_return_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side entry float self
        if "entry-float" in configs["service"]["svc-side-net"].keys():
            datastr = {"name":"svc-" + name + "-svc-side-in-float","vlan":"svc-" + name + "-svc-side-in","address":"" + configs["service"]["svc-side-net"]["entry-float"] + "","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side return float self
        if "return-float" in configs["service"]["svc-side-net"].keys():
            datastr = {"name":"svc-" + name + "-svc-side-out-float","vlan":"svc-" + name + "-svc-side-out","address":"" + configs["service"]["svc-side-net"]["return-float"] + "","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## monitor
        datastr = {"name":"svc-" + name + "-monitor","interval":3,"timeout":7}
        s.post("https://" + host + "/mgmt/tm/ltm/monitor/gateway-icmp", data=json.dumps(datastr))

        ## service pool
        datastr = {"name":"svc-" + name + "-service-pool","monitor":"/Common/svc-" + name + "-monitor","members":mbrstr}
        s.post("https://" + host + "/mgmt/tm/ltm/pool", data=json.dumps(datastr))

        ## service rules
        #datastr = {"name":"svc-" + name + "-sslo-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { call sslo-tier-library::set_data \"" + name + "\" }"}
        datastr = {"name":"svc-" + name + "-sslo-side-rule","apiAnonymous":"when HTTP_REQUEST { if { ![info exists randstr] } { set randstr [subst [string repeat {[format %c [expr {int(rand() * 26) + (rand() > .5 ? 97 : 65)}]]} 15]] } ; HTTP::header insert \"X-F5-SplitSession2\" ${randstr} ; call sslo-tier-library::set_data \"" + name + "\" ${randstr} }"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        #datastr = {"name":"svc-" + name + "-svc-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { node [call sslo-tier-library::get_data \"" + name + "\"] }"}
        datastr = {"name":"svc-" + name + "-svc-side-rule","apiAnonymous":"when HTTP_REQUEST { catch { node [call sslo-tier-library::get_data \"" + name + "\" [HTTP::header \"X-F5-SplitSession2\"]] }}"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        ## monitor rule
        datastr = {"name":"svc-" + name + "-monitor-rule","apiAnonymous":"when FLOW_INIT { if { [active_members svc-" + name + "-service-pool] < 1 } {drop} }"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        ## service virtuals
        datastr = {"name":"svc-" + name + "-sslo-side","source":"0.0.0.0/0","destination":"" + sslo_side_net_entry_ip + ":0","mask":"255.255.255.255","pool":"svc-" + name + "-service-pool","ipProtocol":"tcp","profiles":"/Common/http","rules":["svc-" + name + "-sslo-side-rule"],"translateAddress":"enabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        datastr = {"name":"svc-" + name + "-svc-side","source":"0.0.0.0/0","destination":"0.0.0.0:0","mask":"any","profiles":"/Common/http","rules":["svc-" + name + "-svc-side-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-svc-side-out"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## monitor virtual
        monitor_ip = configs["service"]["sslo-side-net"]["entry-ip"]
        datastr = {"name":"svc-" + name + "-monitor","source":"0.0.0.0/0","destination":monitor_ip + ":9999","mask":"255.255.255.255","profiles":"/Common/tcp","ip-protocol":"tcp","rules":["svc-" + name + "-monitor-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## commit transaction
        del s.headers['X-F5-REST-Coordination-Id']
        result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()['state']
        #result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()
        print(result)

    else:
        error_exit("Incorrect state value entered.")


def service_http_transparent(configs):
    ## state value
    if "state" in configs["service"].keys():
        state = configs["service"]["state"]
    else:
        state = "present"

    ## name value
    if "name" in configs["service"].keys():
        name = configs["service"]["name"]
    else:
        error_exit("No service name supplied in YAML")

    ## host value
    if "host" in configs.keys():
        host = configs["host"]
    else:
        error_exit("No host name supplied in YAML")

    ## user value
    if "user" in configs.keys():
        user = configs["user"]
    else:
        error_exit("No username supplied in YAML")

    ## password value
    if "password" in configs.keys():
        password = configs["password"]
    else:
        error_exit("No password supplied in YAML")

    ## process state
    if state == "absent":
        #### Delete named objects
        print("Deleting HTTP Transparent Service Objects")
        
        ## reset any possible existing objects
        reset_objects(host, user, password, name)


    elif state == "present":
        #### Parse YAML values ####
        print("Creating HTTP Transparent Service Objects")

        ## sslo-side-net and svc-side-net base keys
        if "sslo-side-net" in configs["service"].keys() and "svc-side-net" in configs["service"].keys():
            pass
        else:
            error_exit("Missing sslo-side-net or svc-side-net keys.")

        ## sslo-side-net values
        if "entry-interface" in configs["service"]["sslo-side-net"].keys() and "entry-self" in configs["service"]["sslo-side-net"].keys() and "return-interface" in configs["service"]["sslo-side-net"].keys() and "return-self" in configs["service"]["sslo-side-net"].keys():
            sslo_side_net_entry_self = configs["service"]["sslo-side-net"]["entry-self"]
            sslo_side_net_return_self = configs["service"]["sslo-side-net"]["return-self"]
        else:
            error_exit("Missing entry and/or return sslo-side interface/self values.")

        ## svc-side-net values
        if "entry-interface" in configs["service"]["svc-side-net"].keys() and "entry-self" in configs["service"]["svc-side-net"].keys() and "return-interface" in configs["service"]["svc-side-net"].keys() and "return-self" in configs["service"]["svc-side-net"].keys():
            svc_side_net_entry_self = configs["service"]["svc-side-net"]["entry-self"]
            svc_side_net_return_self = configs["service"]["svc-side-net"]["return-self"]
        else:
            error_exit("Missing entry and/or return svc-side interface/self values.")
        
        ## svc-members values
        if "svc-members" in configs["service"].keys():
            mbrstr = []
            for x in configs["service"]["svc-members"]:
                mbrdict = {"name":"" + x + ":any","address":"" + x + ""}
                mbrstr.append(mbrdict)
        else:
            error_exit("Missing svc-members key.")


        #### Create or modify named objects ####
        
        ## make sure the data group exists
        sslo_datagroup(user, password, host)

        ## create the library iRules
        sslo_library_rule(user, password, host)

        ## create tmsh transaction to build network objects
        s = requests.session()
        s.auth = (user, password)
        s.verify = False
        s.headers.update({'Content-Type':'application/json'})

        ## reset any possible existing objects
        reset_objects(host, user, password, name)

        ## make sure nodes don't exist
        for x in configs["service"]["svc-members"]:
            vals = x.split(":")
            resp = s.get("https://" + host + "/mgmt/tm/node/" + vals[0] + "").json()
            if "kind" in resp:
                s.delete("https://" + host + "/mgmt/tm/node/" + vals[0] + "")

        ## build transaction
        tx = s.post("https://" + host + "/mgmt/tm/transaction", data=json.dumps({})).json()['transId']
        s.headers.update({'X-F5-REST-Coordination-Id': str(tx)})

        ## build objects - sslo-side entry vlan
        datastr = vlan_descriptor(configs, name, "sslo-side-net", "entry", "sslo-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## sslo-side return vlan
        datastr = vlan_descriptor(configs, name, "sslo-side-net", "return", "sslo-side-out")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## svc-side entry vlan
        datastr = vlan_descriptor(configs, name, "svc-side-net", "entry", "svc-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## svc-side return vlan
        datastr = vlan_descriptor(configs, name, "svc-side-net", "return", "svc-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## sslo-side entry self
        datastr = {"name":"svc-" + name + "-sslo-side-in","vlan":"svc-" + name + "-sslo-side-in","address":"" + sslo_side_net_entry_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## sslo-side return self
        datastr = {"name":"svc-" + name + "-sslo-side-out","vlan":"svc-" + name + "-sslo-side-out","address":"" + sslo_side_net_return_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## sslo-side entry float self
        if "entry-float" in configs["service"]["sslo-side-net"].keys():
            datastr = {"name":"svc-" + name + "-sslo-side-in-float","vlan":"svc-" + name + "-sslo-side-in","address":"" + configs["service"]["sslo-side-net"]["entry-float"] + "","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side entry self
        datastr = {"name":"svc-" + name + "-svc-side-in","vlan":"svc-" + name + "-svc-side-in","address":"" + svc_side_net_entry_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side return self
        datastr = {"name":"svc-" + name + "-svc-side-out","vlan":"svc-" + name + "-svc-side-out","address":"" + svc_side_net_return_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side entry float self
        if "entry-float" in configs["service"]["svc-side-net"].keys():
            datastr = {"name":"svc-" + name + "-svc-side-in-float","vlan":"svc-" + name + "-svc-side-in","address":"" + configs["service"]["svc-side-net"]["entry-float"] + "","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side return float self
        if "return-float" in configs["service"]["svc-side-net"].keys():
            datastr = {"name":"svc-" + name + "-svc-side-out-float","vlan":"svc-" + name + "-svc-side-out","address":"" + configs["service"]["svc-side-net"]["return-float"] + "","allowService":"default","trafficGroup":"traffic-group-1"}
            s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## monitor
        datastr = {"name":"svc-" + name + "-monitor","interval":3,"timeout":7}
        s.post("https://" + host + "/mgmt/tm/ltm/monitor/gateway-icmp", data=json.dumps(datastr))

        ## service pool
        datastr = {"name":"svc-" + name + "-service-pool","monitor":"/Common/svc-" + name + "-monitor","members":mbrstr}
        s.post("https://" + host + "/mgmt/tm/ltm/pool", data=json.dumps(datastr))

        ## service rules
        #datastr = {"name":"svc-" + name + "-sslo-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { call sslo-tier-library::set_data \"" + name + "\" }"}
        datastr = {"name":"svc-" + name + "-sslo-side-rule","apiAnonymous":"when HTTP_REQUEST { if { ![info exists randstr] } { set randstr [subst [string repeat {[format %c [expr {int(rand() * 26) + (rand() > .5 ? 97 : 65)}]]} 15]] } ; HTTP::header insert \"X-F5-SplitSession2\" ${randstr} ; call sslo-tier-library::set_data \"" + name + "\" ${randstr} }"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        #datastr = {"name":"svc-" + name + "-svc-side-rule","apiAnonymous":"when CLIENT_ACCEPTED { node [call sslo-tier-library::get_data \"" + name + "\"] }"}
        datastr = {"name":"svc-" + name + "-svc-side-rule","apiAnonymous":"when HTTP_REQUEST { catch { node [call sslo-tier-library::get_data \"" + name + "\" [HTTP::header \"X-F5-SplitSession2\"]] }}"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        ## monitor rule
        datastr = {"name":"svc-" + name + "-monitor-rule","apiAnonymous":"when FLOW_INIT { if { [active_members svc-" + name + "-service-pool] < 1 } {drop} }"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        ## service virtuals
        datastr = {"name":"svc-" + name + "-sslo-side","source":"0.0.0.0/0","destination":"0.0.0.0:0","mask":"any","pool":"svc-" + name + "-service-pool","ipProtocol":"tcp","profiles":"/Common/http","rules":["svc-" + name + "-sslo-side-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        datastr = {"name":"svc-" + name + "-svc-side","source":"0.0.0.0/0","destination":"0.0.0.0:0","mask":"any","profiles":"/Common/http","rules":["svc-" + name + "-svc-side-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-svc-side-out"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## monitor virtual
        if "entry-float" in configs["service"]["sslo-side-net"].keys():
            monitor_ip = configs["service"]["sslo-side-net"]["entry-float"].split("/")
        else:
            monitor_ip = configs["service"]["sslo-side-net"]["entry-self"].split("/")

        datastr = {"name":"svc-" + name + "-monitor","source":"0.0.0.0/0","destination":monitor_ip[0] + ":9999","mask":"255.255.255.255","profiles":"/Common/tcp","ip-protocol":"tcp","rules":["svc-" + name + "-monitor-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## commit transaction
        del s.headers['X-F5-REST-Coordination-Id']
        result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()['state']
        #result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()
        print(result)

    else:
        error_exit("Incorrect state value entered.")


## icap service procedures
def service_icap(configs):
    ## state value
    if "state" in configs["service"].keys():
        state = configs["service"]["state"]
    else:
        state = "present"

    ## name value
    if "name" in configs["service"].keys():
        name = configs["service"]["name"]
    else:
        error_exit("No service name supplied in YAML")

    ## host value
    if "host" in configs.keys():
        host = configs["host"]
    else:
        error_exit("No host name supplied in YAML")

    ## user value
    if "user" in configs.keys():
        user = configs["user"]
    else:
        error_exit("No username supplied in YAML")

    ## password value
    if "password" in configs.keys():
        password = configs["password"]
    else:
        error_exit("No password supplied in YAML")

    ## process state
    if state == "absent":
        #### Delete named objects
        print("Deleting ICAP Service Objects")
        
        ## reset any possible existing objects
        reset_objects(host, user, password, name)


    elif state == "present":
        #### Parse YAML values ####
        print("Creating ICAP Service Objects")

        ## sslo-side-net and svc-side-net base keys
        if "sslo-side-net" in configs["service"].keys() and "svc-side-net" in configs["service"].keys():
            pass
        else:
            error_exit("Missing sslo-side-net or svc-side-net keys.")

        ## sslo-side-net values
        if "entry-interface" in configs["service"]["sslo-side-net"].keys() and "entry-self" in configs["service"]["sslo-side-net"].keys() and "entry-ip" in configs["service"]["sslo-side-net"].keys():
            sslo_side_net_entry_self = configs["service"]["sslo-side-net"]["entry-self"]
            sslo_side_net_entry_ip = configs["service"]["sslo-side-net"]["entry-ip"]
        else:
            error_exit("Missing entry and/or return sslo-side interface/self values.")

        if "entry-snat" in configs["service"]["svc-side-net"].keys():
            if configs["service"]["svc-side-net"]["entry-snat"] == "automap":
                sslo_side_net_entry_snat = "automap"
            elif isinstance(configs["service"]["svc-side-net"]["entry-snat"], list):
                sslo_side_net_entry_snat = "snatpool"
                snatstr = []
                for x in configs["service"]["svc-side-net"]["entry-snat"]:
                    snatstr.append("/Common/" + str(x))
            else:
                error_exit("Incorrect ICAP SNAT value.")

        ## svc-side-net values
        if "entry-interface" in configs["service"]["svc-side-net"].keys() and "entry-self" in configs["service"]["svc-side-net"].keys():
            svc_side_net_entry_self = configs["service"]["svc-side-net"]["entry-self"]
        else:
            error_exit("Missing entry and/or return svc-side interface/self values.")
        
        ## svc-members values
        if "svc-members" in configs["service"].keys():
            mbrstr = []
            for x in configs["service"]["svc-members"]:
                mbrdict = {"name":"" + x + ":any","address":"" + x + ""}
                mbrstr.append(mbrdict)
        else:
            error_exit("Missing svc-members key.")


        #### Create or modify named objects ####
        
        ## make sure the data group exists
        sslo_datagroup(user, password, host)

        ## create the library iRules
        sslo_library_rule(user, password, host)

        ## create tmsh transaction to build network objects
        s = requests.session()
        s.auth = (user, password)
        s.verify = False
        s.headers.update({'Content-Type':'application/json'})

        ## reset any possible existing objects
        reset_objects(host, user, password, name)

        ## make sure nodes don't exist
        for x in configs["service"]["svc-members"]:
            vals = x.split(":")
            resp = s.get("https://" + host + "/mgmt/tm/node/" + vals[0] + "").json()
            if "kind" in resp:
                s.delete("https://" + host + "/mgmt/tm/node/" + vals[0] + "")

        ## build transaction
        tx = s.post("https://" + host + "/mgmt/tm/transaction", data=json.dumps({})).json()['transId']
        s.headers.update({'X-F5-REST-Coordination-Id': str(tx)})

        ## build objects - sslo-side entry vlan
        datastr = vlan_descriptor(configs, name, "sslo-side-net", "entry", "sslo-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## svc-side entry vlan
        datastr = vlan_descriptor(configs, name, "svc-side-net", "entry", "svc-side-in")
        s.post("https://" + host + "/mgmt/tm/net/vlan", data=json.dumps(datastr))

        ## sslo-side entry self
        datastr = {"name":"svc-" + name + "-sslo-side-in","vlan":"svc-" + name + "-sslo-side-in","address":"" + sslo_side_net_entry_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## svc-side entry self
        datastr = {"name":"svc-" + name + "-svc-side-in","vlan":"svc-" + name + "-svc-side-in","address":"" + svc_side_net_entry_self + "","allowService":"default","trafficGroup":"traffic-group-local-only"}
        s.post("https://" + host + "/mgmt/tm/net/self", data=json.dumps(datastr))

        ## monitor
        datastr = {"name":"svc-" + name + "-monitor","interval":3,"timeout":7}
        s.post("https://" + host + "/mgmt/tm/ltm/monitor/gateway-icmp", data=json.dumps(datastr))

        ## service pool
        datastr = {"name":"svc-" + name + "-service-pool","monitor":"/Common/svc-" + name + "-monitor","members":mbrstr}
        s.post("https://" + host + "/mgmt/tm/ltm/pool", data=json.dumps(datastr))

        ## snat pool
        if sslo_side_net_entry_snat == "snatpool":
            datastr = {"name":"svc-" + name + "-snat-pool","members":snatstr}
            s.post("https://" + host + "/mgmt/tm/ltm/snatpool", data=json.dumps(datastr))

        ## monitor rule
        datastr = {"name":"svc-" + name + "-monitor-rule","apiAnonymous":"when FLOW_INIT { if { [active_members svc-" + name + "-service-pool] < 1 } {drop} }"}
        s.post("https://" + host + "/mgmt/tm/ltm/rule", data=json.dumps(datastr))

        ## service virtuals
        if sslo_side_net_entry_snat == "automap":
            datastr = {"name":"svc-" + name + "-sslo-side","source":"0.0.0.0/0","destination":"" + sslo_side_net_entry_ip + ":0","mask":"255.255.255.255","pool":"svc-" + name + "-service-pool","ipProtocol":"tcp","sourceAddressTranslation":{"type":"automap"},"translateAddress":"enabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        elif sslo_side_net_entry_snat == "snatpool":
            datastr = {"name":"svc-" + name + "-sslo-side","source":"0.0.0.0/0","destination":"" + sslo_side_net_entry_ip + ":0","mask":"255.255.255.255","pool":"svc-" + name + "-service-pool","ipProtocol":"tcp","sourceAddressTranslation":{"type":"snat","pool":"svc-" + name + "-snat-pool"},"translateAddress":"enabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        else:
            datastr = {"name":"svc-" + name + "-sslo-side","source":"0.0.0.0/0","destination":"" + sslo_side_net_entry_ip + ":0","mask":"255.255.255.255","pool":"svc-" + name + "-service-pool","ipProtocol":"tcp","translateAddress":"enabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## monitor virtual
        monitor_ip = configs["service"]["sslo-side-net"]["entry-ip"]
        datastr = {"name":"svc-" + name + "-monitor","source":"0.0.0.0/0","destination":monitor_ip + ":9999","mask":"255.255.255.255","profiles":"/Common/tcp","ip-protocol":"tcp","rules":["svc-" + name + "-monitor-rule"],"translateAddress":"disabled","translatePort":"disabled","vlans":["svc-" + name + "-sslo-side-in"],"vlansEnabled":True}
        s.post("https://" + host + "/mgmt/tm/ltm/virtual", data=json.dumps(datastr))

        ## commit transaction
        del s.headers['X-F5-REST-Coordination-Id']
        result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()['state']
        #result = s.patch("https://" + host + "/mgmt/tm/transaction/{}".format(tx), data=json.dumps({"state":"VALIDATING"})).json()
        print(result)

    else:
        error_exit("Incorrect state value entered.")


## service mapping procedures
def service_mapping(configs):
    ## host value
    if "host" in configs.keys():
        host = configs["host"]
    else:
        error_exit("No host name supplied in YAML")

    ## user value
    if "user" in configs.keys():
        user = configs["user"]
    else:
        error_exit("No username supplied in YAML")

    ## password value
    if "password" in configs.keys():
        password = configs["password"]
    else:
        error_exit("No password supplied in YAML")

    ## sslo-side-net and svc-side-net base keys
    if "mapping" not in configs["service"].keys():
        error_exit("Missing sslo-side-net or svc-side-net keys.")
    
    ## create data group key:value list
    datastr = []
    for x in configs["service"]["mapping"]:
        service = x["service"]
        for y in x["maps"]:
            srcmac = y["srcmac"]
            destip = y["destip"]
            datadict = {"name":"" + service + ":" + srcmac + "","data":"" + destip + ""}
            datastr.append(datadict)

    ## update sslo-tier-datagroup
    s = requests.session()
    s.auth = (user, password)
    s.verify = False
    s.headers.update({'Content-Type':'application/json'})
    
    datastr = {"records":datastr}
    s.patch("https://" + host + "/mgmt/tm/ltm/data-group/internal/sslo-tier-datagroup", data=json.dumps(datastr))
    print("COMPLETED")


## Test command-line arguments
try:
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", dest="filename", help="Input a configuration file", metavar="FILE", required=True)
    args = parser.parse_args()
except:
    error_exit("Incorrect arguments supplied.")


## Test supplied YAML file for existence and structure
try:
    with open(args.filename, "r") as file:
        configs = safe_load(file)
except:
    error_exit("Failed to open supplied file, or incorrect YAML format.")


## Test YAML file for required content
try:
    type = configs["service"]["type"]
    if type == "layer3":
        service_layer3(configs)
    elif type == "layer2":
        service_layer2(configs)
    elif type == "http_explicit":
        service_http_explicit(configs)
    elif type == "http_transparent":
        service_http_transparent(configs)
    elif type == "icap":
        service_icap(configs)
    elif type == "mapping":
        service_mapping(configs)
    else:
        error_exit("Incorrect service type specified")

except:
    sys.exit()

