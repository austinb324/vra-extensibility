import requests
import json

#Get network profile cidr from vRA
def get_networkDetails(context, networkSelectionIds):
    idcidrmapping = {}
    CIDRs = []
    
    for networkId in networkSelectionIds:
        #This will handle the various datastructures being passed into the function by different event types
        networkId = networkId[0] if isinstance(networkId, list) else networkId
        if networkId in idcidrmapping:
            cidr = idcidrmapping[networkId]
        else:
            print("Getting network profile cidr from vRA for network ID: ", networkId)
            resp = context.request("/iaas/api/fabric-networks/"+networkId, "GET", "")
            json_resp = {}
            try:
                json_resp = json.loads(resp['content'])
            except json.decoder.JSONDecodeError as ex:
                print("Error occured while parsing json response: ")
                print(ex)
            cidr = json_resp["cidr"]
            print("Found CIDR: ", cidr)
            idcidrmapping[networkId] = cidr
        CIDRs.append(cidr)
    print("Returning CIDRs: ", CIDRs)
    return CIDRs
    
#Get subnet identifier by CIDR
def get_subnetIdByCIDR(CIDRs):
    idcidrmapping = {}
    subnetIDs = []

    for cidr in CIDRs:
        if cidr in idcidrmapping:
            subnetid = idcidrmapping[cidr]
        else:
            print ("Getting subnet ID from PHPipam for cidr: ", cidr)
            url = "http://"+phpipamhost+"/api/"+app+"/subnets/cidr/"+cidr
            responseObj = do_restOperation("GET",url)
            print("Response: ", responseObj['code'], (" failed"," success")[responseObj['success']])
            subnetid = responseObj["data"][0]["id"]
            print ("Found subnetID : " + subnetid)
        subnetIDs.append(subnetid)
        
    return subnetIDs

#Get subnet identifier
def get_subnetIdByIp(ipaddresses):
    idipmapping = {}
    subnetIDs = []

    for ipaddress in ipaddresses:
        if ipaddress in idipmapping:
            subnetid = idipmapping[ip]
        else:    
            print ("Getting subnet ID from PHPipam for ip: ", ipaddress)
            url = "http://"+phpipamhost+"/api/"+app+"/addresses/search/"+ipaddress
            responseObj = do_restOperation("GET",url)
            result = responseObj['success']
            print("Response: ", responseObj['code'], (" failed"," success")[result])
            if result:
                subnetid = responseObj["data"][0]["subnetId"]
                print ("Found subnetID : " + subnetid)
            else:
                print ("No ipaddress", ipaddress, "found")
                subnetid = None
        subnetIDs.append(subnetid)
        
    return subnetIDs

#Get and allocate next free IP in specified subnet
def allocate_NextNFreeIpInSubnet(CIDRs, subnetIds, hostname, project, owner):
    newIPs = []

    for subnetid, cidr in zip(subnetIds, CIDRs):
        print("Allocating next free IP address in CIDR: ", cidr, "for hostname: ", hostname)
        url = "http://"+phpipamhost+"/api/"+app+"/addresses/first_free/"+subnetid
        payload = "{\"hostname\":\""+hostname+"\",\"description\":\""+"Currently Building in vRA"+"\",\"owner\":\""+project+" - "+owner+"\"}"

        responseObj = do_restOperation("POST",url,payload)
        print("Response: ", responseObj['code'], (" failed: "," success: ")[responseObj['success']], responseObj['message'])
        
        ipaddress = responseObj["data"]
        print ("New ipaddress : " + ipaddress)
        newIPs.append(ipaddress)
    return newIPs
  
    
#Get token
def get_token(app_token, Authorization):
    url = "http://"+phpipamhost+"/api/"+app+"/user"
    payload  = {}
    headers = {
      'Content-Type': 'application/json',
      'token': ''+app_token+'',
      'Authorization': ''+Authorization+'',
    }
    responseObj = do_restOperation("POST",url,payload,headers)
    #Set token Variable
    token = (responseObj['data']['token'])
    return token

#Delete VM info
def delete_vm(ipaddress, subnetid):
    url = "http://"+phpipamhost+"/api/"+app+"/addresses/"+ipaddress+"/"+subnetid+""
    responseObj = do_restOperation("DELETE",url)
    print("Response: ", responseObj['code'], (" failed: "," success: ")[responseObj['success']], responseObj['message'])
    
#Create VM info
def create_vm(project, ipaddress, subnetid, hostname, owner):
    #Create Custom Description
    description = "Project : "+project
    note = "Created by VRA"
    #Set IP
    url = "http://"+phpipamhost+"/api/"+app+"/addresses/"
    payload = "{\"ip\":\""+ipaddress+"\",\"subnetId\":\""+subnetid+"\",\"hostname\":\""+hostname+"\",\"description\":\""+description+"\",\"owner\":\""+owner+"\",\"note\":\""+note+"\"}"
    responseObj = do_restOperation("POST",url,payload)
    print("Response: ", responseObj['code'], (" failed: "," success: ")[responseObj['success']], responseObj['message'])

def do_restOperation(action,url,payload={},headers=None):
    if headers == None:
        headers = {
         'Content-Type': 'application/json',
         'token': ''+token+'',
        }
    response = requests.request(action, url, headers=headers, data = payload)
    #If an error occur, this method returns a HTTPError object
    response.raise_for_status()
    
    json_resp = {}
    try:
        json_resp = json.loads(response.content)
    except json.decoder.JSONDecodeError as ex:
        print("Error occured while parsing json response for following request: ")
        print(action, url)
        print(headers)
        print(payload)
        raise ex
    return json_resp
  
#Main Function
def phpipam(context, inputs):
    print ("Running PHPipam function")
    
    global phpipamhost
    global app
    global token
    
    phpipamhost   = inputs["phpipamhost"]
    app           = inputs["app"]                               #PHPmyipam API App Name
    app_token     = inputs["app_token"]                         #PHPmyipam API App Token
    Authorization = inputs["auth"]                              #Username and Pass for PHPipam. Can be generated here https://www.blitter.se/utils/basic-authentication-header-generator/           
    event         = str(inputs["__metadata"]["eventTopicId"])   #Provision or remove
    project       = str(inputs["tags"]["project"])              #The project the deployment belongs to.
    owner         = str(inputs["__metadata"]["userName"])       #The requester of the ressource
    
    token = get_token(app_token, Authorization)
    
    provision = event.startswith('compute.provision')
    if provision:
        print("Updating IPs as part of Provision event")
        ipaddresses   = inputs["addresses"][0]                  #Array of IPs
        hostname  = inputs["resourceNames"][0]                  #Hostname
        networkIds = inputs["subnetIds"][0]
        CIDRs = get_networkDetails(context, networkIds)
        subnetIDs = get_subnetIdByCIDR(CIDRs)
        for ipaddress, subnetid in zip(ipaddresses, subnetIDs):
            print("Deleting existing IPAM record for address: ", ipaddress)
            delete_vm(ipaddress, subnetid)
            print("Adding new IPAM record for address: ", ipaddress)
            create_vm(project, ipaddress, subnetid, hostname, owner)
        outputs = {}
            
    removal = event.startswith('compute.removal')
    if removal:
        print("Deleting IPs as part of removal event")
        ipaddresses   = inputs["addresses"][0]                  #Array of IPs
        subnetIDs = get_subnetIdByIp(ipaddresses)
        for ipaddress, subnetid in zip(ipaddresses, subnetIDs):
            if subnetid != None:
                print("Deleting IPAM record for address: ", ipaddress)
                delete_vm(ipaddress, subnetid)
        outputs = {}

    netConfig = event.startswith('network.configure')
    if netConfig:
        print("Allocating IPs as part of network configure event")
        hostnames = inputs["externalIds"]
        networkIds = inputs["networkSelectionIds"][0]
        CIDRs = get_networkDetails(context, networkIds)
        subnetIds = get_subnetIdByCIDR(CIDRs)
        alladdresses = []
    
        for hostname in hostnames:
            ipaddresses = allocate_NextNFreeIpInSubnet(CIDRs, subnetIds, hostname, project, owner)
            alladdresses.append(ipaddresses)
        
        outputs = {
            "addresses": alladdresses
        }
        print(outputs)
    
    if not provision and not removal and not netConfig:
        print("Action called on invalid event: ", event)
        outputs = {}
    
    return outputs
	