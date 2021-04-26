#!/usr/bin/env python3

''' pdb-intersect.py

    Author

        Internet Systems Consortium, Elmar K. Bins, <ekb@isc.org>, 2020-2021
        This file uses 4 blanks, not tabs. (expandtab, softtabstop=4, ts=4)


    Synopsis

      pdb-intersect.py [--config <config>] <asn1> <asn2> [<pat1>] [<pat2>]

      Optionally, you can use the long-parameter version
        pdb-intersect.py [--config <config>] --asn1 <asn1> --asn2 <asn2> [--pat1 <pat1>] [--pat2 <pat2>]

      pdb-intersect collects all asns that belong to asn1's "org" object and
      intersects them with all asns hanging off asn2's "org" object. The
      patterns filter on the found asn (net) objects' notes fields.


    PeeringDB authentication

      API authentication info is stored in a config file, login on the first
      line, password on the second. This config file can be specified; if it
      is not, "pdb-intersect.conf" in the script's directory is used. If the
      config file is not found, you will be using the API anonymously, which
      might not give you the results you'd expect.


    Example

      pdb-intersect 3557 <your asn> 3557         # where can I peer with F-Root?

      This will intersect your ASN with all ASNs that hang off 3557's org object
      and that do contain "3557" in the notes field. (Not specifying the pattern
      would also get you intersections with 1280, because 3557 and 1280 both
      hang off the same org object.)


    History

    In Q1 2020, peeringdb removed a feature from the database that allowed you
    to keep a "main ASN" and record all your peerings with it, even when you
    used different ASNs at each IXP (which, incidentally, F-Root does).

    PeeringDB would be searchable for your master ASN, and you would get all
    your IXP addresses and ASNs, making it workable for peerfinder.py.

    Since the change, all ASNs are separate now and don't connect to each other,
    except at the very top, in the organisation object.

    I had to write this script (and the library used) from scratch after finding
    that peerfinder.py could not be easily amended, since it had a lot of
    interwoven features.

    pdb-intersect.py now grabs the org object for each ASN given, finds all net
    objects for it, filters out those that don't match the (optional) pattern
    in their notes field. Now the net objects are ready to be intersected, and
    you will get the same type of output as for a simple call to peerfinder.py.

    Only the intersection is implemented, for all other features, you will have
    to use peerfinder.py at https://github.com/rucarrol/PeerFinder

'''

import re
import sys
import os
import ipaddress

from prettytable import PrettyTable

from lib_peeringdb import pdb_net_by_orgid, pdb_net_by_asn, pdb_netixlan_by_netid
from lib_peeringdb import pdb_net_tree_by_asn, pdb_org_by_id, pdb_net_tree_by_asnlist
from lib_peeringdb import first_data_object, all_data_objects, pdb_set_credentials

#- preset our globals
asn1 = None
asn2 = None
pat1 = None
pat2 = None

#------------------------------------------------------------------------------

def get_all_net_for_orgid(orgid, pat=None):
    '''
    Return list of net object dicts of objects hanging off orgid,
    optionally the "notes" field matching pat
    '''

    nets = all_data_objects(pdb_net_by_orgid(orgid))

    if nets == None: return nets
    if pat == None: return nets

    #- fix the pattern for partial matching
    pat=".*"+pat+".*"

    for net in nets:
        if not re.match(pat, net["notes"]):
            nets.remove(net)

    return nets


def get_orgid_for_asn(asn):
    net = first_data_object(pdb_net_by_asn(asn))
    if net == None: return None
    return net["org_id"]

#------------------------------------------------------------------------------

def ixlan_intersect(netixlan1, netixlan2):
    ''' Finds the common ixlans for the netixlan objects,
        returns asn1+2 information alongside the ixlan info for matches
    '''
    #- build lookup dicts for ixlans
    netixlans1_by_ixlanid = {}
    netixlans2_by_ixlanid = {}

    for netixlan in netixlan1:
        key = netixlan["ixlan_id"]
        if key not in netixlans1_by_ixlanid: netixlans1_by_ixlanid[key] = []
        netixlans1_by_ixlanid[key].append(netixlan)

    for netixlan in netixlan2:
        key = netixlan["ixlan_id"]
        if key not in netixlans2_by_ixlanid: netixlans2_by_ixlanid[key] = []
        netixlans2_by_ixlanid[key].append(netixlan)

    #- construct sets for each and intersect
    ixlans1 = set(netixlans1_by_ixlanid.keys())
    ixlans2 = set(netixlans2_by_ixlanid.keys())
    ixlans_common = ixlans1.intersection(ixlans2)

    #- construct the resulting set
    result = {}
    for ixlanid in ixlans_common:
        netixlans1 = netixlans1_by_ixlanid[ixlanid]
        netixlans2 = netixlans2_by_ixlanid[ixlanid]

        items1 = []
        items2 = []

        for ni in netixlans1: items1.append("\n".join(["ASN:  "+str(ni['asn']),"IPv4: "+str(ni['ipaddr4']),"IPv6: "+str(ni['ipaddr6'])]))
        for ni in netixlans2: items2.append("\n".join(["ASN:  "+str(ni['asn']),"IPv4: "+str(ni['ipaddr4']),"IPv6: "+str(ni['ipaddr6'])]))

        col1 = netixlans1[0]["name"]

        col2 = "\n\n".join(items1)
        col3 = "\n\n".join(items2)

        tab.add_row([col1,col2,col3])

#------------------------------------------------------------------------------

def readcreds_fromconfig(config):
    if config=="":
        mypath = os.path.dirname(__file__)
        config = "/".join([mypath, "pdb-intersect.conf"])

    try:
        with open(config, "r") as f:
            u = f.readline().rstrip()
            p = f.readline().rstrip()
            return (u,p)
    except:
        return("","")

#------------------------------------------------------------------------------

def getArgs():

    global asn1
    global asn2
    global pat1
    global pat2
    config=""

    myname = sys.argv.pop(0)
    arg  = None

    try:
        arg = sys.argv.pop(0)
    except:
        pass

    while arg!= None:

        try:
            if   arg == "--asn1":   asn1 = sys.argv.pop(0)
            elif arg == "--asn2":   asn2 = sys.argv.pop(0)
            elif arg == "--pat1":   pat1 = sys.argv.pop(0)
            elif arg == "--pat2":   pat2 = sys.argv.pop(0)
            elif arg == "--config": config = sys.argv.pop(0)
            else:
                if   asn1 == None: asn1 = arg
                elif asn2 == None: asn2 = arg
                elif pat1 == None: pat1 = arg
                elif pat2 == None: pat2 = arg
        except:
            pass

        #-- now try for the next in the list
        #   if finished, just set to None and the loop will quit
        try:
            arg = sys.argv.pop(0)
        except:
            arg = None


    if asn1==None or asn2==None:
        print("ERR: Please specify asn1 and asn2")
        exit(1)

    if pat1==None: pat1=""
    if pat2==None: pat2=""

    #- get our authentication info ready
    (pdbuser,pdbpass) = readcreds_fromconfig(config)
    if pdbuser != "": pdb_set_credentials(pdbuser,pdbpass)



#------------------------------------------------------------------------------
# main()
#------------------------------------------------------------------------------

#- init a PrettyTable object (cool library, folks)
global tab
tab = PrettyTable()

#- read the args and init authentication info, setting the API URI accordingly
getArgs()

# - get ASNs' org and net objects first (travel UP the tree)
orgid1 = get_orgid_for_asn(asn1)
orgid2 = get_orgid_for_asn(asn2)
asn1_nets = get_all_net_for_orgid(orgid1,pat1)
asn2_nets = get_all_net_for_orgid(orgid2,pat2)

if asn1_nets == None:
    print("No IXPs found for ASN {}".format(asn1))
    exit(1)

if asn2_nets == None:
    print("No IXPs found for ASN {}".format(asn2))
    exit(1)

#- get a full tree for all ASN1's org's asns (travel DOWN the tree)
asns1 = []
for net in asn1_nets: asns1.append(str(net["asn"]))
tree1 = all_data_objects(pdb_net_tree_by_asnlist(",".join(asns1)))

#- get a full tree for all ASN2's org's asns (travel DOWN the tree)
asns2 = []
for net in asn2_nets: asns2.append(str(net["asn"]))
tree2 = all_data_objects(pdb_net_tree_by_asnlist(",".join(asns2)))

#- actually read the org objects to extract the name, for proper output
org1 = first_data_object(pdb_org_by_id(orgid1))
org2 = first_data_object(pdb_org_by_id(orgid2))
tab.field_names = ["IX", org1["name"], org2["name"]+"."]

#- get ixlan list for the ASNs hanging off asn1 (travel DOWN per ASN)
netixlan1 = []
for net in tree1:
    ixlanset = net["netixlan_set"]
    netixlan1 += ixlanset

#- and for asn2 (travel DOWN per ASN)
netixlan2 = []
for net in tree2:
    ixlanset = net["netixlan_set"]
    netixlan2 += ixlanset

#- intersect by ixlan_id, intersect() puts results into the tab object
ixlan_intersect(netixlan1, netixlan2)

#- format and output tab object output in a nice fashion (yes, this is great)
tab.hrules = 1
tab.sortby="IX"
tab.align="l"
print("\n\n")
print(tab)

exit(0)

