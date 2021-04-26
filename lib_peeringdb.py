#!/usr/bin/env python3

''' lib_peeringdb.py

    Author

        Internet Systems Consortium, Elmar K. Bins, <ekb@isc.org>, 2020-2021
        This file uses 4 blanks, not tabs. (expandtab, softtabstop=4, ts=4)

    Synopsis

        Stupid little library to read data from PeeringDB     ekb@isc.org 2020-2021
        Based upon API documentation at https://www.peeringdb.com/apidocs/

'''

import json
import requests
import pprint
import ipaddress
import re

#- start anonymous; for full API, use pdb_set_credentials()

PDB_baseurl = "https://peeringdb.com/api"


def pdb_set_credentials(arguser,argpass):
    global PDB_baseurl
    PDB_baseurl = "https://{}:{}@peeringdb.com/api".format(arguser,argpass)


#-
# Run a reading query

def querypdb(url):
    pdb_json = requests.get(url=url)
    pdb_dict = json.loads(pdb_json.text)
    return pdb_dict


#-
# Do an update

def updatepdb(url,dict_obj):
    dict_headers = {
            "Accept"       : "application/json",
            "Content-Type" : "application/json",
            }

    result = requests.put(url=url, data=json.dumps(dict_obj), headers=dict_headers)

    if not result:
        print("PUT encountered problems:")
        pprint.pprint(result.json())

    return None


#-
# simple pdb functions, identified by some id or directly queriable field
#
# pdb_XXX getter functions return the full hash that will consist of
#   hash["meta"] -> Metainfo hash
#   hash["data"] -> List of hashes of content
#   ("data" might be missing, or list["data"] might be empty))

#-- entire trees

def pdb_org_tree_by_id(orgid):
    url = PDB_baseurl+"/org?id={}&depth=2".format(orgid)
    return querypdb(url)

def pdb_net_tree_by_asn(asn):
    url = PDB_baseurl+"/net?asn={}&depth=2".format(asn)
    return querypdb(url)

def pdb_net_tree_by_asnlist(asn):
    url = PDB_baseurl+"/net?asn__in={}&depth=2".format(asn)
    return querypdb(url)

def pdb_ix_tree(id, depth=2):
    url = PDB_baseurl+"/ix?id={}&depth={}".format(id, depth)
    return querypdb(url)


#-- net

def pdb_net_update(id, changes):
    if id==None: return None
    url = PDB_baseurl+"/net/{}".format(id)
    updatepdb(url, changes)

def pdb_net_by_id(id):
    url = PDB_baseurl+"/net?id={}".format(id)
    return querypdb(url)

def pdb_net_by_asn(asn):
    url = PDB_baseurl+"/net?asn={}".format(asn)
    return querypdb(url)

def pdb_net_by_orgid(orgid):
    url = PDB_baseurl+"/net?org_id={}".format(orgid)
    return querypdb(url)

def pdb_net_by_orgid_and_name(orgid, name):
    url = PDB_baseurl+"/net?org_id={}&name__contains={}".format(orgid, name)
    return querypdb(url)


#-- org

def pdb_org_by_id(id):
    url = PDB_baseurl+"/org?id={}".format(id)
    return querypdb(url)


#-- poc

def pdb_poc_by_id(id):
    url = PDB_baseurl+"/poc?id={}".format(id)
    return querypdb(url)

def pdb_poc_by_netid(id):
    url = PDB_baseurl+"/poc?net_id={}".format(id)
    return querypdb(url)


#-- ixp

def pdb_ix_by_id(id):
    url = PDB_baseurl+"/ix?id={}".format(id)
    return querypdb(url)


#-- ixlan

def pdb_ixlan_by_id(id):
    url = PDB_baseurl+"/ixlan?id={}".format(id)
    return querypdb(url)

def pdb_ixlan_by_ixid(id):
    url = PDB_baseurl+"/ixlan?ix_id={}".format(id)
    return querypdb(url)

def pdb_ixlan_by_ixpfxid(id):
    url = PDB_baseurl+"/ixlan?ixpfx_id={}".format(id)
    return querypdb(url)


def pdb_ixlan_ALL():
    url = PDB_baseurl+"/ixlan"
    return querypdb(url)


#-- netixlan

def pdb_netixlan_by_id(id):
    url = PDB_baseurl+"/netixlan?id={}".format(id)
    return querypdb(url)

def pdb_netixlan_by_netid(id):
    url = PDB_baseurl+"/netixlan?net_id={}".format(id)
    return querypdb(url)

def pdb_netixlan_by_asn(id):
    url = PDB_baseurl+"/netixlan?asn={}".format(id)
    return querypdb(url)


#-- ixpfx

def pdb_ixpfx_by_id(id):
    url = PDB_baseurl+"/ixpfx?id={}".format(id)
    return querypdb(url)

def pdb_ixpfx_by_ixlanid(id):
    url = PDB_baseurl+"/ixpfx?ixlan_id={}".format(id)
    return querypdb(url)

def getixpfxlist_by_partial(partial):
    url = PDB_baseurl+"/ixpfx?prefix__startswith={}".format(partial)
    return querypdb(url)

def pdb_ixpfx_ALL():
    url = PDB_baseurl+"/ixpfx"
    return querypdb(url)


#-
# more complex/indirect actions

def find_ixpfx_by_ixid(id):
    ''' find the ixpfx objects for an ix
        returns a list of ixpfx "data" hashes, not
        the pdb_ construct like pdb_ functions
    '''
    ixlans = getixlan_by_ixid(id)
    ixpfxs = []
    for ixlan in ixlans["data"]:
        ixpfx = getixpfx_by_ixlanid(ixlan["id"])
        for ixpfxpart in ixpfx["data"]:
            ixpfxs.append(ixpfxpart)
    return ixpfxs


def one_ixp_by_ixpfx(ixpfx):
    ''' finds the first ixx object that is linked to the
        ixpfx object given
        returns the ix object hash without meta/data stuff
    '''
    # get the list of ixlans that ixpfx comes from
    ixlans=getixlan_by_id(ixpfx["ixlan_id"])["data"]
    if len(ixlans) == 0: return None

    # now get the ix from only the first ixlan found
    ixp = getixp_by_id(ixlans[0]["ix_id"])

    if len(ixp["data"])>0: return ixp["data"][0]



def getixp_by_ipv4(v4):
    ''' Find the ix object that links (indirectly) to the
        IPv4 address given; uses the base /16 for limiting
        the search, then checks all returned objects.
        returns one ix object hash (without meta/data stuff), or None
    '''
    v4net = ipaddress.ip_network(v4+"/32")
    v4arr = v4.split(".")
    v4partial = v4arr[0]+"."+v4arr[1]                       # just use /16

    # get list of ixpfx that match the slash16
    data = getixpfxlist_by_partial(v4partial)["data"]

    # find first ixpfx that is a supernet of v4
    ixpfx=None
    for ixpfx in data:
        try:
            net = ipaddress.ip_network(ixpfx["prefix"])
        except:
            continue

        if v4net.subnet_of(net): break

    if ixpfx==None: return None

    return getixp_by_ixpfx(ixpfx)


#- IPv6... hmm... più difficile...
#  generate a net from our address, then explode and take the first 6 quads.
#  Since pdb does store compressed, and no empty quads (using shorthand),
#  we need to trim trailing "0" quads.
#
#  So, e.g.:
#  2001:de8:6::714:1 would become
#  2001:0de8:0006:0000:0000:0000:0714:0001 from explode, then trimmed to 6 quads
#  2001:0de8:0006:0000:0000:0000, then dropping trailing 0 quads and shortening
#  2001:de8:6                   - this is used for matching, coarse, but works
#

def getixp_by_ipv6(v6):
    ''' Find the ix object that links (indirectly) to the
        IPv6 address given; does some tricky magic to limit the search set,
        then checks all returned objects
        returns one ix object hash (without meta/data stuff), or None
    '''
    v6net = ipaddress.ip_network(v6+"/128")
    v6add = ipaddress.ip_address(v6)
    v6full = v6add.exploded

    v6arr = v6full.split(":")[0:6]

    #--
    # a little bit of array string manipulation ;-)
    # - walk all parts in v6arr, back-to-front (reversed)
    #    ignore "0000" while still at the end of the array (atend=True)
    #    trim the leading "0"s from each part
    #    but set empty parts to "0"
    #    insert to front of resultarray

    resultarr = []
    atend=True
    for part in reversed(v6arr):
        if part == "0000" and atend: continue
        atend=False
        part = re.sub("^0+","",part)
        if part == "": part="0"
        resultarr.insert(0,part)

    v6partial = ":".join(resultarr[0:6])

    #--
    # get list of ixpfx that match our slash16
    data = getixpfxlist_by_partial(v6partial)["data"]

    # find first ixpfx that is a supernet in v6
    ixpfx=None
    for ixpfx in data:
        try:
            net = ipaddress.ip_network(ixpfx["prefix"])
        except:
            continue

        if v6net.subnet_of(net): break

    if ixpfx==None: return None
    return getixp_by_ixpfx(ixpfx)


def unexplode_ip(ip):
    ''' Unexplodes an "exploded" IP address; very necessary for IPv4,
        because the ipaddress library interprets numbers with leading
        "0" (from explode()) as octal numbers
    '''
    ips = ip.split(".")
    if len(ips) == 4: joinchar="."
    else:
        ips = ip.split(":")
        if len(ips) > 1: joinchar=":"
        else: return ip

    results = []
    for i in ips:
        i=re.sub("^0*", "", i)
        if len(i)==0: i="0"
        results.append(i)

    result = joinchar.join(results)
    return result


def getixp_by_ip(ip):
    ''' Find "the" matching ix object for the IP given (v4 or v6).
        Returns first ix object hash found, or None
    '''
    ip = unexplode_ip(ip)           # necessary, ipaddress library tries octal

    addr = ipaddress.ip_address(ip)
    if addr.version==4:
        return getixp_by_ipv4(ip)
    elif addr.version==6:
        return getixp_by_ipv6(ip)
    else:
        return None


def first_data_object(obj):
    ''' takes the hash/hash/array/hash object we got from the pdb query
        and returns the first data hash, if available, None otherwise.
        '''
    if obj == None: return None
    if not "data" in obj: return None
    if len(obj["data"])==0: return None
    return obj["data"][0]


def all_data_objects(obj):
    ''' takes the hash/hash/array/hash object we got from the pdb query
        and returns all data hashes in a list (or None)
        '''
    if obj == None: return None
    if not "data" in obj: return None
    if len(obj["data"])==0: return None

    reslist = []
    for o in obj["data"]: reslist.append(o)

    return reslist

