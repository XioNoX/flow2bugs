#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Author: Arzhel Younsi <arzhel@mozilla.com>

# Based a LOT on vuln2bugs
# https://github.com/gdestuynder/vuln2bugs

from urllib2 import urlopen
from urllib import urlencode
from dns import reversename, resolver
from bugzilla import *
import ssl
import hjson as json
import hashlib
import base64
import pyservicelib
import httplib2
import re
import warnings
from requests.packages.urllib3 import exceptions as requestexp
from time import localtime,strftime,sleep
from xml.dom import minidom



def get_hosts_owners(eisowners):
    '''Import and sort the list of services/owners (key is hostname)'''
    # Disable SSL cert verification
    httpsctx = ssl.create_default_context()
    httpsctx.check_hostname = False
    httpsctx.verify_mode = ssl.CERT_NONE
    # Download the list of owners, space separated values:
    #host operator team v2bkey
    #host operator team v2bkey
    #host operator team v2bkey
    owners_file = urlopen(eisowners, context=httpsctx)
    attributes = {}
    owners = {}
    #Iterate over the text file
    for line in owners_file.readlines():
        # Ignore comment lines
        if line.startswith('#'):
            continue
        # Separate list of values based on the space caractere
        host, operator, team, v2bkey = line.split(' ')
        attributes = {
            'operator': operator,
            'team': team,
            'v2bkey': v2bkey.rstrip('\n'),
        }
        # Set the hostname as key
        owners[host] = attributes
    return owners

def query_splunk(config):
    ## From http://blogs.splunk.com/2011/08/02/splunk-rest-api-is-easy-to-use/

    baseurl = config['splunk']['host']
    username = config['splunk']['username']
    password = config['splunk']['password']
    myhttp = httplib2.Http(disable_ssl_certificate_validation=True)

    #Step 1: Get a session key
    servercontent = myhttp.request(baseurl + '/services/auth/login', 'POST',
                                headers={}, body=urlencode({'username':username, 'password':password}))[1]
    sessionkey = minidom.parseString(servercontent).getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue

    #Step 2: Create a search job
    searchquery = config['splunk']['query']
    if not searchquery.startswith('search'):
        searchquery = 'search ' + searchquery

    searchjob = myhttp.request(baseurl + '/services/search/jobs','POST',
    headers={'Authorization': 'Splunk %s' % sessionkey},body=urlencode({'search': searchquery, 'earliest_time': '-24h@h', 'latest_time': 'now'}))[1]
    sid = minidom.parseString(searchjob).getElementsByTagName('sid')[0].childNodes[0].nodeValue
    print "Splunk search job ID: %s" % sid
    #Step 3: Get the search status
    myhttp.add_credentials(username, password)
    servicessearchstatusstr = '/services/search/jobs/%s/' % sid
    isnotdone = True
    while isnotdone:
        searchstatus = myhttp.request(baseurl + servicessearchstatusstr, 'GET')[1]
        isdonestatus = re.compile('isDone">(0|1)')
        isdonestatus = isdonestatus.search(searchstatus).groups()[0]
        sleep(10)
        if (isdonestatus == '1'):
            isnotdone = False
    #Step 4: Get the search results
    services_search_results_str = '/services/search/jobs/%s/results?output_mode=json&count=0' % sid
    searchresults = myhttp.request(baseurl + services_search_results_str, 'GET')[1]
    return searchresults



def get_flows_grp_ips(config, raw_splunk_data):
    '''Import the list of flows and group them by src_ip (key is src_ip)'''
    flows_grouped_by_src_ip = {}

    # Parse the raw data as json
    raw_splunk_data_json = json.loads(raw_splunk_data)
    for line_parsed in raw_splunk_data_json['results']:
        # We ignore any line that has a whitelisted destination IPs
        if line_parsed['dest_ip'] in config['dest_whitelist']:
            continue
        attributes = {
            'dest_ip': line_parsed['dest_ip'],
            'dest_port': line_parsed['dest_port'],
        }
        # If source IP is already in the dict
        if line_parsed['src_ip'] in flows_grouped_by_src_ip:
            # Add an additional dest_ip/dest_port to the list
            flows_grouped_by_src_ip[line_parsed['src_ip']] = flows_grouped_by_src_ip[line_parsed['src_ip']] + [attributes]
        else:
            # Create the first list element
            flows_grouped_by_src_ip[line_parsed['src_ip']] = [attributes]
    # Close splunk file
    return flows_grouped_by_src_ip

def merge_flows_owners(flows, owners, config):
    '''convert src_ip to hostnames and merge owner_list'''
    flows_fqdn_owner = {}
    # use pyservicelib to submit hosts to EIS
    pyservicelib.config.apihost = config['eisendpoint']
    warnings.simplefilter('ignore', requestexp.SubjectAltNameWarning)
    #pyservicelib.config.sslverify = False
    s = pyservicelib.Search()
    # Iterate over dict of src_ip, containing list of destip/port
    for src_ip, attributes in flows.iteritems():
        # Get the litteral reverse name
        rev_name = reversename.from_address(src_ip)
        try:
            # Try to get the PTR from DNS
            fqdn = str(resolver.query(rev_name,"PTR")[0]).rstrip('.')
            # Add hostname to the list to be sent to EIS
            s.add_host(fqdn, confidence=90)
        except resolver.NXDOMAIN:
            # If DNS issue or IP doesn't have a PTR
            # Display error message and ignore that src IP
            print('{0} is not in dns'.format(src_ip))
            continue
        # If no issues add attributes (destIP/port) as 'flows' to the dict
        flows_fqdn_owner[fqdn] = {}
        flows_fqdn_owner[fqdn]['flows'] = attributes
        try:
            # Try to set the host's owner information as 'owner' to the dict
            flows_fqdn_owner[fqdn]['owner'] = owners[fqdn]
        except KeyError:
            # If hostname not in owner list
            # display error and set 'owner' to None
            print('{} is not in owner list'.format(fqdn))
            flows_fqdn_owner[fqdn]['owner'] = None
        if flows_fqdn_owner[fqdn]['owner'] != None:
            # If owner is "unset" display error message
            if flows_fqdn_owner[fqdn]['owner']['team'] == 'unset':
                print('{0} has no defined owner in owner list'.format(fqdn))
    # Send data to EIS database
    s.execute()
    return flows_fqdn_owner

# group list by teams
def flows_grp_team(flows_owners):
    '''Group hosts and flows by team/owners (key is v2bkey)'''
    assets_grouped_teams = {}
    # in the list of hostname with their flows and hostnames
    for asset,attributes in flows_owners.iteritems():
        if not attributes['owner']:
            # If no owners set, default it to unset-unset
            attributes['owner'] = {}
            attributes['owner']['v2bkey'] = 'unset-unset'
        # Group hostames by v2bkeys
        if not attributes['owner']['v2bkey'] in assets_grouped_teams:
            assets_grouped_teams[attributes['owner']['v2bkey']] = {}
        assets_grouped_teams[attributes['owner']['v2bkey']][asset] = attributes
    return assets_grouped_teams

def team_flows_to_csv(assets_grouped_teams,team):
    '''Return a CSV of flows for a team'''
    full_csv = ''
    team_assets = assets_grouped_teams[team]
    for asset,attributes in team_assets.iteritems():
        # Sort the 2nd row so we don't consider an attachment change when only the order is different
        sorted_flows = sorted(attributes['flows'], key=lambda k: k['dest_ip'])
        for flow in sorted_flows:
            full_csv += "{},{},{}\n".format(asset,flow['dest_ip'],flow['dest_port'])
    return full_csv


def khash(data):
    '''Single place to change hashes of attachments'''
    return hashlib.sha256(data.encode('ascii')).hexdigest()

def bugzilla_actions(config, team, ordered_flows):
    # Retreive specific config for a team
    teamcfg = config['teamsetup'][team]
    bug = find_latest_open_bug(config, team)
    hosts_count = 0
    # If the team has flows and need a bug (update)
    if team in ordered_flows:
        flows_for_team = True
        # Prepare the attachments
        attachment = bugzilla.DotDict()
        attachment.file_name = 'flows_list.csv'
        attachment.summary = 'CSV list of source hostname, destination IP, destination ports'
        attachment.data = team_flows_to_csv(ordered_flows, team)
        hosts_count = len(ordered_flows[team])
    else:
        flows_for_team = False

    bug_title = "[{} hosts] Unproxied HTTP(S) flows to untrust report for {}".format(
                hosts_count, teamcfg['name'])

    bug_body = """This is an automated message resulting of firewall logs analysis for the killchain remediation project.
{hosts_count} hosts are going directly to the internet without using the site proxies.

Please follow this documentation to see if the flow is already permitted through the proxies: {doc_permitted}
Then either file a bug under Infrastructure & Operations: Proxy ACL request or/and follow this doc to configure your servers:
{doc_use_proxies}.

If the host should NOT use the proxies, please document the reason in {exceptions_list}.

Current ownership mapping for all known hosts can be obtained from {eisowners}.

""".format(hosts_count     = hosts_count,
           doc_permitted   = config['doc_permitted'],
           doc_use_proxies = config['doc_use_proxies'],
           eisowners       = config['eisowners'],
           exceptions_list = config['exceptions_list'],
          )


    if ((bug == None) and (flows_for_team)):
        print('Flows found for {0}, creating bug.'.format(team))
        bug_create(config, team, teamcfg, bug_title, bug_body, attachment)
    else:
        #No more vulnerablities? Woot! Close the bug!
        if not flows_for_team:
            close = True
            if (bug == None or len(bug) == 0):
                print('No flows found for {}, no previous bug found, nothing to do!'.format(team))
                return
        else:
            close = False
        update_bug(config, teamcfg, bug_title, bug_body, attachment, bug, close)

def find_latest_open_bug(config, team):
    url = config['bugzilla']['host']
    b = bugzilla.Bugzilla(url=url+'/rest/', api_key=config['bugzilla']['api_key'])
    teamcfg = config['teamsetup'][team]

    terms = [{'product': teamcfg['product']}, {'component': teamcfg['component']},
            {'creator': config['bugzilla']['creator']}, {'whiteboard': 'autoentry'}, {'resolution': ''},
            {'status': 'NEW'}, {'status': 'ASSIGNED'}, {'status': 'REOPENED'}, {'status': 'UNCONFIRMED'},
            {'whiteboard': 'flow2b-key={}'.format(team)}]
    bugs = b.search_bugs(terms)['bugs']
    #Newest only
    try:
        return bugzilla.DotDict(bugs[-1])
    except IndexError:
        return None

def bug_create(config, team, teamcfg, title, body, attachment):
    '''This will create a Bugzilla bug using whatever settings you have for a team in 'teamsetup' '''
    url = config['bugzilla']['host']
    b = bugzilla.Bugzilla(url=url+'/rest/', api_key=config['bugzilla']['api_key'])

    bug = bugzilla.DotDict()
    bug.component = teamcfg['component']
    bug.product = teamcfg['product']
    bug.version = teamcfg['version']
    bug.status = teamcfg['status']
    bug.summary = title
    bug.groups = teamcfg['groups']
    bug.description = body
    #today = toUTC(datetime.now())
    #sla = today + timedelta(days=SLADAYS)
    #bug.whiteboard = 'autoentry v2b-autoclose v2b-autoremind v2b-duedate={} v2b-key={}'.format(sla.strftime('%Y-%m-%d'), team)
    bug.whiteboard = 'autoentry flow2b-autoclose flow2b-key={}'.format(team)
    bug.priority = teamcfg['priority']
    bug.severity = teamcfg['severity']
    bug = b.post_bug(bug)
    print('Created bug {}').format(bug)

    b.post_attachment(bug.id, attachment)
    #bug_update = bugzilla.DotDict()
    #bug_update.blocks.set = config['blocks_bugs']
    #b.put_bug(bug.id, bug_update) //TODO to be uncommented out in prod

def update_bug(config, teamcfg, title, body, attachment, bug, close):
    '''This will update any open bug with correct attributes.
    This check attachments instead of a control hash since it's needed for attachment obsolescence.. its also neat
    anyway.'''
    #Safety stuff - never edit bugs that aren't ours
    #These asserts should normally never trigger
    assert bug.creator == config['bugzilla']['creator']
    assert bug.whiteboard.find('autoentry') != -1

    any_update = False

    url = config['bugzilla']['host']
    b = bugzilla.Bugzilla(url=url+'/rest/', api_key=config['bugzilla']['api_key'])
    print('Checking for updates on {}/{}'.format(url, bug.id))

    #Check if we have to close this bug first (i.e. job's done, hurrai!)
    if (bug.whiteboard.find('flow2b-autoclose') != -1):
        if (close):
            bug_update = bugzilla.DotDict()
            bug_update.resolution = 'fixed'
            bug_update.status = 'resolved'
            b.put_bug(bug.id, bug_update)
            print("Closing bug {}").format(bug.id)
            return

    new_hashes = {}
    new_hashes[khash(attachment.data)] = attachment

    old_hashes = {}
    for a in b.get_attachments(bug.id)[str(bug.id)]:
        a = bugzilla.DotDict(a)
        if a.is_obsolete: continue
        a.data = base64.standard_b64decode(a.data).decode('ascii', 'ignore')
        old_hashes[khash(a.data)] = a

    for h in new_hashes:
        if (h in old_hashes): continue
        a = new_hashes[h]
        for i in old_hashes:
            old_a = old_hashes[i]
            if (old_a.file_name == a.file_name):
                # setting obsolete attachments during the new attachment post does not actually work in the API
                # So we update the old attachment to set it obsolete meanwhile
                a.obsoletes = [old_a.id]
                tmp = bugzilla.DotDict()
                tmp.is_obsolete = True
                tmp.file_name = old_a.file_name
                b.put_attachment(old_a.id, tmp)
        b.post_attachment(bug.id, a)
        any_update = True

    if (any_update):
        #Summary/title update
        bug_update = bugzilla.DotDict()
        bug_update.summary = title
        b.put_bug(bug.id, bug_update)
        print('Updated bug {}/{}'.format(url, bug.id))
    else:
        print('No update for {}/{}'.format(url, bug.id))

def main():
    '''Start here'''

    # Load configuration file
    with open('flow2bugs.json') as fd:
        config = json.load(fd)
    teams_config = config['teamsetup']

    # Download and parse the list of hosts and their owners
    hosts_owners = get_hosts_owners(config['eisowners'])

    raw_splunk_data = query_splunk(config)
    # Group the flows by source IP
    flows_grp_ips = get_flows_grp_ips(config, raw_splunk_data)
    # Resolve IP's PTR record (fqdn), assemble unique FQDN with its owner
    flows_owners = merge_flows_owners(flows_grp_ips,hosts_owners,config)
    #Group couples (source fqdn/owner info) by teams
    ordered_flows = flows_grp_team(flows_owners)

    # Iterate over the 'teamsetup' part of the config
    for team_config in teams_config:
        if 'name' not in teams_config[team_config]:
            # If name attribute is missing, default it to is key.
            teams_config[team_config]['name'] = team_config
        # Create or update bugs for that team
        bugzilla_actions(config, team_config, ordered_flows)

    # Identify "orphan" teams, aka identified as source host owner, but not present in the config
    for team,attributes in ordered_flows.iteritems():
        if team not in teams_config:
            print("Team {} is not defined in config['teamsetup']".format(team))
            # Display matching flows
            print(team_flows_to_csv(ordered_flows, team))

if __name__ == "__main__":
    main()
