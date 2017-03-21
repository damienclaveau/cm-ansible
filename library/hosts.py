#!/usr/bin/python2
# parcels:  Manage hosts within Cloudera manager.


DOCUMENTATION = '''
---
module: hosts
short_description: Manage CM hosts
description:
    - Manage hosts
options:
    cm_host:
      description:
        - Cloudera Manager hostname.
      required: true
      default: null
    cm_port:
      description:
        - Cloudera Manager port.
      required: false
      default: 7180
    cm_username:
      description:
        - Cloudera Manager user.
      required: true
      default: null
    cm_password:
      description:
        - Cloudera Manager password.
      required: true
      default: null
    cluster_name:
      description:
        - Cluster name.
      required: true
      default: null
    hostname:
      description:
        - Host name.
      required: true
      default: null
    restart_cluster:
      descripion:
        - Restart the cluster after distribute/activate
      required: false
      default: True
    action:
      descripion:
        - Action on host - choices map [add, delete]
      required: true
      default: null
'''

EXAMPLES = '''
# Distribute CDH 5.8.4 parcel
- parcels:
    cm_host: cm.example.com
    cm_username: admin
    cm_password: my-password
    hostname: ip-172-31-8-95.us-west-2.compute.internal
    action: add
  register: cm

'''

import os
import time
import syslog
import sys
import socket
from ansible.module_utils.basic import *

try:
    from cm_api.api_client import *
    from cm_api import *
    from cm_api.endpoints.cms import ClouderaManager
    from cm_api.endpoints.types import config_to_json, ApiConfig
    api_enabled = True
except ImportError:
    api_enabled = False


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cm_host=dict(required=True, type='str'),
            cm_port=dict(required=False, type='int', default=7180),
            cm_username=dict(required=True, type='str'),
            cm_password=dict(required=True, type='str', no_log=True),
            cm_tls=dict(required=False, type='bool', default=False),
            cluster_name=dict(required=False, type='str',default='cluster'),
            cm_version=dict(required=False, type='str',default='13'),
            hostname=dict(required=True, type='str'),
            restart_cluster=dict(required=False, type='str',default='True'),
            action=dict(choices=['add', 'delete'])
        )
    )

    cm_host = module.params.get('cm_host')
    cm_port = module.params.get('cm_port')
    cm_username = module.params.get('cm_username')
    cm_password = module.params.get('cm_password')
    cm_tls = module.params.get('cm_tls')
    cm_version = module.params.get('cm_version')
    cluster_name = module.params.get('cluster_name')
    restart_cluster = module.params.get('restart_cluster')
    hostname = module.params.get('hostname')
    action = module.params.get('action')

    changed = False
    start_roles = True

    if not api_enabled:
        module.fail_json(changed=changed, msg='cm_api required for this module')

    try:
        resource = ApiResource(cm_host, server_port=cm_port,
                                  username=cm_username,
                                  password=cm_password,
                                  use_tls=cm_tls,
                                  version=cm_version)
        cluster = resource.get_cluster(cluster_name)
    except ApiException as e:
        module.fail_json(changed=changed,
                         msg="Can't connect to CM API: {0}".format(e))

    def restart_cluster():
        global cluster
        cluster.stop().wait()
        cluster.start().wait()

    if action == "add":
      try:
	#hostID = "e2b55696-63c7-451f-ba98-bc71031544bc"
	host = []
	#host = resource.get_host(hostname)
        #host = resource.create_host(
        #  hostname,
        #  hostname,
        #  socket.gethostbyname(hostname),
        #  "/default")
	#time.sleep(20)
	host.append(hostname)
        cluster.add_hosts(host)
        module.exit_json(changed=True, rc=0)
      except Exception as e:
        module.fail_json(changed=changed, msg="{0}".format(e))
    
    #elif action == 'delete':


    module.exit_json(changed=False, settings=cms.get_config('summary'))

if __name__ == '__main__':
        main()


