#!/usr/bin/python2
# parcels:  Download and distribute CDH parcels


DOCUMENTATION = '''
---
module: parcels
short_description: Manage CDH parcels
description:
    - Manage parcels
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
    parcel_version:
      description:
        - Parcel version.
      required: true
      default: null
    restart_cluster:
      descripion:
        - Restart the cluster after distribute/activate
      required: false
      default: True
    action:
      descripion:
        - Action on parcels - choices map [download, distribute]
      required: true
      default: null
'''

EXAMPLES = '''
# Distribute CDH 5.8.4 parcel
- parcels:
    cm_host: cm.example.com
    cm_username: admin
    cm_password: my-password
    parcel_version:
    action: distribute
  register: cm

'''

import os
import time
import syslog
import sys
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
            cm_version=dict(required=False, type='int', default=10),
            cluster_name=dict(required=False, type='str',default='cluster'),
            parcel_version=dict(required=False, type='str'),
            restart_cluster=dict(required=False, type='bool',default='False'),
            action=dict(choices=['download', 'distribute'])
        )
    )

    cm_host = module.params.get('cm_host')
    cm_port = module.params.get('cm_port')
    cm_username = module.params.get('cm_username')
    cm_password = module.params.get('cm_password')
    cm_tls = module.params.get('cm_tls')
    cm_version = module.params.get('cm_version')
    cluster_name = module.params.get('cluster_name')
    parcel_version = module.params.get('parcel_version')
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
        parcel = cluster.get_parcel('CDH', parcel_version)
    except ApiException as e:
        module.fail_json(changed=changed,
                         msg="Can't connect to CM API: {0}".format(e))

    def restart_cluster(cluster):
        cluster.stop().wait()
        cluster.start().wait()

    if action == "download":
      try:
        parcel.start_download()
        while True:
          parcel = cluster.get_parcel('CDH', parcel_version)
          if parcel.stage == 'DOWNLOADED':
            break
          if parcel.state.errors:
            raise Exception(str(parcel.state.errors))
          time.sleep(15) # check again in 15 seconds
        module.exit_json(changed=True, rc=0)
      except Exception as e:
        module.fail_json(changed=changed, msg="{0}".format(e))

    elif action == 'distribute':
      try:
	parcel.start_distribution()
        while True:
          parcel = cluster.get_parcel('CDH', parcel_version)
	  if parcel.stage in ['DISTRIBUTED','ACTIVATED']:
            break
          if parcel.state.errors:
            raise Exception(str(parcel.state.errors))
          time.sleep(15) # check again in 15 seconds
        parcel.activate()
	
	if restart_cluster:
          module.exit_json(changed=True, msg="wtf")
          restart_cluster(cluster)
        
	module.exit_json(changed=True, rc=0)
      except Exception as e:
        module.fail_json(changed=changed, msg="{0}".format(e))

    #if action == "create"
    #if action == "delete"

    module.exit_json(changed=False, settings=cms.get_config('summary'))

if __name__ == '__main__':
        main()

