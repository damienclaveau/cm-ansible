#!/usr/bin/python2
# template:  create / apply / delete a template to a cluster via CM API

DOCUMENTATION = '''
---
module: template
short_description: Manage templates on the cluster
description:
    - Manage templates
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
        - host to configure.
      required: true
      default: null
    template_name:
      descripion:
        - Host template name
      required: true
      default: null
    restart_cluster:
      descripion:
        - Restart the cluster after configs changes
'''

EXAMPLES = '''
# Apply a template newly created host
- template:
    cm_host: cm.example.com
    cm_username: admin
    cm_password: my-password
    hostname: myhost01
    template_name: workers
    cluster_name: mycluster
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
    from cm_api.endpoints.host_templates import *
    from cm_api.endpoints.cms import ClouderaManager
    from cm_api.endpoints.types import config_to_json, ApiConfig, ApiClusterTemplate
    api_enabled = True
except ImportError:
    api_enabled = False

CMD_TIMEOUT=10


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cm_host=dict(required=True, type='str'),
            cm_port=dict(required=False, type='int', default=7180),
            cm_username=dict(required=True, type='str'),
            cm_password=dict(required=True, type='str', no_log=True),
            cm_tls=dict(required=False, type='bool', default=False),
            cluster_name=dict(required=False, type='str',default='cluster'),
            hostname=dict(required=True, type='str'),
            template_name=dict(required=True, type='str'),
	    cm_version=dict(required=False, type='int', default=13),
	    redeploy_config=dict(required=False, type='bool',default='True'),
            action=dict(choices=['create', 'apply', 'delete','config'])
        )
    )

    cm_host = module.params.get('cm_host')
    cm_port = module.params.get('cm_port')
    cm_username = module.params.get('cm_username')
    cm_password = module.params.get('cm_password')
    cm_tls = module.params.get('cm_tls')
    cluster_name = module.params.get('cluster_name')
    hostname = module.params.get('hostname')
    template_name = module.params.get('template_name')
    cm_version = module.params.get('cm_version')   
    redeploy_config = module.params.get('redeploy_config')
    action = module.params.get('action')

    changed = False

    if not api_enabled:
        module.fail_json(changed=changed, msg='cm_api required for this module')

    try:
        resource = ApiResource(cm_host, server_port=cm_port,
                                  username=cm_username,
                                  password=cm_password,
                                  use_tls=cm_tls,
                                  version=cm_version)
        cluster = resource.get_cluster(cluster_name)
	template = cluster.get_host_template(template_name)
    except ApiException as e:
        module.fail_json(changed=changed,
                         msg="Can't connect to CM API: {0}".format(e))

    def redeploy_client_config(cluster):
        cluster.deploy_client_config()

    if action == "apply":
        try:
          host = list()
          host.append(hostname)
	  cmd = template.apply_host_template(host,True)
          while True:
                if cmd.wait(CMD_TIMEOUT).success:
                        break
          cluster.deploy_client_config()
	  module.exit_json(changed=True, rc=0)
        except Exception as e:
          module.fail_json(changed=changed, msg="{0}".format(e))

    if action == "config":
	try:
		redeploy_client_config(cluster)
		module.exit_json(changed=True, rc=0)
	except Exception as e:
		module.fail_json(changed=changed, msg="{0}".format(e))

    module.exit_json(changed=False, settings=cms.get_config('summary'))

if __name__ == '__main__':
        main()

