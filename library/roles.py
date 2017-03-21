#!/usr/bin/python2
# roles:  create / apply / delete a role from the cluster via CM API

DOCUMENTATION = '''
---
module: role
short_description: Manage host roles on the cluster
description:
    - Manage roles
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
    service_name:
      descripion:
        - Service name
      required: true
      default: null
    role_type:
      descripion:
        - Role type
      required: true
      default: null
    role_name:
      descripion:
        - Role name
      required: true
      default: null
    action:
      descripion:
        - Action choices [create, delete, update, add, move]
      required: true
    restart_role:
      descripion:
        - Wether restart or not
      required: false
'''

EXAMPLES = '''
# Create a new role
- roles:
    cm_host: cm.example.com
    cm_username: admin
    cm_password: my-password
    hostname: myhost01
    service_name: HDFS
    role_type: DATANODE
    role_name: DN
    action: create
    restart_role: true
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
            cluster_name=dict(required=False, type='str',default='cluster01'),
            hostname=dict(required=True, type='str'),
            service_name=dict(required=True, type='str'),
            role_type=dict(required=True, type='str'),
            role_name=dict(required=True, type='str'),
            restart_role=dict(required=False, type='bool', default=True),
            action=dict(choices=['create', 'delete', 'update'])
        )
    )

    cm_host = module.params.get('cm_host')
    cm_port = module.params.get('cm_port')
    cm_username = module.params.get('cm_username')
    cm_password = module.params.get('cm_password')
    cm_tls = module.params.get('cm_tls')
    cluster_name = module.params.get('cluster_name')
    hostname = module.params.get('hostname')
    service_name = module.params.get('service_name')
    role_type = module.params.get('role_type')
    role_name = module.params.get('role_name')
    restart_role = module.params.get('restart_role')
    action = module.params.get('action')

    changed = False
    start_roles = True
    cmd_timeout = 420

    if not api_enabled:
        module.fail_json(changed=changed, msg='cm_api required for this module')

    try:
        resource = ApiResource(cm_host, server_port=cm_port,
                                  username=cm_username,
                                  password=cm_password,
                                  use_tls=cm_tls,
                                  version=cm_version)
        cms = ClouderaManager(api)
        cluster = resource.get_cluster(cluster_name)
        service = cluster.get_service(service_name)
    except ApiException as e:
        module.fail_json(changed=changed,
                         msg="Can't connect to CM API: {0}".format(e))

    def restart_roles():
        global service
        print "Restarting role %s on host %s in role group %s" % (role_name, host_name, role_name)
          try:
            role = service.get_role(agent_name)
            cmds = service.restart_roles(role.name)
            for cmd in cmds:
              print " Waiting for restart..."
              cmd.wait(CMD_TIMEOUT)
              print "Role restarted."
          except ApiException as err:
              "Failed to restart role %s on host %s in role group %s. %s"
                  % (role_name, host_name, role_name, err.message)


    if action == "create":
        print "Checking if role group %s exists. It will be created if not." % role_name
        try:
          service.create_role_config_group(role_name, role_name, role_type)
          print " Role group %s created." % role_name
          module.exit_json(changed=True, rc=0)
        except Exception as e:
          print " Role group %s already exists." % role_name
          module.fail_json(changed=changed, msg="{0}".format(e))

    elif:
      action == "update":
        try:
          role_group = service.get_role_config_group(role_name)
          ## Read the config file
          f = open(config_file,'r')
          role_conf = ""
          while 1:
          line = f.readline()
          if not line:break
          role_conf += line
          f.close()

          ## Update the role group configuration
          print "Updating role group configuration."
          role_group.update_config({"config_file" : role_conf})
            if restart_role:
              restart_roles()

        except Exception as e:
          module.fail_json(changed=changed, msg="{0}".format(e))
    elif:
      action == "add":
        try:
          print "Checking if role '%s' exists. It will be created if not." % role_name
          hostID = resource.get_host(hostname).hostId
          role = service.create_role(role_type = role_type, role_name = role_name, host_id = hostID)
          if restart_role:
              restart_roles()
        except Exception as e:
          print " Role '%s' already exists." % role_name
          module.fail_json(changed=changed, msg="{0}".format(e))
    elif:
      action == "move":
        try:
          print "Moving host '%s' to role group '%s'" % (host_name, role_name)
          role_group.move_roles([role.name])
          if restart_role:
              restart_roles()
        except Exception as e:
          module.fail_json(changed=changed, msg="{0}".format(e))


    module.exit_json(changed=False, settings=cms.get_config('summary'))

if __name__ == '__main__':
        main()

