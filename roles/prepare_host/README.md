Prerequisites:
0/ create manually the file systems according the needs


1/ Create a local user on all the Hosts from management interface

useradd {{svc_user_local}}
<get password from your team keepass>

2/ Provide passwordless sudo access to this local account

visudo /etc/sudoers and add line :
{{svc_user_local}} ALL=(ALL) NOPASSWD:ALL

3/ Add all the hosts on Platform DNS refering to their final fqdn 
This step is required for Ansible to get access to these hosts

4/ Update the inventory with the new servers as required

5/ Run the ansible script from AdminT2 server using {{svc_user_local}} 

this command will update all hosts from inventory
ansible-playbook -i <inventory> -u {{svc_user_local}} setup.hosts.yml -k


this command will restrict update to specific hosts from inventory (e.g. only new servers)
ansible-playbook -i <inventory> -u {{svc_user_local}} setup.hosts.yml -k --limit <fqdn or group>

e.g. ansible-playbook -i nadc -u svc_bigdata_na_local setup.hosts.yml -k --limit nadc.daas


/usr/java/jdk1.7.0_67-cloudera/jre/bin/keytool -importcert -keystore /opt/cloudera/cdh.truststore -alias ldap.na.bigdata.intraxa -storepass cloudera -file /etc/pki/tls/certs/ldap.na.bigdata.intraxa.crt -noprompt
/usr/java/jdk1.7.0_67-cloudera/jre/bin/keytool -importcert -keystore /opt/cloudera/cdh.truststore -alias AXA_ROOT_CA -storepass cloudera -file /etc/pki/tls/certs/AXA_ROOT_CA.crt -noprompt
/usr/java/jdk1.7.0_67-cloudera/jre/bin/keytool -importcert -keystore /opt/cloudera/cdh.truststore -alias AXA_STD_CA_01 -storepass cloudera -file /etc/pki/tls/certs/AXA_STD_CA_01.crt -noprompt
/usr/java/jdk1.7.0_67-cloudera/jre/bin/keytool -importcert -keystore /opt/cloudera/cdh.truststore -alias bigdata_competency_center_selfsigned_ca -storepass cloudera -file /etc/pki/tls/certs/bigdata_competency_center_selfsigned_ca.crt -noprompt
