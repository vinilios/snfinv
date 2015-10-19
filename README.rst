******
snfinv
******

`snfinv` is a a simplistic virtual machine provision and dynamic ansible 
inventory tool to be used on Synnefo IaaS deployments.


Install
=======

Install using `pip`::

    $ pip install snfinv


Provisioning
============

Create an `inventory.yml` and define your nodes configuration::

    provision:
        networks:
            priv1:
                type: MAC_FILTERED
                cidr: 10.12.21.0/24

        coreos_node1:
            project: xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx 
            flavour:
                cpu: 2
                ram: 1024
                disk: 10
            image: b9236d02-0904-4d00-8967-3279f0053d18 // CoreOS image
            floating_ips: [auto, 83.212.221.53]
            groups: ['sql']
            keys: ['/home/user/.ssh/id_rsa.pub']
            users: ['core']
            networks:
                priv1:
                    ip: 10.12.21.1
            vars:
                ansible_var1: 'value'

        coreos_node2:
            project: xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx 
            flavour:
                cpu: 2
                ram: 1024
                disk: 10
            image: b9236d02-0904-4d00-8967-3279f0053d18 // CoreOS image
            floating_ips: [auto]
            groups: ['web']
            keys: ['/home/user/.ssh/id_rsa.pub']
            users: ['core']
            networks:
                priv1:
                    ip: 10.12.21.1
            vars:
                ansible_var1: 'value'

You can then provision the above specification by running within the directory 
the file above was created::

    $ snfinv --provision

Provision script is reentrant and it won't try to recreate existing resources
but it is not smart enough to delicately re-assemble flimsy configuration
changes such as changes of vm flavor/ips/keys etc.


Ansible inventory
=================

`snfinv` tool provides the required command line interface to be able to use 
is as a dynamic ansible inventory::

    $ ansible `which snfinv` "coreos_node2" -m shell -a ls


Additional arguments
====================

* **--dry**

  Used in conjuction with `--provision`. If set no calls will be sent to the
  synnefo api endpoints.
 
* **--list-hosts**

  Outputs `/etc/hosts` friendly list of the available nodes.

* **--config=<path-to-inventory.yml>**

  Provide a custom `inventory.yml` file. By default `./inventory.yml` is used.
  `SNFINV_CONFIG` environment variable may also be used to declare the path 
  to the provision configuration file.
 
* **--kamaki-config**

  Use a custom location for the kamaki config file.
