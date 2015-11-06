#!/usr/bin/env python

import pyfscache
import logging
import json
import yaml
import base64
import importlib
import os
import sys
import argparse
import re
import time

UUID_RE = re.compile('[0-9a-f\-]{36}\Z', re.I)

fscache = pyfscache.FSCache("/tmp/.inv-cache", seconds=120)

from collections import defaultdict


try:
    from kamaki.cli import config as kamaki_config
except ImportError:
    sys.stderr.write("\nKamaki library is required. `pip install kamaki`")
    exit(0)

from kamaki.clients.utils import https
from kamaki.clients.astakos import AstakosClient, parse_endpoints
from kamaki.cli import _setup_logging

from astakosclient.errors import NoEndpoints


class CloudClient(object):

    clients_map_override = {
        'cyclades': {'endpoint': 'compute'}
    }

    clients_override = {
        'network': 'cyclades_network'
    }

    def __init__(self, config, cloud=None, debug=False):
        _setup_logging(debug, debug)

        self.config = kamaki_config.Config(config)
        self.cloud = cloud

        if not self.cloud:
            self.cloud = self.config.get("global", "default_cloud")

        self.ignore_ssl = \
            self.config.get("global", "ignore_ssl").lower() == "on"
        self.ca_certs = \
            self.config.get("global", "ca_certs")
        https.patch_ignore_ssl(self.ignore_ssl)
        if self.ca_certs is not None:
            https.patch_with_certs(self.ca_certs)
        self.auth_url = self.config.get_cloud(self.cloud, "url")
        self.token = self.config.get_cloud(self.cloud, "token")
        self.auth_client = AstakosClient(self.auth_url, self.token)
        self.endpoints = None  # lazyness

    def fill_endpoints(self):
        self.endpoints = self.auth_client.authenticate()

    def get_cli(self, name):
        name = self.clients_override.get(name, name)
        if not self.endpoints:
            self.fill_endpoints()

        ns = name.split("_")[0].lower()
        normalized = name.replace("_", " ").title().replace(" ", "")
        import_path = self.clients_map_override.get(name, {}).get('module',
                                                                  None)
        if not import_path:
            import_path = 'kamaki.clients.%s.%s' % (ns, normalized + 'Client')

        module_name = ".".join(import_path.split(".")[:-1])
        cli_name = import_path.split(".")[-1]
        module = importlib.import_module(module_name)

        endpoint_type = self.clients_map_override.get(
            name, {}).get('endpoint', ns)
        try:
            catalog = parse_endpoints(self.endpoints, ep_type=endpoint_type)
        except NoEndpoints, e:
            if "_" not in name:
                raise e
            endpoint_type = name.split("_")[1]
            catalog = parse_endpoints(self.endpoints, ep_type=endpoint_type)

        endpoint = catalog[0]['endpoints'][0]['publicURL']
        return module.__dict__[cli_name](endpoint, self.token)

    def __getattr__(self, name):
        if name not in self.__dict__:
            return self.get_cli(name)
        return object.__getattribute__(self, name)


class SNFProvisioner(object):

    def __init__(self, cfg=None, kamaki_cfg=None, debug=False):
        self.debug = debug
        self.kamaki_cfg = kamaki_cfg
        self.config = {}
        if cfg is not None:
            fd = file(cfg)
            self.config.update(yaml.load(fd))

        self.clouds = self.config.get('clouds', [None])
        self.clouds_id = ",".join(map(lambda x: x or 'None', sorted(self.clouds)))
        self.clients = {}
        self.logger = logging.getLogger('snf_provision')
        self.logger.addHandler(logging.StreamHandler(sys.stdout))
        self.logger.setLevel(logging.DEBUG)

        for cloud in self.clouds:
            self.clients[cloud] = CloudClient(self.kamaki_cfg, cloud, debug)

    def get_flavor(self, meta, client):
        if meta.get('id', None):
            return meta.get('id')

        cpu = meta.get('cpu')
        ram = meta.get('ram')
        disk = meta.get('disk')
        disk_type = meta.get('disk_type', 'drbd')
        flavor_name = 'C%sR%sD%s%s' % (cpu, ram, disk, disk_type)
        flavor_id = None
        for flavor in client.compute.list_flavors():
            if flavor['name'] == flavor_name:
                flavor_id = flavor['id']
        return flavor_id

    def get_image(self, image, client):

        if isinstance(image, basestring) and UUID_RE.match(image):
            return image.strip()

        image_name = None
        image_user = None

        if isinstance(image, dict):
            image_name = image.get('name', None)
            image_user = image.get('user', None)

        if isinstance(image, basestring):
            image_name = image

        if image_name is None and image_user is None:
            return None

        images = client.compute.list_images(detail=True)
        _name_re = None
        if image_name:
            _name_re = re.compile(".*%s.*" % image_name)
        _user_re = None
        if image_user:
            _user_re = re.compile(".*%s.*" % image_user)

        image_id = None
        _found = False
        for image in images:
            if _found:
                break

            _name_found = False
            _name = image['name'] + ' ' + \
                image.get('metadata', {}).get('description', '')

            if _name_re and _name_re.match(_name):
                print "NAME FOUND", _name
                _name_found = True

            if not _user_re:
                if _name_found:
                    _found = image
                continue

            _user_id = image['user_id']
            _username = client.auth_client.get_username(_user_id)
            if _user_re and _user_re.match(_username) and _name_found:
                _found = image

        if _found:
            self.logger.info("Resolved image to %s (%s)" %
                             (_found['name'], _found['id']))
            image_id = _found['id']

        return image_id

    def get_client(self, cloud):
        return self.clients.get(cloud, self.clients.values()[0])

    def get_project(self, data, client=None):
        token = client.auth_client.authenticate()['access']['token']
        user_project_id = token['tenant']['id']
        default_project_id = self.config.get('project', user_project_id)
        project_id = data.get('project', default_project_id)

        if UUID_RE.match(project_id):
            return project_id

        project_name = None
        if isinstance(project_id, dict):
            project_name = project_id.get('name')
        if isinstance(project_id, basestring):
            project_name = project_id

        if project_name is None:
            return None

        project_id = None
        _re = re.compile(".*" + project_name + ".*")
        for project in client.auth_client.get_projects():
            match = project['name']
            if _re.match(match):
                project_id = project['id']
        return project_id

    def provision(self, sleep=45, dryrun=False):
        fscache.purge()
        conf = self.config.get('provision', {})

        for network, meta in conf.get('networks').iteritems():
            client = self.get_client(meta.get('cloud'))
            networks = self.networks()
            if network in map(lambda x: x['name'], networks.values()):
                self.logger.info("Network %r already exists" % network)
                continue
            self.logger.info("Provisioning network %r" % network)
            project_id = self.get_project(meta, client)
            _net = {'id': 'None'}
            if not dryrun:
                _net = client.network.create_network(name=network,
                                                    type=meta.get('type'),
                                                    project_id=project_id)
            self.logger.info("Network %r created with id %r" %
                             (network, _net['id']))

            netid = _net.get('id')
            dhcp = meta.get('enable_dhcp', False)
            gwip = meta.get('gateway_ip', '')
            cidr = meta.get('cidr', None)
            create = client.network.create_subnet
            _subnet = {'id': 'None'}
            if not dryrun:
                _subnet = create(network_id=netid, enable_dhcp=dhcp,
                                 gateway_ip=gwip, cidr=cidr)
            self.logger.info("Subnet %r created with id %r" % (cidr,
                                                               _subnet['id']))

        machines = self.machines()
        allnets = self.networks()
        ips = None

        _conf_machines = conf.get('machines', {})
        keys = sorted(_conf_machines.keys())

        for key in keys:
            fscache.purge()
            machine = key
            meta = _conf_machines.get(key)

            create_server = True
            client = self.get_client(meta.get('cloud'))
            project = self.get_project(meta, client)

            metadata = {}
            metadata['groups'] = ",".join(meta.get('groups', []))
            metadata['snf_machine_name'] = machine
            metadata['ansible_vars'] = json.dumps(meta.get('vars', {}))

            if machine in machines:
                self.logger.info("Machine %r already exists" % machine)
                _machine_id = machines[machine]['vars']['snf_machine_id']
                remote_meta = client.compute.get_server_metadata(_machine_id)
                changed = []
                for key, val in metadata.iteritems():
                    if key in remote_meta:
                        if remote_meta[key] != metadata[key]:
                            changed.append(key)
                            remote_meta[key] = metadata[key]
                    else:
                        changed.append(key)
                        remote_meta[key] = metadata[key]
                if changed:
                    self.logger.info("\tUpdating server metadata")
                    if not dryrun:
                        client.compute.update_server_metadata(_machine_id,
                                                            **remote_meta)
                continue

            ports = []
            networks = []
            for network, _meta in meta.get('networks', {}).iteritems():
                netid = None
                for _net in allnets.values():
                    if network == _net['name']:
                        netid = _net['id']
                ips = None
                if isinstance(_meta, dict):
                    ips = [{'ip_address': _meta.get('ip', None)}]
                if isinstance(_meta, basestring):
                    # ip as value
                    ips = [{'ip_address': _meta}]
                try:
                    if netid is None:
                        raise Exception("%r network does not exist" % network)
                    port = {'id': 'None'}
                    if not dryrun:
                        port = client.network.create_port(
                            network_id=netid,
                            fixed_ips=ips)
                        ports.append({'uuid': netid, 'port': port['id']})
                    self.logger.info("Created port %r connected to %r" %
                                     (port['id'], network))
                except Exception, e:
                    # cleanup ports
                    for port in client.network.list_ports():
                        if port['status'] == 'DOWN':
                            client.network.delete_port(port['id'])
                    create_server = False
                    self.logger.exception(e)

            ips = []
            created_ips = []
            for ip in meta.get('floating_ips', []):
                if ip == 'auto':
                    # TODO: find spare
                    # if no spare available, create one
                    create = client.network.create_floatingip
                    try:
                        ip = {'floating_ip_address': 'None'}
                        if not dryrun:
                            ip = create(project_id=project)
                            ips.append({'uuid': ip['floating_network_id'],
                                        'fixed_ip': ip['floating_ip_address']})
                            created_ips.append(ip['id'])
                        self.logger.info("Created floating ip %r" %
                                         ip['floating_ip_address'])
                    except Exception, e:
                        create_server = False
                        self.logger.exception(e)
                else:
                    floating = client.network.list_floatingips()
                    found = False
                    for _ip in floating:
                        if _ip['floating_ip_address'] == ip:
                            found = True
                            ips.append({
                                'uuid': _ip['floating_network_id'],
                                'fixed_ip': _ip['floating_ip_address']
                            })
                    if not found:
                        self.logger.error("%s floating ip not found" % ip)
                        create_server = False

            name = machine
            image_id = self.get_image(meta.get('image', None), client)
            keys = map(lambda k: file(k).read(), meta.get('keys', []))
            flavor = self.get_flavor(meta.get('flavor', {}), client)
            networks = []
            networks += ips
            networks += ports

            personality = []
            files = meta.get('files', [])

            for attch in files:
                contents = attch.get('contents', '')
                if os.path.exists(contents):
                    with file(contents) as f:
                        contents = f.read()
                contents = base64.b64encode(contents)
                entry = dict(attch)
                entry['contents'] = contents
                personality.append(entry)

            for key in keys:
                for user in meta.get('users', ['root']):
                    user_home = 'home/%s' % user
                    if user == 'root':
                        user_home = 'root'
                    personality.append({
                        'path': '/%s/.ssh/authorized_keys' % user_home,
                        'contents': base64.b64encode(key),
                        'mode': 384,
                        'owner': '%s' % user
                    })

            if create_server:
                try:
                    server = {'id': 'None'}
                    if not dryrun:
                        server = client.cyclades.create_server(
                            name=name,
                            image_id=image_id,
                            project_id=project,
                            personality=personality,
                            metadata=metadata,
                            networks=networks,
                            flavor_id=flavor
                        )
                        time.sleep(sleep)
                    self.logger.info("Machine %s created %r" % (name,
                                                                server['id']))
                except Exception, e:
                    create_server = False
                    self.logger.exception(e)

            if not create_server:
                for ip in created_ips:
                    self.logger.info("Deleting redundant IP")
                    client.network.delete_floatingip(ip)
                for port in ports:
                    self.logger.info("Deleting redundant ports")
                    client.network.delete_port(port['port'])

    def networks(self):
        networks = {}
        for client in self.clients.values():
            for network in client.network.list_networks():
                networks[network['name'] + network['id']] = network
        return networks

    def machines(self, hosts_only=False, prefix=None):

        if prefix is None:
            prefix = os.environ.get('SNFINV_PREFIX', None)
        if hosts_only and self.clouds_id + 'hosts' in fscache:
            return fscache[self.clouds_id + 'hosts']
        if self.clouds_id + 'all' in fscache:
            return fscache[self.clouds_id + 'all']

        machines = []
        hosts = {}
        _networks = self.networks()
        networks = {}
        for key, data in _networks.iteritems():
            networks[data['id']] = data

        ret = defaultdict(lambda: {'children': [], 'vars': {}})

        for client in self.clients.itervalues():
            machines = client.compute.list_servers(detail=True)

            for machine in machines:
                metadata = machine.get('metadata', {})
                groups = filter(bool, metadata.get(
                    'groups', '').split(","))

                if not groups:
                    continue

                machine_host = machine.get('SNF:fqdn')
                machine_vars = {'snf_kamaki_cloud': client.cloud,
                                'snf_machine_id': machine['id']}
                machine_id = metadata.get('snf_machine_name',
                                          machine_host)
                machine_vars['snf_machine_name'] = machine_id

                if prefix and not machine_id.startswith(prefix):
                    continue

                for key, meta in machine.get('metadata', {}).iteritems():
                    if key == 'ansible_vars':
                        metavars = json.loads(meta)
                        machine_vars.update(metavars)
                        continue
                    if key.startswith('ansible_'):
                        machine_vars[key] = meta

                if machine_id:
                    ips = {}
                    ips_list = []
                    for ip in machine.get('attachments'):
                        if not ip['network_id'] in networks:
                            continue
                        _ip = ip['ipv4'] or ip['ipv6']
                        name = networks[ip['network_id']]['name']
                        if 'Public' in name:
                            name = 'public'
                            if ip['ipv6']:
                                name = 'public_v6'
                        ips[name] = _ip
                        ips_list.append(_ip)

                    if 'public' not in ips and 'public_v6' in ips:
                        ips['public'] = ips['public_v6']
                    machine_vars['snf_ips'] = ips
                    machine_vars['snf_ips_list'] = ips_list
                    hosts[machine_id] = {
                        'hosts': [machine_host],
                        'vars': machine_vars
                    }

                for group in groups:
                    _vars = self.config.get('group_vars', {}).get(group, None)
                    if _vars:
                        ret[group]['vars'].update(_vars)
                    ret[group]['children'].append(machine_id)

            if hosts_only:
                hosts = dict(hosts)
                fscache[self.clouds_id + 'hosts'] = hosts
                return hosts

            ret.update(hosts)
            ret = dict(ret)
            fscache[self.clouds_id + 'all'] = ret
            return ret


def main():
    _kamaki_config = os.getenv("HOME") + "/.kamakirc"
    parser = argparse.ArgumentParser(
        description="Provision deis cluster on synnefo cloud")
    parser.add_argument("--config", default=None)
    parser.add_argument("--kamaki-config", default=_kamaki_config)
    parser.add_argument("--host", default=None)
    parser.add_argument("--list", action="store_true", default=True)
    parser.add_argument("--sleep", default=5)
    parser.add_argument("--prefix", default=None)
    parser.add_argument("--list-hosts", action="store_true")
    parser.add_argument("--provision", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--dry", action="store_true")
    parser.add_argument("--no-cache", action="store_true", default=False)
    args = parser.parse_args()

    if args.no_cache:
        fscache.purge()

    if args.config is None and os.path.exists("./inventory.yml"):
        args.config = os.environ.get("SNFINV_CONFIG", "./inventory.yml")

    provisioner = SNFProvisioner(args.config, args.kamaki_config, args.debug)
    if args.provision:
        provisioner.provision(sleep=int(args.sleep), dryrun=args.dry)
        exit()

    if args.host:
        machines = provisioner.machines(hosts_only=True, prefix=args.prefix)
        _vars = machines.get(args.host, {'vars': {}}).get('vars')
        print json.dumps(_vars, indent=4)
        exit()

    if args.list_hosts:
        args.list = False

    if args.list:
        machines = provisioner.machines(hosts_only=False, prefix=args.prefix)
        print json.dumps(machines, indent=4)

    if args.list_hosts:
        machines = provisioner.machines(hosts_only=True, prefix=args.prefix)
        keys = sorted(machines.keys())
        for key in keys:
            machine = key
            data = machines.get(key)
            if data.get('children'):
                continue
            ip = data.get('vars').get('snf_ips').get('public')
            host = data.get('hosts')[0]
            print "%s\t%s\t#  %s" % (ip, machine, host)
    exit()

if __name__ == "__main__":
    main()
