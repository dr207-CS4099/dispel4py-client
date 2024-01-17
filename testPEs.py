from dispel4py.core import GenericPE
from dispel4py.base import IterativePE, ConsumerPE, ProducerPE
class Pub_connect(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Create and connect this thread's zmq socket. If a publisher socket
            already exists "pub_close" is called before creating and connecting a
            new socket.
            '''
            if self.pub_sock:
                self.pub_close()
            ctx = zmq.Context.instance()
            self._sock_data.sock = ctx.socket(zmq.PUSH)
            self.pub_sock.setsockopt(zmq.LINGER, -1)
            if self.opts.get('ipc_mode', '') == 'tcp':
                pull_uri = 'tcp://127.0.0.1:{0}'.format(
                    self.opts.get('tcp_master_publish_pull', 4514)
                    )
            else:
                pull_uri = 'ipc://{0}'.format(
                    os.path.join(self.opts['sock_dir'], 'publish_pull.ipc')
                    )
            log.debug("Connecting to pub server: %s", pull_uri)
            self.pub_sock.connect(pull_uri)
            return self._sock_data.sock
class Removed(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Ensure that the named snap package is not installed
    
        name
            The snap package
        '''
    
        ret = {'name': name,
               'changes': {},
               'pchanges': {},
               'result': None,
               'comment': ''}
    
        old = __salt__['snap.versions_installed'](name)
        if not old:
            ret['comment'] = 'Package {0} is not installed'.format(name)
            ret['result'] = True
            return ret
    
        if __opts__['test']:
            ret['comment'] = 'Package {0} would have been removed'.format(name)
            ret['result'] = None
            ret['pchanges']['old'] = old[0]['version']
            ret['pchanges']['new'] = None
            return ret
    
        remove = __salt__['snap.remove'](name)
        ret['comment'] = 'Package {0} removed'.format(name)
        ret['result'] = True
        ret['changes']['old'] = old[0]['version']
        ret['changes']['new'] = None
        return ret
class _get_queue(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, config):
        '''
        Check the context for the notifier and construct it if not present
        '''
    
        if 'watchdog.observer' not in __context__:
            queue = collections.deque()
            observer = Observer()
            for path in config.get('directories', {}):
                path_params = config.get('directories').get(path)
                masks = path_params.get('mask', DEFAULT_MASK)
                event_handler = Handler(queue, masks)
                observer.schedule(event_handler, path)
    
            observer.start()
    
            __context__['watchdog.observer'] = observer
            __context__['watchdog.queue'] = queue
    
        return __context__['watchdog.queue']
class Beacon(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, config):
        '''
        Watch the configured directories
    
        Example Config
    
        .. code-block:: yaml
    
            beacons:
              watchdog:
                - directories:
                    /path/to/dir:
                      mask:
                        - create
                        - modify
                        - delete
                        - move
    
        The mask list can contain the following events (the default mask is create,
        modify delete, and move):
        * create  - File or directory is created in watched directory
        * modify  - The watched directory is modified
        * delete  - File or directory is deleted from watched directory
        * move    - File or directory is moved or renamed in the watched directory
        '''
    
        _config = {}
        list(map(_config.update, config))
    
        queue = _get_queue(_config)
    
        ret = []
        while queue:
            ret.append(to_salt_event(queue.popleft()))
    
        return ret
class Bounce_cluster(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Bounce all Traffic Server nodes in the cluster. Bouncing Traffic Server
        shuts down and immediately restarts Traffic Server, node-by-node.
    
        .. code-block:: yaml
    
            bounce_ats_cluster:
              trafficserver.bounce_cluster
        '''
        ret = {'name': name,
               'changes': {},
               'result': None,
               'comment': ''}
    
        if __opts__['test']:
            ret['comment'] = 'Bouncing cluster'
            return ret
    
        __salt__['trafficserver.bounce_cluster']()
    
        ret['result'] = True
        ret['comment'] = 'Bounced cluster'
        return ret
class Clear_cluster(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Clears accumulated statistics on all nodes in the cluster.
    
        .. code-block:: yaml
    
            clear_ats_cluster:
              trafficserver.clear_cluster
        '''
        ret = {'name': name,
               'changes': {},
               'result': None,
               'comment': ''}
    
        if __opts__['test']:
            ret['comment'] = 'Clearing cluster statistics'
            return ret
    
        __salt__['trafficserver.clear_cluster']()
    
        ret['result'] = True
        ret['comment'] = 'Cleared cluster statistics'
        return ret
class Clear_node(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Clears accumulated statistics on the local node.
    
        .. code-block:: yaml
    
            clear_ats_node:
              trafficserver.clear_node
        '''
        ret = {'name': name,
               'changes': {},
               'result': None,
               'comment': ''}
    
        if __opts__['test']:
            ret['comment'] = 'Clearing local node statistics'
            return ret
    
        __salt__['trafficserver.clear_node']()
    
        ret['result'] = True
        ret['comment'] = 'Cleared local node statistics'
        return ret
class Restart_cluster(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Restart the traffic_manager process and the traffic_server process on all
        the nodes in a cluster.
    
        .. code-block:: bash
    
            restart_ats_cluster:
              trafficserver.restart_cluster
    
        '''
        ret = {'name': name,
               'changes': {},
               'result': None,
               'comment': ''}
    
        if __opts__['test']:
            ret['comment'] = 'Restarting cluster'
            return ret
    
        __salt__['trafficserver.restart_cluster']()
    
        ret['result'] = True
        ret['comment'] = 'Restarted cluster'
        return ret
class Shutdown(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Shut down Traffic Server on the local node.
    
        .. code-block:: yaml
    
            shutdown_ats:
              trafficserver.shutdown
        '''
        ret = {'name': name,
               'changes': {},
               'result': None,
               'comment': ''}
    
        if __opts__['test']:
            ret['comment'] = 'Shutting down local node'
            return ret
    
        __salt__['trafficserver.shutdown']()
    
        ret['result'] = True
        ret['comment'] = 'Shutdown local node'
        return ret
class Startup(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Start Traffic Server on the local node.
    
        .. code-block:: yaml
    
            startup_ats:
              trafficserver.startup
        '''
        ret = {'name': name,
               'changes': {},
               'result': None,
               'comment': ''}
    
        if __opts__['test']:
            ret['comment'] = 'Starting up local node'
            return ret
    
        __salt__['trafficserver.startup']()
    
        ret['result'] = True
        ret['comment'] = 'Starting up local node'
        return ret
class Refresh(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Initiate a Traffic Server configuration file reread. Use this command to
        update the running configuration after any configuration file modification.
    
        The timestamp of the last reconfiguration event (in seconds since epoch) is
        published in the proxy.node.config.reconfigure_time metric.
    
        .. code-block:: yaml
    
            refresh_ats:
              trafficserver.refresh
        '''
        ret = {'name': name,
               'changes': {},
               'result': None,
               'comment': ''}
    
        if __opts__['test']:
            ret['comment'] = 'Refreshing local node configuration'
            return ret
    
        __salt__['trafficserver.refresh']()
    
        ret['result'] = True
        ret['comment'] = 'Refreshed local node configuration'
        return ret
class Zero_cluster(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Reset performance statistics to zero across the cluster.
    
        .. code-block:: yaml
    
            zero_ats_cluster:
              trafficserver.zero_cluster
        '''
        ret = {'name': name,
               'changes': {},
               'result': None,
               'comment': ''}
    
        if __opts__['test']:
            ret['comment'] = 'Zeroing cluster statistics'
            return ret
    
        __salt__['trafficserver.zero_cluster']()
    
        ret['result'] = True
        ret['comment'] = 'Zeroed cluster statistics'
        return ret
class Zero_node(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Reset performance statistics to zero on the local node.
    
        .. code-block:: yaml
    
            zero_ats_node:
              trafficserver.zero_node
        '''
        ret = {'name': name,
               'changes': {},
               'result': None,
               'comment': ''}
    
        if __opts__['test']:
            ret['comment'] = 'Zeroing local node statistics'
            return ret
    
        __salt__['trafficserver.zero_node']()
    
        ret['result'] = True
        ret['comment'] = 'Zeroed local node statistics'
        return ret
class Avail_locations(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a dict of all available VM locations on the cloud provider with
        relevant data
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The avail_locations function must be called with '
                '-f or --function, or with the --list-locations option'
            )
    
        params = {'Action': 'DescribeRegions'}
        items = query(params=params)
    
        ret = {}
        for region in items['Regions']['Region']:
            ret[region['RegionId']] = {}
            for item in region:
                ret[region['RegionId']][item] = six.text_type(region[item])
    
        return ret
class Avail_sizes(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a list of the image sizes that are on the provider
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The avail_sizes function must be called with '
                '-f or --function, or with the --list-sizes option'
            )
    
        params = {'Action': 'DescribeInstanceTypes'}
        items = query(params=params)
    
        ret = {}
        for image in items['InstanceTypes']['InstanceType']:
            ret[image['InstanceTypeId']] = {}
            for item in image:
                ret[image['InstanceTypeId']][item] = six.text_type(image[item])
    
        return ret
class List_availability_zones(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        List all availability zones in the current region
        '''
        ret = {}
    
        params = {'Action': 'DescribeZones',
                  'RegionId': get_location()}
        items = query(params)
    
        for zone in items['Zones']['Zone']:
            ret[zone['ZoneId']] = {}
            for item in zone:
                ret[zone['ZoneId']][item] = six.text_type(zone[item])
    
        return ret
class List_nodes_min(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a list of the VMs that are on the provider. Only a list of VM names,
        and their state, is returned. This is the minimum amount of information
        needed to check for existing VMs.
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The list_nodes_min function must be called with -f or --function.'
            )
    
        ret = {}
        location = get_location()
        params = {
            'Action': 'DescribeInstanceStatus',
            'RegionId': location,
        }
        nodes = query(params)
    
        log.debug(
            'Total %s instance found in Region %s',
            nodes['TotalCount'], location
        )
        if 'Code' in nodes or nodes['TotalCount'] == 0:
            return ret
    
        for node in nodes['InstanceStatuses']['InstanceStatus']:
            ret[node['InstanceId']] = {}
            for item in node:
                ret[node['InstanceId']][item] = node[item]
    
        return ret
class List_nodes(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a list of the VMs that are on the provider
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The list_nodes function must be called with -f or --function.'
            )
    
        nodes = list_nodes_full()
        ret = {}
        for instanceId in nodes:
            node = nodes[instanceId]
            ret[node['name']] = {
                'id': node['id'],
                'name': node['name'],
                'public_ips': node['public_ips'],
                'private_ips': node['private_ips'],
                'size': node['size'],
                'state': six.text_type(node['state']),
            }
        return ret
class List_nodes_full(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a list of the VMs that are on the provider
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The list_nodes_full function must be called with -f '
                'or --function.'
            )
    
        ret = {}
        location = get_location()
        params = {
            'Action': 'DescribeInstanceStatus',
            'RegionId': location,
            'PageSize': '50'
        }
        result = query(params=params)
    
        log.debug(
            'Total %s instance found in Region %s',
            result['TotalCount'], location
        )
        if 'Code' in result or result['TotalCount'] == 0:
            return ret
    
        # aliyun max 100 top instance in api
        result_instancestatus = result['InstanceStatuses']['InstanceStatus']
        if result['TotalCount'] > 50:
            params['PageNumber'] = '2'
            result = query(params=params)
            result_instancestatus.update(result['InstanceStatuses']['InstanceStatus'])
    
        for node in result_instancestatus:
    
            instanceId = node.get('InstanceId', '')
    
            params = {
                'Action': 'DescribeInstanceAttribute',
                'InstanceId': instanceId
            }
            items = query(params=params)
            if 'Code' in items:
                log.warning('Query instance:%s attribute failed', instanceId)
                continue
    
            name = items['InstanceName']
            ret[name] = {
                'id': items['InstanceId'],
                'name': name,
                'image': items['ImageId'],
                'size': 'TODO',
                'state': items['Status']
            }
            for item in items:
                value = items[item]
                if value is not None:
                    value = six.text_type(value)
                if item == "PublicIpAddress":
                    ret[name]['public_ips'] = items[item]['IpAddress']
                if item == "InnerIpAddress" and 'private_ips' not in ret[name]:
                    ret[name]['private_ips'] = items[item]['IpAddress']
                if item == 'VpcAttributes':
                    vpc_ips = items[item]['PrivateIpAddress']['IpAddress']
                    if vpc_ips:
                        ret[name]['private_ips'] = vpc_ips
                ret[name][item] = value
    
        provider = __active_provider_name__ or 'aliyun'
        if ':' in provider:
            comps = provider.split(':')
            provider = comps[0]
    
        __opts__['update_cachedir'] = True
        __utils__['cloud.cache_node_list'](ret, provider, __opts__)
    
        return ret
class List_securitygroup(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a list of security group
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The list_nodes function must be called with -f or --function.'
            )
    
        params = {
            'Action': 'DescribeSecurityGroups',
            'RegionId': get_location(),
            'PageSize': '50',
        }
    
        result = query(params)
        if 'Code' in result:
            return {}
    
        ret = {}
        for sg in result['SecurityGroups']['SecurityGroup']:
            ret[sg['SecurityGroupId']] = {}
            for item in sg:
                ret[sg['SecurityGroupId']][item] = sg[item]
    
        return ret
class Get_image(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Return the image object to use
        '''
        images = avail_images()
        vm_image = six.text_type(config.get_cloud_config_value(
            'image', vm_, __opts__, search_global=False
        ))
    
        if not vm_image:
            raise SaltCloudNotFound('No image specified for this VM.')
    
        if vm_image and six.text_type(vm_image) in images:
            return images[vm_image]['ImageId']
        raise SaltCloudNotFound(
            'The specified image, \'{0}\', could not be found.'.format(vm_image)
        )
class Get_securitygroup(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Return the security group
        '''
        sgs = list_securitygroup()
        securitygroup = config.get_cloud_config_value(
            'securitygroup', vm_, __opts__, search_global=False
        )
    
        if not securitygroup:
            raise SaltCloudNotFound('No securitygroup ID specified for this VM.')
    
        if securitygroup and six.text_type(securitygroup) in sgs:
            return sgs[securitygroup]['SecurityGroupId']
        raise SaltCloudNotFound(
            'The specified security group, \'{0}\', could not be found.'.format(
                securitygroup)
        )
class Get_size(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Return the VM's size. Used by create_node().
        '''
        sizes = avail_sizes()
        vm_size = six.text_type(config.get_cloud_config_value(
            'size', vm_, __opts__, search_global=False
        ))
    
        if not vm_size:
            raise SaltCloudNotFound('No size specified for this VM.')
    
        if vm_size and six.text_type(vm_size) in sizes:
            return sizes[vm_size]['InstanceTypeId']
    
        raise SaltCloudNotFound(
            'The specified size, \'{0}\', could not be found.'.format(vm_size)
        )
class __get_location(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Return the VM's location
        '''
        locations = avail_locations()
        vm_location = six.text_type(config.get_cloud_config_value(
            'location', vm_, __opts__, search_global=False
        ))
    
        if not vm_location:
            raise SaltCloudNotFound('No location specified for this VM.')
    
        if vm_location and six.text_type(vm_location) in locations:
            return locations[vm_location]['RegionId']
        raise SaltCloudNotFound(
            'The specified location, \'{0}\', could not be found.'.format(
                vm_location
            )
        )
class Create_node(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, kwargs):
        '''
        Convenience function to make the rest api call for node creation.
        '''
        if not isinstance(kwargs, dict):
            kwargs = {}
    
        # Required parameters
        params = {
            'Action': 'CreateInstance',
            'InstanceType': kwargs.get('size_id', ''),
            'RegionId': kwargs.get('region_id', DEFAULT_LOCATION),
            'ImageId': kwargs.get('image_id', ''),
            'SecurityGroupId': kwargs.get('securitygroup_id', ''),
            'InstanceName': kwargs.get('name', ''),
        }
    
        # Optional parameters'
        optional = [
            'InstanceName', 'InternetChargeType',
            'InternetMaxBandwidthIn', 'InternetMaxBandwidthOut',
            'HostName', 'Password', 'SystemDisk.Category', 'VSwitchId'
            # 'DataDisk.n.Size', 'DataDisk.n.Category', 'DataDisk.n.SnapshotId'
        ]
    
        for item in optional:
            if item in kwargs:
                params.update({item: kwargs[item]})
    
        # invoke web call
        result = query(params)
        return result['InstanceId']
class Create(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Create a single VM from a data dict
        '''
        try:
            # Check for required profile parameters before sending any API calls.
            if vm_['profile'] and config.is_profile_configured(__opts__,
                                                               __active_provider_name__ or 'aliyun',
                                                               vm_['profile'],
                                                               vm_=vm_) is False:
                return False
        except AttributeError:
            pass
    
        __utils__['cloud.fire_event'](
            'event',
            'starting create',
            'salt/cloud/{0}/creating'.format(vm_['name']),
            args=__utils__['cloud.filter_event']('creating', vm_, ['name', 'profile', 'provider', 'driver']),
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        log.info('Creating Cloud VM %s', vm_['name'])
        kwargs = {
            'name': vm_['name'],
            'size_id': get_size(vm_),
            'image_id': get_image(vm_),
            'region_id': __get_location(vm_),
            'securitygroup_id': get_securitygroup(vm_),
        }
        if 'vswitch_id' in vm_:
            kwargs['VSwitchId'] = vm_['vswitch_id']
        if 'internet_chargetype' in vm_:
            kwargs['InternetChargeType'] = vm_['internet_chargetype']
        if 'internet_maxbandwidthin' in vm_:
            kwargs['InternetMaxBandwidthIn'] = six.text_type(vm_['internet_maxbandwidthin'])
        if 'internet_maxbandwidthout' in vm_:
            kwargs['InternetMaxBandwidthOut'] = six.text_type(vm_['internet_maxbandwidthOut'])
        if 'hostname' in vm_:
            kwargs['HostName'] = vm_['hostname']
        if 'password' in vm_:
            kwargs['Password'] = vm_['password']
        if 'instance_name' in vm_:
            kwargs['InstanceName'] = vm_['instance_name']
        if 'systemdisk_category' in vm_:
            kwargs['SystemDisk.Category'] = vm_['systemdisk_category']
    
        __utils__['cloud.fire_event'](
            'event',
            'requesting instance',
            'salt/cloud/{0}/requesting'.format(vm_['name']),
            args=__utils__['cloud.filter_event']('requesting', kwargs, list(kwargs)),
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        try:
            ret = create_node(kwargs)
        except Exception as exc:
            log.error(
                'Error creating %s on Aliyun ECS\n\n'
                'The following exception was thrown when trying to '
                'run the initial deployment: %s',
                vm_['name'], six.text_type(exc),
                # Show the traceback if the debug logging level is enabled
                exc_info_on_loglevel=logging.DEBUG
            )
            return False
        # repair ip address error and start vm
        time.sleep(8)
        params = {'Action': 'StartInstance',
                  'InstanceId': ret}
        query(params)
    
        def __query_node_data(vm_name):
            data = show_instance(vm_name, call='action')
            if not data:
                # Trigger an error in the wait_for_ip function
                return False
            if data.get('PublicIpAddress', None) is not None:
                return data
    
        try:
            data = salt.utils.cloud.wait_for_ip(
                __query_node_data,
                update_args=(vm_['name'],),
                timeout=config.get_cloud_config_value(
                    'wait_for_ip_timeout', vm_, __opts__, default=10 * 60),
                interval=config.get_cloud_config_value(
                    'wait_for_ip_interval', vm_, __opts__, default=10),
            )
        except (SaltCloudExecutionTimeout, SaltCloudExecutionFailure) as exc:
            try:
                # It might be already up, let's destroy it!
                destroy(vm_['name'])
            except SaltCloudSystemExit:
                pass
            finally:
                raise SaltCloudSystemExit(six.text_type(exc))
    
        if data['public_ips']:
            ssh_ip = data['public_ips'][0]
        elif data['private_ips']:
            ssh_ip = data['private_ips'][0]
        else:
            log.info('No available ip:cant connect to salt')
            return False
        log.debug('VM %s is now running', ssh_ip)
        vm_['ssh_host'] = ssh_ip
    
        # The instance is booted and accessible, let's Salt it!
        ret = __utils__['cloud.bootstrap'](vm_, __opts__)
        ret.update(data)
    
        log.info('Created Cloud VM \'%s\'', vm_['name'])
        log.debug(
            '\'%s\' VM creation details:\n%s',
            vm_['name'], pprint.pformat(data)
        )
    
        __utils__['cloud.fire_event'](
            'event',
            'created instance',
            'salt/cloud/{0}/created'.format(vm_['name']),
            args=__utils__['cloud.filter_event']('created', vm_, ['name', 'profile', 'provider', 'driver']),
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        return ret
class Query(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, params=None):
        '''
        Make a web call to aliyun ECS REST API
        '''
        path = 'https://ecs-cn-hangzhou.aliyuncs.com'
    
        access_key_id = config.get_cloud_config_value(
            'id', get_configured_provider(), __opts__, search_global=False
        )
        access_key_secret = config.get_cloud_config_value(
            'key', get_configured_provider(), __opts__, search_global=False
        )
    
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
        # public interface parameters
        parameters = {
            'Format': 'JSON',
            'Version': DEFAULT_ALIYUN_API_VERSION,
            'AccessKeyId': access_key_id,
            'SignatureVersion': '1.0',
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureNonce': six.text_type(uuid.uuid1()),
            'TimeStamp': timestamp,
        }
    
        # include action or function parameters
        if params:
            parameters.update(params)
    
        # Calculate the string for Signature
        signature = _compute_signature(parameters, access_key_secret)
        parameters['Signature'] = signature
    
        request = requests.get(path, params=parameters, verify=True)
        if request.status_code != 200:
            raise SaltCloudSystemExit(
                'An error occurred while querying aliyun ECS. HTTP Code: {0}  '
                'Error: \'{1}\''.format(
                    request.status_code,
                    request.text
                )
            )
    
        log.debug(request.url)
    
        content = request.text
    
        result = salt.utils.json.loads(content)
        if 'Code' in result:
            raise SaltCloudSystemExit(
                pprint.pformat(result.get('Message', {}))
            )
        return result
class _write_adminfile(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, kwargs):
        '''
        Create a temporary adminfile based on the keyword arguments passed to
        pkg.install.
        '''
        # Set the adminfile default variables
        email = kwargs.get('email', '')
        instance = kwargs.get('instance', 'quit')
        partial = kwargs.get('partial', 'nocheck')
        runlevel = kwargs.get('runlevel', 'nocheck')
        idepend = kwargs.get('idepend', 'nocheck')
        rdepend = kwargs.get('rdepend', 'nocheck')
        space = kwargs.get('space', 'nocheck')
        setuid = kwargs.get('setuid', 'nocheck')
        conflict = kwargs.get('conflict', 'nocheck')
        action = kwargs.get('action', 'nocheck')
        basedir = kwargs.get('basedir', 'default')
    
        # Make tempfile to hold the adminfile contents.
        adminfile = salt.utils.files.mkstemp(prefix="salt-")
    
        def _write_line(fp_, line):
            fp_.write(salt.utils.stringutils.to_str(line))
    
        with salt.utils.files.fopen(adminfile, 'w') as fp_:
            _write_line(fp_, 'email={0}\n'.format(email))
            _write_line(fp_, 'instance={0}\n'.format(instance))
            _write_line(fp_, 'partial={0}\n'.format(partial))
            _write_line(fp_, 'runlevel={0}\n'.format(runlevel))
            _write_line(fp_, 'idepend={0}\n'.format(idepend))
            _write_line(fp_, 'rdepend={0}\n'.format(rdepend))
            _write_line(fp_, 'space={0}\n'.format(space))
            _write_line(fp_, 'setuid={0}\n'.format(setuid))
            _write_line(fp_, 'conflict={0}\n'.format(conflict))
            _write_line(fp_, 'action={0}\n'.format(action))
            _write_line(fp_, 'basedir={0}\n'.format(basedir))
    
        return adminfile
class Iter_transport_opts(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, opts):
        '''
        Yield transport, opts for all master configured transports
        '''
        transports = set()
    
        for transport, opts_overrides in six.iteritems(opts.get('transport_opts', {})):
            t_opts = dict(opts)
            t_opts.update(opts_overrides)
            t_opts['transport'] = transport
            transports.add(transport)
            yield transport, t_opts
    
        if opts['transport'] not in transports:
            yield opts['transport'], opts
class Event(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Chekcs for a specific event match and returns result True if the match
        happens
    
        USAGE:
    
        .. code-block:: yaml
    
            salt/foo/*/bar:
              check.event
    
            run_remote_ex:
              local.cmd:
                - tgt: '*'
                - func: test.ping
                - require:
                  - check: salt/foo/*/bar
        '''
        ret = {'name': name,
               'changes': {},
               'comment': '',
               'result': False}
    
        for event in __events__:
            if salt.utils.stringutils.expr_match(event['tag'], name):
                ret['result'] = True
    
        return ret
class Map_clonemode(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_info):
        """
        Convert the virtualbox config file values for clone_mode into the integers the API requires
        """
        mode_map = {
          'state': 0,
          'child': 1,
          'all':   2
        }
    
        if not vm_info:
            return DEFAULT_CLONE_MODE
    
        if 'clonemode' not in vm_info:
            return DEFAULT_CLONE_MODE
    
        if vm_info['clonemode'] in mode_map:
            return mode_map[vm_info['clonemode']]
        else:
            raise SaltCloudSystemExit(
                "Illegal clonemode for virtualbox profile.  Legal values are: {}".format(','.join(mode_map.keys()))
            )
class Create(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_info):
        '''
        Creates a virtual machine from the given VM information
    
        This is what is used to request a virtual machine to be created by the
        cloud provider, wait for it to become available, and then (optionally) log
        in and install Salt on it.
    
        Events fired:
    
        This function fires the event ``salt/cloud/vm_name/creating``, with the
        payload containing the names of the VM, profile, and provider.
    
        @param vm_info
    
        .. code-block:: text
    
            {
                name: <str>
                profile: <dict>
                driver: <provider>:<profile>
                clonefrom: <vm_name>
                clonemode: <mode> (default: state, choices: state, child, all)
            }
    
        @type vm_info dict
        @return dict of resulting vm. !!!Passwords can and should be included!!!
        '''
        try:
            # Check for required profile parameters before sending any API calls.
            if vm_info['profile'] and config.is_profile_configured(
                __opts__,
                    __active_provider_name__ or 'virtualbox',
                vm_info['profile']
            ) is False:
                return False
        except AttributeError:
            pass
    
        vm_name = vm_info["name"]
        deploy = config.get_cloud_config_value(
            'deploy', vm_info, __opts__, search_global=False, default=True
        )
        wait_for_ip_timeout = config.get_cloud_config_value(
            'wait_for_ip_timeout', vm_info, __opts__, default=60
        )
        boot_timeout = config.get_cloud_config_value(
            'boot_timeout', vm_info, __opts__, default=60 * 1000
        )
        power = config.get_cloud_config_value(
            'power_on', vm_info, __opts__, default=False
        )
        key_filename = config.get_cloud_config_value(
            'private_key', vm_info, __opts__, search_global=False, default=None
        )
        clone_mode = map_clonemode(vm_info)
        wait_for_pattern = vm_info['waitforpattern'] if 'waitforpattern' in vm_info.keys() else None
        interface_index = vm_info['interfaceindex'] if 'interfaceindex' in vm_info.keys() else 0
    
        log.debug("Going to fire event: starting create")
        __utils__['cloud.fire_event'](
            'event',
            'starting create',
            'salt/cloud/{0}/creating'.format(vm_info['name']),
            args=__utils__['cloud.filter_event']('creating', vm_info, ['name', 'profile', 'provider', 'driver']),
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        # to create the virtual machine.
        request_kwargs = {
            'name': vm_info['name'],
            'clone_from': vm_info['clonefrom'],
            'clone_mode': clone_mode
        }
    
        __utils__['cloud.fire_event'](
            'event',
            'requesting instance',
            'salt/cloud/{0}/requesting'.format(vm_info['name']),
            args=__utils__['cloud.filter_event']('requesting', request_kwargs, list(request_kwargs)),
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
        vm_result = vb_clone_vm(**request_kwargs)
    
        # Booting and deploying if needed
        if power:
            vb_start_vm(vm_name, timeout=boot_timeout)
            ips = vb_wait_for_network_address(wait_for_ip_timeout, machine_name=vm_name, wait_for_pattern=wait_for_pattern)
    
            if ips:
                ip = ips[interface_index]
                log.info("[ %s ] IPv4 is: %s", vm_name, ip)
                # ssh or smb using ip and install salt only if deploy is True
                if deploy:
                    vm_info['key_filename'] = key_filename
                    vm_info['ssh_host'] = ip
    
                    res = __utils__['cloud.bootstrap'](vm_info, __opts__)
                    vm_result.update(res)
    
        __utils__['cloud.fire_event'](
            'event',
            'created machine',
            'salt/cloud/{0}/created'.format(vm_info['name']),
            args=__utils__['cloud.filter_event']('created', vm_result, list(vm_result)),
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        # Passwords should be included in this object!!
        return vm_result
class Install(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, runas=None):
        '''
        Install RVM system-wide
    
        runas
            The user under which to run the rvm installer script. If not specified,
            then it be run as the user under which Salt is running.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' rvm.install
        '''
        # RVM dependencies on Ubuntu 10.04:
        #   bash coreutils gzip bzip2 gawk sed curl git-core subversion
        installer = 'https://raw.githubusercontent.com/rvm/rvm/master/binscripts/rvm-installer'
        ret = __salt__['cmd.run_all'](
            # the RVM installer automatically does a multi-user install when it is
            # invoked with root privileges
            'curl -Ls {installer} | bash -s stable'.format(installer=installer),
            runas=runas,
            python_shell=True
        )
        if ret['retcode'] > 0:
            msg = 'Error encountered while downloading the RVM installer'
            if ret['stderr']:
                msg += '. stderr follows:\n\n' + ret['stderr']
            raise CommandExecutionError(msg)
        return True
class List_(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, runas=None):
        '''
        List all rvm-installed rubies
    
        runas
            The user under which to run rvm. If not specified, then rvm will be run
            as the user under which Salt is running.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' rvm.list
        '''
        rubies = []
        output = _rvm(['list'], runas=runas)
        if output:
            regex = re.compile(r'^[= ]([*> ]) ([^- ]+)-([^ ]+) \[ (.*) \]')
            for line in output.splitlines():
                match = regex.match(line)
                if match:
                    rubies.append([
                        match.group(2), match.group(3), match.group(1) == '*'
                    ])
        return rubies
class Gemset_list_all(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, runas=None):
        '''
        List all gemsets for all installed rubies.
    
        Note that you must have set a default ruby before this can work.
    
        runas
            The user under which to run rvm. If not specified, then rvm will be run
            as the user under which Salt is running.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' rvm.gemset_list_all
        '''
        gemsets = {}
        current_ruby = None
        output = _rvm_do('default', ['rvm', 'gemset', 'list_all'], runas=runas)
        if output:
            gems_regex = re.compile('^   ([^ ]+)')
            gemset_regex = re.compile('^gemsets for ([^ ]+)')
            for line in output.splitlines():
                match = gemset_regex.match(line)
                if match:
                    current_ruby = match.group(1)
                    gemsets[current_ruby] = []
                match = gems_regex.match(line)
                if match:
                    gemsets[current_ruby].append(match.group(1))
        return gemsets
class Interfaces(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, root):
        '''
        Generate a dictionary with all available interfaces relative to root.
        Symlinks are not followed.
    
        CLI example:
         .. code-block:: bash
    
            salt '*' sysfs.interfaces block/bcache0/bcache
    
        Output example:
         .. code-block:: json
    
           {
              "r": [
                "state",
                "partial_stripes_expensive",
                "writeback_rate_debug",
                "stripe_size",
                "dirty_data",
                "stats_total/cache_hits",
                "stats_total/cache_bypass_misses",
                "stats_total/bypassed",
                "stats_total/cache_readaheads",
                "stats_total/cache_hit_ratio",
                "stats_total/cache_miss_collisions",
                "stats_total/cache_misses",
                "stats_total/cache_bypass_hits",
              ],
              "rw": [
                "writeback_rate",
                "writeback_rate_update_seconds",
                "cache_mode",
                "writeback_delay",
                "label",
                "writeback_running",
                "writeback_metadata",
                "running",
                "writeback_rate_p_term_inverse",
                "sequential_cutoff",
                "writeback_percent",
                "writeback_rate_d_term",
                "readahead"
              ],
              "w": [
                "stop",
                "clear_stats",
                "attach",
                "detach"
              ]
           }
    
        .. note::
          * 'r' interfaces are read-only
          * 'w' interfaces are write-only (e.g. actions)
          * 'rw' are interfaces that can both be read or written
        '''
    
        root = target(root)
        if root is False or not os.path.isdir(root):
            log.error('SysFS %s not a dir', root)
            return False
    
        readwrites = []
        reads = []
        writes = []
    
        for path, _, files in salt.utils.path.os_walk(root, followlinks=False):
            for afile in files:
                canpath = os.path.join(path, afile)
    
                if not os.path.isfile(canpath):
                    continue
    
                stat_mode = os.stat(canpath).st_mode
                is_r = bool(stat.S_IRUSR & stat_mode)
                is_w = bool(stat.S_IWUSR & stat_mode)
    
                relpath = os.path.relpath(canpath, root)
                if is_w:
                    if is_r:
                        readwrites.append(relpath)
                    else:
                        writes.append(relpath)
                elif is_r:
                    reads.append(relpath)
                else:
                    log.warning('Unable to find any interfaces in %s', canpath)
    
        return {
            'r': reads,
            'w': writes,
            'rw': readwrites
        }
class _get_librato(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, ret=None):
        '''
        Return a Librato connection object.
        '''
        _options = _get_options(ret)
    
        conn = librato.connect(
            _options.get('email'),
            _options.get('api_token'),
            sanitizer=librato.sanitize_metric_name,
            hostname=_options.get('api_url'))
        log.info("Connected to librato.")
        return conn
class Returner(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, ret):
        '''
        Parse the return data and return metrics to Librato.
        '''
        librato_conn = _get_librato(ret)
    
        q = librato_conn.new_queue()
    
        if ret['fun'] == 'state.highstate':
            log.debug('Found returned Highstate data.')
            # Calculate the runtimes and number of failed states.
            stats = _calculate_runtimes(ret['return'])
            log.debug('Batching Metric retcode with %s', ret['retcode'])
            q.add('saltstack.highstate.retcode',
                  ret['retcode'], tags={'Name': ret['id']})
    
            log.debug(
                'Batching Metric num_failed_jobs with %s',
                stats['num_failed_states']
            )
            q.add('saltstack.highstate.failed_states',
                  stats['num_failed_states'], tags={'Name': ret['id']})
    
            log.debug(
                'Batching Metric num_passed_states with %s',
                stats['num_passed_states']
            )
            q.add('saltstack.highstate.passed_states',
                  stats['num_passed_states'], tags={'Name': ret['id']})
    
            log.debug('Batching Metric runtime with %s', stats['runtime'])
            q.add('saltstack.highstate.runtime',
                  stats['runtime'], tags={'Name': ret['id']})
    
            log.debug(
                'Batching Metric runtime with %s',
                stats['num_failed_states'] + stats['num_passed_states']
            )
            q.add('saltstack.highstate.total_states', stats[
                  'num_failed_states'] + stats['num_passed_states'], tags={'Name': ret['id']})
    
        log.info('Sending metrics to Librato.')
        q.submit()
class _get_bgp_runner_opts(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the bgp runner options.
        '''
        runner_opts = __opts__.get('runners', {}).get('bgp', {})
        return {
            'tgt': runner_opts.get('tgt', _DEFAULT_TARGET),
            'tgt_type': runner_opts.get('tgt_type', _DEFAULT_EXPR_FORM),
            'display': runner_opts.get('display', _DEFAULT_DISPLAY),
            'return_fields': _DEFAULT_INCLUDED_FIELDS + runner_opts.get('return_fields', _DEFAULT_RETURN_FIELDS),
            'outputter': runner_opts.get('outputter', _DEFAULT_OUTPUTTER),
        }
class Neighbors(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *asns,**kwargs):
        '''
        Search for BGP neighbors details in the mines of the ``bgp.neighbors`` function.
    
        Arguments:
    
        asns
            A list of AS numbers to search for.
            The runner will return only the neighbors of these AS numbers.
    
        device
            Filter by device name (minion ID).
    
        ip
            Search BGP neighbor using the IP address.
            In multi-VRF environments, the same IP address could be used by
            more than one neighbors, in different routing tables.
    
        network
            Search neighbors within a certain IP network.
    
        title
            Custom title.
    
        display: ``True``
            Display on the screen or return structured object? Default: ``True`` (return on the CLI).
    
        outputter: ``table``
            Specify the outputter name when displaying on the CLI. Default: :mod:`table <salt.output.table_out>`.
    
        In addition, any field from the output of the ``neighbors`` function
        from the :mod:`NAPALM BGP module <salt.modules.napalm_bgp.neighbors>` can be used as a filter.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt-run bgp.neighbors 13335 15169
            salt-run bgp.neighbors 13335 ip=172.17.19.1
            salt-run bgp.neighbors multipath=True
            salt-run bgp.neighbors up=False export_policy=my-export-policy multihop=False
            salt-run bgp.neighbors network=192.168.0.0/16
    
        Output example:
    
        .. code-block:: text
    
            BGP Neighbors for 13335, 15169
            ________________________________________________________________________________________________________________________________________________________________
            |    Device    | AS Number |         Neighbor Address        | State|#Active/Received/Accepted/Damped |         Policy IN         |         Policy OUT         |
            ________________________________________________________________________________________________________________________________________________________________
            | edge01.bjm01 |   13335   |          172.17.109.11          |        Established 0/398/398/0         |       import-policy       |        export-policy       |
            ________________________________________________________________________________________________________________________________________________________________
            | edge01.bjm01 |   13335   |          172.17.109.12          |       Established 397/398/398/0        |       import-policy       |        export-policy       |
            ________________________________________________________________________________________________________________________________________________________________
            | edge01.flw01 |   13335   |          192.168.172.11         |        Established 1/398/398/0         |       import-policy       |        export-policy       |
            ________________________________________________________________________________________________________________________________________________________________
            | edge01.oua01 |   13335   |          172.17.109.17          |          Established 0/0/0/0           |       import-policy       |        export-policy       |
            ________________________________________________________________________________________________________________________________________________________________
            | edge01.bjm01 |   15169   |             2001::1             |       Established 102/102/102/0        |       import-policy       |        export-policy       |
            ________________________________________________________________________________________________________________________________________________________________
            | edge01.bjm01 |   15169   |             2001::2             |       Established 102/102/102/0        |       import-policy       |        export-policy       |
            ________________________________________________________________________________________________________________________________________________________________
            | edge01.tbg01 |   13335   |          192.168.172.17         |          Established 0/1/1/0           |       import-policy       |        export-policy       |
            ________________________________________________________________________________________________________________________________________________________________
        '''
        opts = _get_bgp_runner_opts()
        title = kwargs.pop('title', None)
        display = kwargs.pop('display', opts['display'])
        outputter = kwargs.pop('outputter', opts['outputter'])
    
        # cleaning up the kwargs
        # __pub args not used in this runner (yet)
        kwargs_copy = {}
        kwargs_copy.update(kwargs)
        for karg, _ in six.iteritems(kwargs_copy):
            if karg.startswith('__pub'):
                kwargs.pop(karg)
        if not asns and not kwargs:
            if display:
                print('Please specify at least an AS Number or an output filter')
            return []
        device = kwargs.pop('device', None)
        neighbor_ip = kwargs.pop('ip', None)
        ipnet = kwargs.pop('network', None)
        ipnet_obj = IPNetwork(ipnet) if ipnet else None
        # any other key passed on the CLI can be used as a filter
    
        rows = []
        # building the labels
        labels = {}
        for field in opts['return_fields']:
            if field in _DEFAULT_LABELS_MAPPING:
                labels[field] = _DEFAULT_LABELS_MAPPING[field]
            else:
                # transform from 'previous_connection_state' to 'Previous Connection State'
                labels[field] = ' '.join(map(lambda word: word.title(), field.split('_')))
        display_fields = list(set(opts['return_fields']) - set(_DEFAULT_INCLUDED_FIELDS))
        get_bgp_neighbors_all = _get_mine(opts=opts)
    
        if not title:
            title_parts = []
            if asns:
                title_parts.append('BGP Neighbors for {asns}'.format(
                    asns=', '.join([six.text_type(asn) for asn in asns])
                ))
            if neighbor_ip:
                title_parts.append('Selecting neighbors having the remote IP address: {ipaddr}'.format(ipaddr=neighbor_ip))
            if ipnet:
                title_parts.append('Selecting neighbors within the IP network: {ipnet}'.format(ipnet=ipnet))
            if kwargs:
                title_parts.append('Searching for BGP neighbors having the attributes: {attrmap}'.format(
                    attrmap=', '.join(map(lambda key: '{key}={value}'.format(key=key, value=kwargs[key]), kwargs))
                ))
            title = '\n'.join(title_parts)
        for minion, get_bgp_neighbors_minion in six.iteritems(get_bgp_neighbors_all):  # pylint: disable=too-many-nested-blocks
            if not get_bgp_neighbors_minion.get('result'):
                continue  # ignore empty or failed mines
            if device and minion != device:
                # when requested to display only the neighbors on a certain device
                continue
            get_bgp_neighbors_minion_out = get_bgp_neighbors_minion.get('out', {})
            for vrf, vrf_bgp_neighbors in six.iteritems(get_bgp_neighbors_minion_out):  # pylint: disable=unused-variable
                for asn, get_bgp_neighbors_minion_asn in six.iteritems(vrf_bgp_neighbors):
                    if asns and asn not in asns:
                        # if filtering by AS number(s),
                        # will ignore if this AS number key not in that list
                        # and continue the search
                        continue
                    for neighbor in get_bgp_neighbors_minion_asn:
                        if kwargs and not _compare_match(kwargs, neighbor):
                            # requested filtering by neighbors stats
                            # but this one does not correspond
                            continue
                        if neighbor_ip and neighbor_ip != neighbor.get('remote_address'):
                            # requested filtering by neighbors IP addr
                            continue
                        if ipnet_obj and neighbor.get('remote_address'):
                            neighbor_ip_obj = IPAddress(neighbor.get('remote_address'))
                            if neighbor_ip_obj not in ipnet_obj:
                                # Neighbor not in this network
                                continue
                        row = {
                            'device': minion,
                            'neighbor_address': neighbor.get('remote_address'),
                            'as_number': asn
                        }
                        if 'vrf' in display_fields:
                            row['vrf'] = vrf
                        if 'connection_stats' in display_fields:
                            connection_stats = '{state} {active}/{received}/{accepted}/{damped}'.format(
                                state=neighbor.get('connection_state', -1),
                                active=neighbor.get('active_prefix_count', -1),
                                received=neighbor.get('received_prefix_count', -1),
                                accepted=neighbor.get('accepted_prefix_count', -1),
                                damped=neighbor.get('suppressed_prefix_count', -1),
                            )
                            row['connection_stats'] = connection_stats
                        if 'interface_description' in display_fields or 'interface_name' in display_fields:
                            net_find = __salt__['net.interfaces'](device=minion,
                                                                  ipnet=neighbor.get('remote_address'),
                                                                  display=False)
                            if net_find:
                                if 'interface_description' in display_fields:
                                    row['interface_description'] = net_find[0]['interface_description']
                                if 'interface_name' in display_fields:
                                    row['interface_name'] = net_find[0]['interface']
                            else:
                                # if unable to find anything, leave blank
                                if 'interface_description' in display_fields:
                                    row['interface_description'] = ''
                                if 'interface_name' in display_fields:
                                    row['interface_name'] = ''
                        for field in display_fields:
                            if field in neighbor:
                                row[field] = neighbor[field]
                        rows.append(row)
        return _display_runner(rows, labels, title, display=display, outputter=outputter)
class Returner(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, ret):
        '''
        Return data to a mongodb server
        '''
        conn, mdb = _get_conn(ret)
    
        if isinstance(ret['return'], dict):
            back = _remove_dots(ret['return'])
        else:
            back = ret['return']
    
        if isinstance(ret, dict):
            full_ret = _remove_dots(ret)
        else:
            full_ret = ret
    
        log.debug(back)
        sdata = {'minion': ret['id'], 'jid': ret['jid'], 'return': back, 'fun': ret['fun'], 'full_ret': full_ret}
        if 'out' in ret:
            sdata['out'] = ret['out']
    
        # save returns in the saltReturns collection in the json format:
        # { 'minion': <minion_name>, 'jid': <job_id>, 'return': <return info with dots removed>,
        #   'fun': <function>, 'full_ret': <unformatted return with dots removed>}
        #
        # again we run into the issue with deprecated code from previous versions
    
        if PYMONGO_VERSION > _LooseVersion('2.3'):
            #using .copy() to ensure that the original data is not changed, raising issue with pymongo team
            mdb.saltReturns.insert_one(sdata.copy())
        else:
            mdb.saltReturns.insert(sdata.copy())
class _safe_copy(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, dat):
        ''' mongodb doesn't allow '.' in keys, but does allow unicode equivs.
            Apparently the docs suggest using escaped unicode full-width
            encodings.  *sigh*
    
                \\  -->  \\\            $  -->  \\\\u0024
                .  -->  \\\\u002e
    
            Personally, I prefer URL encodings,
    
            \\  -->  %5c
            $  -->  %24
            .  -->  %2e
    
    
            Which means also escaping '%':
    
            % -> %25
        '''''' mongodb doesn't allow '.' in keys, but does allow unicode equivs.
            Apparently the docs suggest using escaped unicode full-width
            encodings.  *sigh*
    
                \\  -->  \\\\
                $  -->  \\\\u0024
                .  -->  \\\\u002e
    
            Personally, I prefer URL encodings,
    
            \\  -->  %5c
            $  -->  %24
            .  -->  %2e
    
    
            Which means also escaping '%':
    
            % -> %25
        '''
    
        if isinstance(dat, dict):
            ret = {}
            for k in dat:
                r = k.replace('%', '%25').replace('\\', '%5c').replace('$', '%24').replace('.', '%2e')
                if r != k:
                    log.debug('converting dict key from %s to %s for mongodb', k, r)
                ret[r] = _safe_copy(dat[k])
            return ret
    
        if isinstance(dat, (list, tuple)):
            return [_safe_copy(i) for i in dat]
    
        return dat
class Get_load(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, jid):
        '''
        Return the load associated with a given job id
        '''
        conn, mdb = _get_conn(ret=None)
        return mdb.jobs.find_one({'jid': jid}, {'_id': 0})
class Get_minions(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return a list of minions
        '''
        conn, mdb = _get_conn(ret=None)
        ret = []
        name = mdb.saltReturns.distinct('minion')
        ret.append(name)
        return ret
class Get_jids(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return a list of job ids
        '''
        conn, mdb = _get_conn(ret=None)
        map = "function() { emit(this.jid, this); }"
        reduce = "function (key, values) { return values[0]; }"
        result = mdb.jobs.inline_map_reduce(map, reduce)
        ret = {}
        for r in result:
            jid = r['_id']
            ret[jid] = salt.utils.jid.format_jid_instance(jid, r['value'])
        return ret
class Event_return(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, events):
        '''
        Return events to Mongodb server
        '''
        conn, mdb = _get_conn(ret=None)
    
        if isinstance(events, list):
            events = events[0]
    
        if isinstance(events, dict):
            log.debug(events)
    
            if PYMONGO_VERSION > _LooseVersion('2.3'):
                mdb.events.insert_one(events.copy())
            else:
                mdb.events.insert(events.copy())
class Lowstate_file_refs(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, chunks):
        '''
        Create a list of file ref objects to reconcile
        '''
        refs = {}
        for chunk in chunks:
            saltenv = 'base'
            crefs = []
            for state in chunk:
                if state == '__env__':
                    saltenv = chunk[state]
                elif state == 'saltenv':
                    saltenv = chunk[state]
                elif state.startswith('__'):
                    continue
                crefs.extend(salt_refs(chunk[state]))
            if crefs:
                if saltenv not in refs:
                    refs[saltenv] = []
                refs[saltenv].append(crefs)
        return refs
class Salt_refs(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, data):
        '''
        Pull salt file references out of the states
        '''
        proto = 'salt://'
        ret = []
        if isinstance(data, six.string_types):
            if data.startswith(proto):
                return [data]
        if isinstance(data, list):
            for comp in data:
                if isinstance(comp, six.string_types):
                    if comp.startswith(proto):
                        ret.append(comp)
        return ret
class Mod_data(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, fsclient):
        '''
        Generate the module arguments for the shim data
        '''
        # TODO, change out for a fileserver backend
        sync_refs = [
                'modules',
                'states',
                'grains',
                'renderers',
                'returners',
                ]
        ret = {}
        envs = fsclient.envs()
        ver_base = ''
        for env in envs:
            files = fsclient.file_list(env)
            for ref in sync_refs:
                mods_data = {}
                pref = '_{0}'.format(ref)
                for fn_ in sorted(files):
                    if fn_.startswith(pref):
                        if fn_.endswith(('.py', '.so', '.pyx')):
                            full = salt.utils.url.create(fn_)
                            mod_path = fsclient.cache_file(full, env)
                            if not os.path.isfile(mod_path):
                                continue
                            mods_data[os.path.basename(fn_)] = mod_path
                            chunk = salt.utils.hashutils.get_hash(mod_path)
                            ver_base += chunk
                if mods_data:
                    if ref in ret:
                        ret[ref].update(mods_data)
                    else:
                        ret[ref] = mods_data
        if not ret:
            return {}
    
        if six.PY3:
            ver_base = salt.utils.stringutils.to_bytes(ver_base)
    
        ver = hashlib.sha1(ver_base).hexdigest()
        ext_tar_path = os.path.join(
                fsclient.opts['cachedir'],
                'ext_mods.{0}.tgz'.format(ver))
        mods = {'version': ver,
                'file': ext_tar_path}
        if os.path.isfile(ext_tar_path):
            return mods
        tfp = tarfile.open(ext_tar_path, 'w:gz')
        verfile = os.path.join(fsclient.opts['cachedir'], 'ext_mods.ver')
        with salt.utils.files.fopen(verfile, 'w+') as fp_:
            fp_.write(ver)
        tfp.add(verfile, 'ext_version')
        for ref in ret:
            for fn_ in ret[ref]:
                tfp.add(ret[ref][fn_], os.path.join(ref, fn_))
        tfp.close()
        return mods
class Ssh_version(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Returns the version of the installed ssh command
        '''
        # This function needs more granular checks and to be validated against
        # older versions of ssh
        ret = subprocess.Popen(
                ['ssh', '-V'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()
        try:
            version_parts = ret[1].split(b',')[0].split(b'_')[1]
            parts = []
            for part in version_parts:
                try:
                    parts.append(int(part))
                except ValueError:
                    return tuple(parts)
            return tuple(parts)
        except IndexError:
            return (2, 0)
class _convert_args(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, args):
        '''
        Take a list of args, and convert any dicts inside the list to keyword
        args in the form of `key=value`, ready to be passed to salt-ssh
        '''
        converted = []
        for arg in args:
            if isinstance(arg, dict):
                for key in list(arg.keys()):
                    if key == '__kwarg__':
                        continue
                    converted.append('{0}={1}'.format(key, arg[key]))
            else:
                converted.append(arg)
        return converted
class _get_roster(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Read roster filename as a key to the data.
            :return:
            '''
            roster_file = salt.roster.get_roster_file(self.opts)
            if roster_file not in self.__parsed_rosters:
                roster_data = compile_template(roster_file, salt.loader.render(self.opts, {}),
                                               self.opts['renderer'], self.opts['renderer_blacklist'],
                                               self.opts['renderer_whitelist'])
                self.__parsed_rosters[roster_file] = roster_data
            return roster_file
class Get_pubkey(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Return the key string for the SSH public key
            '''
            if '__master_opts__' in self.opts and \
                    self.opts['__master_opts__'].get('ssh_use_home_key') and \
                    os.path.isfile(os.path.expanduser('~/.ssh/id_rsa')):
                priv = os.path.expanduser('~/.ssh/id_rsa')
            else:
                priv = self.opts.get(
                        'ssh_priv',
                        os.path.join(
                            self.opts['pki_dir'],
                            'ssh',
                            'salt-ssh.rsa'
                            )
                        )
            pub = '{0}.pub'.format(priv)
            with salt.utils.files.fopen(pub, 'r') as fp_:
                return '{0} rsa root@master'.format(fp_.read().split()[1])
class Deploy(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Deploy salt-thin
            '''
            self.shell.send(
                self.thin,
                os.path.join(self.thin_dir, 'salt-thin.tgz'),
            )
            self.deploy_ext()
            return True
class Deploy_ext(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Deploy the ext_mods tarball
            '''
            if self.mods.get('file'):
                self.shell.send(
                    self.mods['file'],
                    os.path.join(self.thin_dir, 'salt-ext_mods.tgz'),
                )
            return True
class _cmd_str(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Prepare the command string
            '''
            sudo = 'sudo' if self.target['sudo'] else ''
            sudo_user = self.target['sudo_user']
            if '_caller_cachedir' in self.opts:
                cachedir = self.opts['_caller_cachedir']
            else:
                cachedir = self.opts['cachedir']
            thin_code_digest, thin_sum = salt.utils.thin.thin_sum(cachedir, 'sha1')
            debug = ''
            if not self.opts.get('log_level'):
                self.opts['log_level'] = 'info'
            if salt.log.LOG_LEVELS['debug'] >= salt.log.LOG_LEVELS[self.opts.get('log_level', 'info')]:
                debug = '1'
            arg_str = '''
    OPTIONS.config = """
    {config}
    """
    OPTIONS.delimiter = '{delimeter}'
    OPTIONS.saltdir = '{saltdir}'
    OPTIONS.checksum = '{checksum}'
    OPTIONS.hashfunc = '{hashfunc}'
    OPTIONS.version = '{version}'
    OPTIONS.ext_mods = '{ext_mods}'
    OPTIONS.wipe = {wipe}
    OPTIONS.tty = {tty}
    OPTIONS.cmd_umask = {cmd_umask}
    OPTIONS.code_checksum = {code_checksum}
    ARGS = {arguments}\n''''''
    OPTIONS.config = \
    """
    {config}
    """
    OPTIONS.delimiter = '{delimeter}'
    OPTIONS.saltdir = '{saltdir}'
    OPTIONS.checksum = '{checksum}'
    OPTIONS.hashfunc = '{hashfunc}'
    OPTIONS.version = '{version}'
    OPTIONS.ext_mods = '{ext_mods}'
    OPTIONS.wipe = {wipe}
    OPTIONS.tty = {tty}
    OPTIONS.cmd_umask = {cmd_umask}
    OPTIONS.code_checksum = {code_checksum}
    ARGS = {arguments}\n'''.format(config=self.minion_config,
                                   delimeter=RSTR,
                                   saltdir=self.thin_dir,
                                   checksum=thin_sum,
                                   hashfunc='sha1',
                                   version=salt.version.__version__,
                                   ext_mods=self.mods.get('version', ''),
                                   wipe=self.wipe,
                                   tty=self.tty,
                                   cmd_umask=self.cmd_umask,
                                   code_checksum=thin_code_digest,
                                   arguments=self.argv)
            py_code = SSH_PY_SHIM.replace('#%%OPTS', arg_str)
            if six.PY2:
                py_code_enc = py_code.encode('base64')
            else:
                py_code_enc = base64.encodebytes(py_code.encode('utf-8')).decode('utf-8')
            if not self.winrm:
                cmd = SSH_SH_SHIM.format(
                    DEBUG=debug,
                    SUDO=sudo,
                    SUDO_USER=sudo_user,
                    SSH_PY_CODE=py_code_enc,
                    HOST_PY_MAJOR=sys.version_info[0],
                )
            else:
                cmd = saltwinshell.gen_shim(py_code_enc)
    
            return cmd
class _dict_to_name_value(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, data):
        '''
        Convert a dictionary to a list of dictionaries to facilitate ordering
        '''
        if isinstance(data, dict):
            sorted_data = sorted(data.items(), key=lambda s: s[0])
            result = []
            for name, value in sorted_data:
                if isinstance(value, dict):
                    result.append({name: _dict_to_name_value(value)})
                else:
                    result.append({name: value})
        else:
            result = data
        return result
class _generate_states_report(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, sorted_data):
        '''
        Generate states report
        '''
        states = []
        for state, data in sorted_data:
            module, stateid, name, function = state.split('_|-')
            module_function = '.'.join((module, function))
            result = data.get('result', '')
            single = [
                {'function': module_function},
                {'name': name},
                {'result': result},
                {'duration': data.get('duration', 0.0)},
                {'comment': data.get('comment', '')}
            ]
    
            if not result:
                style = 'failed'
            else:
                changes = data.get('changes', {})
                if changes and isinstance(changes, dict):
                    single.append({'changes': _dict_to_name_value(changes)})
                    style = 'changed'
                else:
                    style = 'unchanged'
    
            started = data.get('start_time', '')
            if started:
                single.append({'started': started})
    
            states.append({stateid: single, '__style__': style})
        return states
class Returner(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, ret):
        '''
        Check highstate return information and possibly fire off an email
        or save a file.
        '''
        setup = _get_options(ret)
    
        log.debug('highstate setup %s', setup)
    
        report, failed = _generate_report(ret, setup)
        if report:
            _produce_output(report, failed, setup)
class Version(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *names,**kwargs):
        '''
        Returns a string representing the package version or an empty string if not
        installed. If more than one package name is specified, a dict of
        name/version pairs is returned.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' pkg.version <package name>
            salt '*' pkg.version <package1> <package2> <package3> ...
        '''
        if len(names) == 1:
            vers = __proxy__['dummy.package_status'](names[0])
            return vers[names[0]]
        else:
            results = {}
            for n in names:
                vers = __proxy__['dummy.package_status'](n)
                results.update(vers)
            return results
class Grant_winsta_and_desktop(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, th):
        '''
        Grant the token's user access to the current process's window station and
        desktop.
        '''
        current_sid = win32security.GetTokenInformation(th, win32security.TokenUser)[0]
        # Add permissions for the sid to the current windows station and thread id.
        # This prevents windows error 0xC0000142.
        winsta = win32process.GetProcessWindowStation()
        set_user_perm(winsta, WINSTA_ALL, current_sid)
        desktop = win32service.GetThreadDesktop(win32api.GetCurrentThreadId())
        set_user_perm(desktop, DESKTOP_ALL, current_sid)
class Dup_token(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, th):
        '''
        duplicate the access token
        '''
        # TODO: is `duplicate_token` the same?
        sec_attr = win32security.SECURITY_ATTRIBUTES()
        sec_attr.bInheritHandle = True
        return win32security.DuplicateTokenEx(
           th,
           win32security.SecurityImpersonation,
           win32con.MAXIMUM_ALLOWED,
           win32security.TokenPrimary,
           sec_attr,
        )
class Elevate_token(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, th):
        '''
        Set all token priviledges to enabled
        '''
        # Get list of privileges this token contains
        privileges = win32security.GetTokenInformation(
            th, win32security.TokenPrivileges)
    
        # Create a set of all privileges to be enabled
        enable_privs = set()
        for luid, flags in privileges:
            enable_privs.add((luid, win32con.SE_PRIVILEGE_ENABLED))
    
        # Enable the privileges
        if win32security.AdjustTokenPrivileges(th, 0, enable_privs) == 0:
            raise WindowsError(win32api.FormatMessage(win32api.GetLastError()))
class Make_inheritable(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, token):
        '''Create an inheritable handle'''
        return win32api.DuplicateHandle(
            win32api.GetCurrentProcess(),
            token,
            win32api.GetCurrentProcess(),
            0,
            1,
            win32con.DUPLICATE_SAME_ACCESS
        )
class _fix_quantities(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, tree):
        '''
        Stupidly simple function to fix any Items/Quantity disparities inside a
        DistributionConfig block before use. Since AWS only accepts JSON-encodable
        data types, this implementation is "good enough" for our purposes.
        '''
        if isinstance(tree, dict):
            tree = {k: _fix_quantities(v) for k, v in tree.items()}
            if isinstance(tree.get('Items'), list):
                tree['Quantity'] = len(tree['Items'])
                if not tree['Items']:
                    tree.pop('Items')  # Silly, but AWS requires it....
            return tree
        elif isinstance(tree, list):
            return [_fix_quantities(t) for t in tree]
        else:
            return tree
class Remove(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, pkg):
        '''
        Remove the specified snap package. Returns a dictionary of "result" and "output".
    
        pkg
            The package name
        '''
        ret = {'result': None, 'output': ""}
        try:
            ret['output'] = subprocess.check_output([SNAP_BINARY_NAME, 'remove', pkg])
            ret['result'] = True
        except subprocess.CalledProcessError as e:
            ret['output'] = e.output
            ret['result'] = False
class Versions_installed(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, pkg):
        '''
        Query which version(s) of the specified snap package are installed.
        Returns a list of 0 or more dictionaries.
    
        pkg
            The package name
        '''
    
        try:
            # Try to run it, merging stderr into output
            output = subprocess.check_output([SNAP_BINARY_NAME, 'list', pkg], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            return []
    
        lines = output.splitlines()[1:]
        ret = []
        for item in lines:
            # If fields contain spaces this will break.
            i = item.split()
            # Ignore 'Notes' field
            ret.append({
                'name':         i[0],
                'version':      i[1],
                'rev':          i[2],
                'tracking':     i[3],
                'publisher':    i[4]
                })
    
        return ret
class Get_site_packages(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, venv):
        '''
        Return the path to the site-packages directory of a virtualenv
    
        venv
            Path to the virtualenv.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' virtualenv.get_site_packages /path/to/my/venv
        '''
        bin_path = _verify_virtualenv(venv)
    
        ret = __salt__['cmd.exec_code_all'](
            bin_path,
            'from distutils import sysconfig; '
                'print(sysconfig.get_python_lib())'
        )
    
        if ret['retcode'] != 0:
            raise CommandExecutionError('{stdout}\n{stderr}'.format(**ret))
    
        return ret['stdout']
class List_nodes(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a list of the VMs
    
        id (str)
        image (str)
        size (str)
        state (str)
        private_ips (list)
        public_ips (list)
    
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The list_nodes function must be called '
                'with -f or --function.'
            )
    
        providers = __opts__.get('providers', {})
    
        ret = {}
        providers_to_check = [_f for _f in [cfg.get('libvirt') for cfg in six.itervalues(providers)] if _f]
        for provider in providers_to_check:
            conn = __get_conn(provider['url'])
            domains = conn.listAllDomains()
            for domain in domains:
                data = {
                    'id': domain.UUIDString(),
                    'image': '',
                    'size': '',
                    'state': VIRT_STATE_NAME_MAP[domain.state()[0]],
                    'private_ips': [],
                    'public_ips': get_domain_ips(domain, libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)}
                # TODO: Annoyingly name is not guaranteed to be unique, but the id will not work in other places
                ret[domain.name()] = data
    
        return ret
class List_nodes_select(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a list of the VMs that are on the provider, with select fields
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The list_nodes_select function must be called '
                'with -f or --function.'
            )
    
        selection = __opts__.get('query.selection')
    
        if not selection:
            raise SaltCloudSystemExit(
                'query.selection not found in /etc/salt/cloud'
            )
    
        # TODO: somewhat doubt the implementation of cloud.list_nodes_select
        return salt.utils.cloud.list_nodes_select(
            list_nodes_full(), selection, call,
        )
class Create(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Provision a single machine
        '''
        clone_strategy = vm_.get('clone_strategy') or 'full'
    
        if clone_strategy not in ('quick', 'full'):
            raise SaltCloudSystemExit("'clone_strategy' must be one of quick or full. Got '{0}'".format(clone_strategy))
    
        ip_source = vm_.get('ip_source') or 'ip-learning'
    
        if ip_source not in ('ip-learning', 'qemu-agent'):
            raise SaltCloudSystemExit("'ip_source' must be one of qemu-agent or ip-learning. Got '{0}'".format(ip_source))
    
        validate_xml = vm_.get('validate_xml') if vm_.get('validate_xml') is not None else True
    
        log.info("Cloning '%s' with strategy '%s' validate_xml='%s'", vm_['name'], clone_strategy, validate_xml)
    
        try:
            # Check for required profile parameters before sending any API calls.
            if vm_['profile'] and config.is_profile_configured(__opts__,
                                                               __active_provider_name__ or 'libvirt',
                                                               vm_['profile']) is False:
                return False
        except AttributeError:
            pass
    
        # TODO: check name qemu/libvirt will choke on some characters (like '/')?
        name = vm_['name']
    
        __utils__['cloud.fire_event'](
            'event',
            'starting create',
            'salt/cloud/{0}/creating'.format(name),
            args=__utils__['cloud.filter_event']('creating', vm_, ['name', 'profile', 'provider', 'driver']),
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        key_filename = config.get_cloud_config_value(
            'private_key', vm_, __opts__, search_global=False, default=None
        )
        if key_filename is not None and not os.path.isfile(key_filename):
            raise SaltCloudConfigError(
                'The defined key_filename \'{0}\' does not exist'.format(
                    key_filename
                )
            )
        vm_['key_filename'] = key_filename
        # wait_for_instance requires private_key
        vm_['private_key'] = key_filename
    
        cleanup = []
        try:
            # clone the vm
            base = vm_['base_domain']
            conn = __get_conn(vm_['url'])
    
            try:
                # for idempotency the salt-bootstrap needs -F argument
                #  script_args: -F
                clone_domain = conn.lookupByName(name)
            except libvirtError as e:
                domain = conn.lookupByName(base)
                # TODO: ensure base is shut down before cloning
                xml = domain.XMLDesc(0)
    
                kwargs = {
                    'name': name,
                    'base_domain': base,
                }
    
                __utils__['cloud.fire_event'](
                    'event',
                    'requesting instance',
                    'salt/cloud/{0}/requesting'.format(name),
                    args={
                        'kwargs': __utils__['cloud.filter_event']('requesting', kwargs, list(kwargs)),
                    },
                    sock_dir=__opts__['sock_dir'],
                    transport=__opts__['transport']
                )
    
                log.debug("Source machine XML '%s'", xml)
    
                domain_xml = ElementTree.fromstring(xml)
                domain_xml.find('./name').text = name
                if domain_xml.find('./description') is None:
                    description_elem = ElementTree.Element('description')
                    domain_xml.insert(0, description_elem)
                description = domain_xml.find('./description')
                description.text = "Cloned from {0}".format(base)
                domain_xml.remove(domain_xml.find('./uuid'))
    
                for iface_xml in domain_xml.findall('./devices/interface'):
                    iface_xml.remove(iface_xml.find('./mac'))
                    # enable IP learning, this might be a default behaviour...
                    # Don't always enable since it can cause problems through libvirt-4.5
                    if ip_source == 'ip-learning' and iface_xml.find("./filterref/parameter[@name='CTRL_IP_LEARNING']") is None:
                        iface_xml.append(ElementTree.fromstring(IP_LEARNING_XML))
    
                # If a qemu agent is defined we need to fix the path to its socket
                # <channel type='unix'>
                #   <source mode='bind' path='/var/lib/libvirt/qemu/channel/target/domain-<dom-name>/org.qemu.guest_agent.0'/>
                #   <target type='virtio' name='org.qemu.guest_agent.0'/>
                #   <address type='virtio-serial' controller='0' bus='0' port='2'/>
                # </channel>
                for agent_xml in domain_xml.findall("""./devices/channel[@type='unix']"""):
                    #  is org.qemu.guest_agent.0 an option?
                    if agent_xml.find("""./target[@type='virtio'][@name='org.qemu.guest_agent.0']""") is not None:
                        source_element = agent_xml.find("""./source[@mode='bind']""")
                        # see if there is a path element that needs rewriting
                        if source_element and 'path' in source_element.attrib:
                            path = source_element.attrib['path']
                            new_path = path.replace('/domain-{0}/'.format(base), '/domain-{0}/'.format(name))
                            log.debug("Rewriting agent socket path to %s", new_path)
                            source_element.attrib['path'] = new_path
    
                for disk in domain_xml.findall("""./devices/disk[@device='disk'][@type='file']"""):
                    # print "Disk: ", ElementTree.tostring(disk)
                    # check if we can clone
                    driver = disk.find("./driver[@name='qemu']")
                    if driver is None:
                        # Err on the safe side
                        raise SaltCloudExecutionFailure("Non qemu driver disk encountered bailing out.")
                    disk_type = driver.attrib.get('type')
                    log.info("disk attributes %s", disk.attrib)
                    if disk_type == 'qcow2':
                        source = disk.find("./source").attrib['file']
                        pool, volume = find_pool_and_volume(conn, source)
                        if clone_strategy == 'quick':
                            new_volume = pool.createXML(create_volume_with_backing_store_xml(volume), 0)
                        else:
                            new_volume = pool.createXMLFrom(create_volume_xml(volume), volume, 0)
                        cleanup.append({'what': 'volume', 'item': new_volume})
    
                        disk.find("./source").attrib['file'] = new_volume.path()
                    elif disk_type == 'raw':
                        source = disk.find("./source").attrib['file']
                        pool, volume = find_pool_and_volume(conn, source)
                        # TODO: more control on the cloned disk type
                        new_volume = pool.createXMLFrom(create_volume_xml(volume), volume, 0)
                        cleanup.append({'what': 'volume', 'item': new_volume})
    
                        disk.find("./source").attrib['file'] = new_volume.path()
                    else:
                        raise SaltCloudExecutionFailure("Disk type '{0}' not supported".format(disk_type))
    
                clone_xml = salt.utils.stringutils.to_str(ElementTree.tostring(domain_xml))
                log.debug("Clone XML '%s'", clone_xml)
    
                validate_flags = libvirt.VIR_DOMAIN_DEFINE_VALIDATE if validate_xml else 0
                clone_domain = conn.defineXMLFlags(clone_xml, validate_flags)
    
                cleanup.append({'what': 'domain', 'item': clone_domain})
                clone_domain.createWithFlags(libvirt.VIR_DOMAIN_START_FORCE_BOOT)
    
            log.debug("VM '%s'", vm_)
    
            if ip_source == 'qemu-agent':
                ip_source = libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT
            elif ip_source == 'ip-learning':
                ip_source = libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE
    
            address = salt.utils.cloud.wait_for_ip(
                get_domain_ip,
                update_args=(clone_domain, 0, ip_source),
                timeout=config.get_cloud_config_value('wait_for_ip_timeout', vm_, __opts__, default=10 * 60),
                interval=config.get_cloud_config_value('wait_for_ip_interval', vm_, __opts__, default=10),
                interval_multiplier=config.get_cloud_config_value('wait_for_ip_interval_multiplier', vm_, __opts__, default=1),
            )
    
            log.info('Address = %s', address)
    
            vm_['ssh_host'] = address
    
            # the bootstrap script needs to be installed first in /etc/salt/cloud.deploy.d/
            # salt-cloud -u is your friend
            ret = __utils__['cloud.bootstrap'](vm_, __opts__)
    
            __utils__['cloud.fire_event'](
                'event',
                'created instance',
                'salt/cloud/{0}/created'.format(name),
                args=__utils__['cloud.filter_event']('created', vm_, ['name', 'profile', 'provider', 'driver']),
                sock_dir=__opts__['sock_dir'],
                transport=__opts__['transport']
            )
    
            return ret
        except Exception as e:  # pylint: disable=broad-except
            do_cleanup(cleanup)
            # throw the root cause after cleanup
            raise e
class Do_cleanup(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, cleanup):
        '''
        Clean up clone domain leftovers as much as possible.
    
        Extra robust clean up in order to deal with some small changes in libvirt
        behavior over time. Passed in volumes and domains are deleted, any errors
        are ignored. Used when cloning/provisioning a domain fails.
    
        :param cleanup: list containing dictonaries with two keys: 'what' and 'item'.
                        If 'what' is domain the 'item' is a libvirt domain object.
                        If 'what' is volume then the item is a libvirt volume object.
    
        Returns:
            none
    
        .. versionadded: 2017.7.3
        '''
        log.info('Cleaning up after exception')
        for leftover in cleanup:
            what = leftover['what']
            item = leftover['item']
            if what == 'domain':
                log.info('Cleaning up %s %s', what, item.name())
                try:
                    item.destroy()
                    log.debug('%s %s forced off', what, item.name())
                except libvirtError:
                    pass
                try:
                    item.undefineFlags(libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE+
                                       libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA+
                                       libvirt.VIR_DOMAIN_UNDEFINE_NVRAM)
                    log.debug('%s %s undefined', what, item.name())
                except libvirtError:
                    pass
            if what == 'volume':
                try:
                    item.delete()
                    log.debug('%s %s cleaned up', what, item.name())
                except libvirtError:
                    pass
class Get_size(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Return the VM's size object
        '''
        vm_size = config.get_cloud_config_value(
            'fixed_instance_size', vm_, __opts__, default=None,
            search_global=False
        )
        sizes = avail_sizes()
    
        if not vm_size:
            size = next((item for item in sizes if item['name'] == 'S'), None)
            return size
    
        size = next((item for item in sizes if item['name'] == vm_size or item['id'] == vm_size), None)
        if size:
            return size
    
        raise SaltCloudNotFound(
            'The specified size, \'{0}\', could not be found.'.format(vm_size)
        )
class Get_image(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Return the image object to use
        '''
        vm_image = config.get_cloud_config_value('image', vm_, __opts__).encode(
            'ascii', 'salt-cloud-force-ascii'
        )
    
        images = avail_images()
        for key, value in six.iteritems(images):
            if vm_image and vm_image in (images[key]['id'], images[key]['name']):
                return images[key]
    
        raise SaltCloudNotFound(
            'The specified image, \'{0}\', could not be found.'.format(vm_image)
        )
class _get_block_storage(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, kwargs):
        '''
        Construct a block storage instance from passed arguments
        '''
        if kwargs is None:
            kwargs = {}
    
        block_storage_name = kwargs.get('name', None)
        block_storage_size = kwargs.get('size', None)
        block_storage_description = kwargs.get('description', None)
        datacenter_id = kwargs.get('datacenter_id', None)
        server_id = kwargs.get('server_id', None)
    
        block_storage = BlockStorage(
            name=block_storage_name,
            size=block_storage_size)
    
        if block_storage_description:
            block_storage.description = block_storage_description
    
        if datacenter_id:
            block_storage.datacenter_id = datacenter_id
    
        if server_id:
            block_storage.server_id = server_id
    
        return block_storage
class _get_ssh_key(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, kwargs):
        '''
        Construct an SshKey instance from passed arguments
        '''
        ssh_key_name = kwargs.get('name', None)
        ssh_key_description = kwargs.get('description', None)
        public_key = kwargs.get('public_key', None)
    
        return SshKey(
            name=ssh_key_name,
            description=ssh_key_description,
            public_key=public_key
        )
class _get_firewall_policy(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, kwargs):
        '''
        Construct FirewallPolicy and FirewallPolicy instances from passed arguments
        '''
        fp_name = kwargs.get('name', None)
        fp_description = kwargs.get('description', None)
        firewallPolicy = FirewallPolicy(
            name=fp_name,
            description=fp_description
        )
    
        fpr_json = kwargs.get('rules', None)
        jdata = json.loads(fpr_json)
        rules = []
        for fwpr in jdata:
            firewallPolicyRule = FirewallPolicyRule()
            if 'protocol' in fwpr:
                firewallPolicyRule.rule_set['protocol'] = fwpr['protocol']
            if 'port_from' in fwpr:
                firewallPolicyRule.rule_set['port_from'] = fwpr['port_from']
            if 'port_to' in fwpr:
                firewallPolicyRule.rule_set['port_to'] = fwpr['port_to']
            if 'source' in fwpr:
                firewallPolicyRule.rule_set['source'] = fwpr['source']
            if 'action' in fwpr:
                firewallPolicyRule.rule_set['action'] = fwpr['action']
            if 'description' in fwpr:
                firewallPolicyRule.rule_set['description'] = fwpr['description']
            if 'port' in fwpr:
                firewallPolicyRule.rule_set['port'] = fwpr['port']
            rules.append(firewallPolicyRule)
    
        return {'firewall_policy': firewallPolicy, 'firewall_policy_rules': rules}
class Avail_sizes(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a dict of all available VM sizes on the cloud provider with
        relevant data.
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The avail_sizes function must be called with '
                '-f or --function, or with the --list-sizes option'
            )
    
        conn = get_conn()
    
        sizes = conn.fixed_server_flavors()
    
        return sizes
class Baremetal_models(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a dict of all available baremetal models with relevant data.
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The baremetal_models function must be called with '
                '-f or --function'
            )
    
        conn = get_conn()
    
        bmodels = conn.list_baremetal_models()
    
        return bmodels
class _get_server(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Construct server instance from cloud profile config
        '''
        description = config.get_cloud_config_value(
            'description', vm_, __opts__, default=None,
            search_global=False
        )
    
        ssh_key = load_public_key(vm_)
    
        server_type = config.get_cloud_config_value(
            'server_type', vm_, __opts__, default='cloud',
            search_global=False
        )
        vcore = None
        cores_per_processor = None
        ram = None
        fixed_instance_size_id = None
        baremetal_model_id = None
    
        if 'fixed_instance_size' in vm_:
            fixed_instance_size = get_size(vm_)
            fixed_instance_size_id = fixed_instance_size['id']
        elif 'vm_core' in vm_ and 'cores_per_processor' in vm_ and 'ram' in vm_ and 'hdds' in vm_:
            vcore = config.get_cloud_config_value(
                'vcore', vm_, __opts__, default=None,
                search_global=False
            )
            cores_per_processor = config.get_cloud_config_value(
                'cores_per_processor', vm_, __opts__, default=None,
                search_global=False
            )
            ram = config.get_cloud_config_value(
                'ram', vm_, __opts__, default=None,
                search_global=False
            )
        elif 'baremetal_model_id' in vm_ and server_type == 'baremetal':
            baremetal_model_id = config.get_cloud_config_value(
                'baremetal_model_id', vm_, __opts__, default=None,
                search_global=False
            )
        else:
            raise SaltCloudConfigError("'fixed_instance_size' or 'vcore', "
                                       "'cores_per_processor', 'ram', and 'hdds' "
                                       "must be provided for 'cloud' server. "
                                       "For 'baremetal' server, 'baremetal_model_id'"
                                       "must be provided.")
    
        appliance_id = config.get_cloud_config_value(
            'appliance_id', vm_, __opts__, default=None,
            search_global=False
        )
    
        password = config.get_cloud_config_value(
            'password', vm_, __opts__, default=None,
            search_global=False
        )
    
        firewall_policy_id = config.get_cloud_config_value(
            'firewall_policy_id', vm_, __opts__, default=None,
            search_global=False
        )
    
        ip_id = config.get_cloud_config_value(
            'ip_id', vm_, __opts__, default=None,
            search_global=False
        )
    
        load_balancer_id = config.get_cloud_config_value(
            'load_balancer_id', vm_, __opts__, default=None,
            search_global=False
        )
    
        monitoring_policy_id = config.get_cloud_config_value(
            'monitoring_policy_id', vm_, __opts__, default=None,
            search_global=False
        )
    
        datacenter_id = config.get_cloud_config_value(
            'datacenter_id', vm_, __opts__, default=None,
            search_global=False
        )
    
        private_network_id = config.get_cloud_config_value(
            'private_network_id', vm_, __opts__, default=None,
            search_global=False
        )
    
        power_on = config.get_cloud_config_value(
            'power_on', vm_, __opts__, default=True,
            search_global=False
        )
    
        public_key = config.get_cloud_config_value(
            'public_key_ids', vm_, __opts__, default=None,
            search_global=False
        )
    
        # Contruct server object
        return Server(
            name=vm_['name'],
            description=description,
            fixed_instance_size_id=fixed_instance_size_id,
            vcore=vcore,
            cores_per_processor=cores_per_processor,
            ram=ram,
            appliance_id=appliance_id,
            password=password,
            power_on=power_on,
            firewall_policy_id=firewall_policy_id,
            ip_id=ip_id,
            load_balancer_id=load_balancer_id,
            monitoring_policy_id=monitoring_policy_id,
            datacenter_id=datacenter_id,
            rsa_key=ssh_key,
            private_network_id=private_network_id,
            public_key=public_key,
            server_type=server_type,
            baremetal_model_id=baremetal_model_id
        )
class _get_hdds(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Construct VM hdds from cloud profile config
        '''
        _hdds = config.get_cloud_config_value(
            'hdds', vm_, __opts__, default=None,
            search_global=False
        )
    
        hdds = []
    
        for hdd in _hdds:
            hdds.append(
                Hdd(
                    size=hdd['size'],
                    is_main=hdd['is_main']
                )
            )
    
        return hdds
class Create(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Create a single VM from a data dict
        '''
        try:
            # Check for required profile parameters before sending any API calls.
            if (vm_['profile'] and
               config.is_profile_configured(__opts__,
                                            (__active_provider_name__ or
                                             'oneandone'),
                                            vm_['profile']) is False):
                return False
        except AttributeError:
            pass
    
        data = None
        conn = get_conn()
        hdds = []
    
        # Assemble the composite server object.
        server = _get_server(vm_)
    
        if not bool(server.specs['hardware']['fixed_instance_size_id'])\
            and not bool(server.specs['server_type'] == 'baremetal'):
            # Assemble the hdds object.
            hdds = _get_hdds(vm_)
    
        __utils__['cloud.fire_event'](
            'event',
            'requesting instance',
            'salt/cloud/{0}/requesting'.format(vm_['name']),
            args={'name': vm_['name']},
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        try:
            data = conn.create_server(server=server, hdds=hdds)
    
            _wait_for_completion(conn,
                                 get_wait_timeout(vm_),
                                 data['id'])
        except Exception as exc:  # pylint: disable=W0703
            log.error(
                'Error creating %s on 1and1\n\n'
                'The following exception was thrown by the 1and1 library '
                'when trying to run the initial deployment: \n%s',
                vm_['name'], exc, exc_info_on_loglevel=logging.DEBUG
            )
            return False
    
        vm_['server_id'] = data['id']
        password = data['first_password']
    
        def __query_node_data(vm_, data):
            '''
            Query node data until node becomes available.
            '''
            running = False
            try:
                data = show_instance(vm_['name'], 'action')
                if not data:
                    return False
                log.debug(
                    'Loaded node data for %s:\nname: %s\nstate: %s',
                    vm_['name'],
                    pprint.pformat(data['name']),
                    data['status']['state']
                )
            except Exception as err:
                log.error(
                    'Failed to get nodes list: %s', err,
                    # Show the trackback if the debug logging level is enabled
                    exc_info_on_loglevel=logging.DEBUG
                )
                # Trigger a failure in the wait for IP function
                return False
    
            running = data['status']['state'].lower() == 'powered_on'
            if not running:
                # Still not running, trigger another iteration
                return
    
            vm_['ssh_host'] = data['ips'][0]['ip']
    
            return data
    
        try:
            data = salt.utils.cloud.wait_for_ip(
                __query_node_data,
                update_args=(vm_, data),
                timeout=config.get_cloud_config_value(
                    'wait_for_ip_timeout', vm_, __opts__, default=10 * 60),
                interval=config.get_cloud_config_value(
                    'wait_for_ip_interval', vm_, __opts__, default=10),
            )
        except (SaltCloudExecutionTimeout, SaltCloudExecutionFailure) as exc:
            try:
                # It might be already up, let's destroy it!
                destroy(vm_['name'])
            except SaltCloudSystemExit:
                pass
            finally:
                raise SaltCloudSystemExit(six.text_type(exc.message))
    
        log.debug('VM is now running')
        log.info('Created Cloud VM %s', vm_)
        log.debug('%s VM creation details:\n%s', vm_, pprint.pformat(data))
    
        __utils__['cloud.fire_event'](
            'event',
            'created instance',
            'salt/cloud/{0}/created'.format(vm_['name']),
            args={
                'name': vm_['name'],
                'profile': vm_['profile'],
                'provider': vm_['driver'],
            },
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        if 'ssh_host' in vm_:
            vm_['password'] = password
            vm_['key_filename'] = get_key_filename(vm_)
            ret = __utils__['cloud.bootstrap'](vm_, __opts__)
            ret.update(data)
            return ret
        else:
            raise SaltCloudSystemExit('A valid IP address was not found.')
class Load_public_key(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Load the public key file if exists.
        '''
        public_key_filename = config.get_cloud_config_value(
            'ssh_public_key', vm_, __opts__, search_global=False, default=None
        )
        if public_key_filename is not None:
            public_key_filename = os.path.expanduser(public_key_filename)
            if not os.path.isfile(public_key_filename):
                raise SaltCloudConfigError(
                    'The defined ssh_public_key \'{0}\' does not exist'.format(
                        public_key_filename
                    )
                )
    
            with salt.utils.files.fopen(public_key_filename, 'r') as public_key:
                key = salt.utils.stringutils.to_unicode(public_key.read().replace('\n', ''))
    
                return key
class Avail_images(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        ''' Return a list of the images that are on the provider.
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The avail_images function must be called with '
                '-f or --function, or with the --list-images option'
            )
    
        items = query(method='images', root='marketplace_root')
        ret = {}
        for image in items['images']:
            ret[image['id']] = {}
            for item in image:
                ret[image['id']][item] = six.text_type(image[item])
    
        return ret
class List_nodes(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        ''' Return a list of the BareMetal servers that are on the provider.
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The list_nodes function must be called with -f or --function.'
            )
    
        items = query(method='servers')
    
        ret = {}
        for node in items['servers']:
            public_ips = []
            private_ips = []
            image_id = ''
    
            if node.get('public_ip'):
                public_ips = [node['public_ip']['address']]
    
            if node.get('private_ip'):
                private_ips = [node['private_ip']]
    
            if node.get('image'):
                image_id = node['image']['id']
    
            ret[node['name']] = {
                'id': node['id'],
                'image_id': image_id,
                'public_ips': public_ips,
                'private_ips': private_ips,
                'size': node['volumes']['0']['size'],
                'state': node['state'],
            }
        return ret
class List_nodes_full(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        ''' Return a list of the BareMetal servers that are on the provider.
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'list_nodes_full must be called with -f or --function'
            )
    
        items = query(method='servers')
    
        # For each server, iterate on its parameters.
        ret = {}
        for node in items['servers']:
            ret[node['name']] = {}
            for item in node:
                value = node[item]
                ret[node['name']][item] = value
        return ret
class Get_image(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, server_):
        ''' Return the image object to use.
        '''
        images = avail_images()
        server_image = six.text_type(config.get_cloud_config_value(
            'image', server_, __opts__, search_global=False
        ))
        for image in images:
            if server_image in (images[image]['name'], images[image]['id']):
                return images[image]['id']
        raise SaltCloudNotFound(
            'The specified image, \'{0}\', could not be found.'.format(server_image)
        )
class Create_node(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, args):
        ''' Create a node.
        '''
        node = query(method='servers', args=args, http_method='POST')
    
        action = query(
            method='servers',
            server_id=node['server']['id'],
            command='action',
            args={'action': 'poweron'},
            http_method='POST'
        )
        return node
class Create(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, server_):
        '''
        Create a single BareMetal server from a data dict.
        '''
        try:
            # Check for required profile parameters before sending any API calls.
            if server_['profile'] and config.is_profile_configured(__opts__,
                                                                   __active_provider_name__ or 'scaleway',
                                                                   server_['profile'],
                                                                   vm_=server_) is False:
                return False
        except AttributeError:
            pass
    
        __utils__['cloud.fire_event'](
            'event',
            'starting create',
            'salt/cloud/{0}/creating'.format(server_['name']),
            args=__utils__['cloud.filter_event']('creating', server_, ['name', 'profile', 'provider', 'driver']),
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        log.info('Creating a BareMetal server %s', server_['name'])
    
        access_key = config.get_cloud_config_value(
            'access_key', get_configured_provider(), __opts__, search_global=False
        )
    
        commercial_type = config.get_cloud_config_value(
            'commercial_type', server_, __opts__, default='C1'
        )
    
        key_filename = config.get_cloud_config_value(
            'ssh_key_file', server_, __opts__, search_global=False, default=None
        )
    
        if key_filename is not None and not os.path.isfile(key_filename):
            raise SaltCloudConfigError(
                'The defined key_filename \'{0}\' does not exist'.format(
                    key_filename
                )
            )
    
        ssh_password = config.get_cloud_config_value(
            'ssh_password', server_, __opts__
        )
    
        kwargs = {
            'name': server_['name'],
            'organization': access_key,
            'image': get_image(server_),
            'commercial_type': commercial_type,
        }
    
        __utils__['cloud.fire_event'](
            'event',
            'requesting instance',
            'salt/cloud/{0}/requesting'.format(server_['name']),
            args={
                'kwargs': __utils__['cloud.filter_event']('requesting', kwargs, list(kwargs)),
            },
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        try:
            ret = create_node(kwargs)
        except Exception as exc:
            log.error(
                'Error creating %s on Scaleway\n\n'
                'The following exception was thrown when trying to '
                'run the initial deployment: %s',
                server_['name'], exc,
                # Show the traceback if the debug logging level is enabled
                exc_info_on_loglevel=logging.DEBUG
            )
            return False
    
        def __query_node_data(server_name):
            ''' Called to check if the server has a public IP address.
            '''
            data = show_instance(server_name, 'action')
            if data and data.get('public_ip'):
                return data
            return False
    
        try:
            data = salt.utils.cloud.wait_for_ip(
                __query_node_data,
                update_args=(server_['name'],),
                timeout=config.get_cloud_config_value(
                    'wait_for_ip_timeout', server_, __opts__, default=10 * 60),
                interval=config.get_cloud_config_value(
                    'wait_for_ip_interval', server_, __opts__, default=10),
            )
        except (SaltCloudExecutionTimeout, SaltCloudExecutionFailure) as exc:
            try:
                # It might be already up, let's destroy it!
                destroy(server_['name'])
            except SaltCloudSystemExit:
                pass
            finally:
                raise SaltCloudSystemExit(six.text_type(exc))
    
        server_['ssh_host'] = data['public_ip']['address']
        server_['ssh_password'] = ssh_password
        server_['key_filename'] = key_filename
        ret = __utils__['cloud.bootstrap'](server_, __opts__)
    
        ret.update(data)
    
        log.info('Created BareMetal server \'%s\'', server_['name'])
        log.debug(
            '\'%s\' BareMetal server creation details:\n%s',
            server_['name'], pprint.pformat(data)
        )
    
        __utils__['cloud.fire_event'](
            'event',
            'created instance',
            'salt/cloud/{0}/created'.format(server_['name']),
            args=__utils__['cloud.filter_event']('created', server_, ['name', 'profile', 'provider', 'driver']),
            sock_dir=__opts__['sock_dir'],
            transport=__opts__['transport']
        )
    
        return ret
class Script(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, server_):
        ''' Return the script deployment object.
        '''
        return salt.utils.cloud.os_script(
            config.get_cloud_config_value('script', server_, __opts__),
            server_,
            __opts__,
            salt.utils.cloud.salt_config_to_yaml(
                salt.utils.cloud.minion_config(__opts__, server_)
            )
        )
class Nodes(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, verbose=False):
        '''
        List all compute nodes
    
        verbose : boolean
            print additional information about the node
            e.g. platform version, hvm capable, ...
    
        CLI Example:
    
        .. code-block:: bash
    
            salt-run vmadm.nodes
            salt-run vmadm.nodes verbose=True
        '''
        ret = {} if verbose else []
        client = salt.client.get_local_client(__opts__['conf_file'])
    
        ## get list of nodes
        try:
            for cn in client.cmd_iter('G@virtual:physical and G@os:smartos',
                                      'grains.items', tgt_type='compound'):
                if not cn:
                    continue
                node = next(six.iterkeys(cn))
                if not isinstance(cn[node], dict) or \
                        'ret' not in cn[node] or \
                        not isinstance(cn[node]['ret'], dict):
                    continue
                if verbose:
                    ret[node] = {}
                    ret[node]['version'] = {}
                    ret[node]['version']['platform'] = cn[node]['ret']['osrelease']
                    if 'computenode_sdc_version' in cn[node]['ret']:
                        ret[node]['version']['sdc'] = cn[node]['ret']['computenode_sdc_version']
                    ret[node]['vms'] = {}
                    if 'computenode_vm_capable' in cn[node]['ret'] and \
                            cn[node]['ret']['computenode_vm_capable'] and \
                            'computenode_vm_hw_virt' in cn[node]['ret']:
                        ret[node]['vms']['hw_cap'] = cn[node]['ret']['computenode_vm_hw_virt']
                    else:
                        ret[node]['vms']['hw_cap'] = False
                    if 'computenode_vms_running' in cn[node]['ret']:
                        ret[node]['vms']['running'] = cn[node]['ret']['computenode_vms_running']
                else:
                    ret.append(node)
        except SaltClientError as client_error:
            return "{0}".format(client_error)
    
        if not verbose:
            ret.sort()
        return ret
class _xml_to_dict(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, xmltree):
        '''
        Convert an XML tree into a dict
        '''
        if sys.version_info < (2, 7):
            children_len = len(xmltree.getchildren())
        else:
            children_len = len(xmltree)
    
        if children_len < 1:
            name = xmltree.tag
            if '}' in name:
                comps = name.split('}')
                name = comps[1]
            return {name: xmltree.text}
    
        xmldict = {}
        for item in xmltree:
            name = item.tag
            if '}' in name:
                comps = name.split('}')
                name = comps[1]
            if name not in xmldict:
                if sys.version_info < (2, 7):
                    children_len = len(item.getchildren())
                else:
                    children_len = len(item)
    
                if children_len > 0:
                    xmldict[name] = _xml_to_dict(item)
                else:
                    xmldict[name] = item.text
            else:
                if not isinstance(xmldict[name], list):
                    tempvar = xmldict[name]
                    xmldict[name] = []
                    xmldict[name].append(tempvar)
                xmldict[name].append(_xml_to_dict(item))
        return xmldict
class Optimize_providers(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, providers):
        '''
        Return an optimized list of providers.
    
        We want to reduce the duplication of querying
        the same region.
    
        If a provider is using the same credentials for the same region
        the same data will be returned for each provider, thus causing
        un-wanted duplicate data and API calls to EC2.
    
        '''
        tmp_providers = {}
        optimized_providers = {}
    
        for name, data in six.iteritems(providers):
            if 'location' not in data:
                data['location'] = DEFAULT_LOCATION
    
            if data['location'] not in tmp_providers:
                tmp_providers[data['location']] = {}
    
            creds = (data['id'], data['key'])
            if creds not in tmp_providers[data['location']]:
                tmp_providers[data['location']][creds] = {'name': name,
                                                          'data': data,
                                                          }
    
        for location, tmp_data in six.iteritems(tmp_providers):
            for creds, data in six.iteritems(tmp_data):
                _id, _key = creds
                _name = data['name']
                _data = data['data']
                if _name not in optimized_providers:
                    optimized_providers[_name] = _data
    
        return optimized_providers
class Ssh_interface(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Return the ssh_interface type to connect to. Either 'public_ips' (default)
        or 'private_ips'.
        '''
        ret = config.get_cloud_config_value(
            'ssh_interface', vm_, __opts__, default='public_ips',
            search_global=False
        )
        if ret not in ('public_ips', 'private_ips'):
            log.warning(
                'Invalid ssh_interface: %s. '
                'Allowed options are ("public_ips", "private_ips"). '
                'Defaulting to "public_ips".', ret
            )
            ret = 'public_ips'
        return ret
class Get_ssh_gateway_config(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Return the ssh_gateway configuration.
        '''
        ssh_gateway = config.get_cloud_config_value(
            'ssh_gateway', vm_, __opts__, default=None,
            search_global=False
        )
    
        # Check to see if a SSH Gateway will be used.
        if not isinstance(ssh_gateway, six.string_types):
            return None
    
        # Create dictionary of configuration items
    
        # ssh_gateway
        ssh_gateway_config = {'ssh_gateway': ssh_gateway}
    
        # ssh_gateway_port
        ssh_gateway_config['ssh_gateway_port'] = config.get_cloud_config_value(
            'ssh_gateway_port', vm_, __opts__, default=None,
            search_global=False
        )
    
        # ssh_gateway_username
        ssh_gateway_config['ssh_gateway_user'] = config.get_cloud_config_value(
            'ssh_gateway_username', vm_, __opts__, default=None,
            search_global=False
        )
    
        # ssh_gateway_private_key
        ssh_gateway_config['ssh_gateway_key'] = config.get_cloud_config_value(
            'ssh_gateway_private_key', vm_, __opts__, default=None,
            search_global=False
        )
    
        # ssh_gateway_password
        ssh_gateway_config['ssh_gateway_password'] = config.get_cloud_config_value(
            'ssh_gateway_password', vm_, __opts__, default=None,
            search_global=False
        )
    
        # ssh_gateway_command
        ssh_gateway_config['ssh_gateway_command'] = config.get_cloud_config_value(
            'ssh_gateway_command', vm_, __opts__, default=None,
            search_global=False
        )
    
        # Check if private key exists
        key_filename = ssh_gateway_config['ssh_gateway_key']
        if key_filename is not None and not os.path.isfile(key_filename):
            raise SaltCloudConfigError(
                'The defined ssh_gateway_private_key \'{0}\' does not exist'
                .format(key_filename)
            )
        elif (
            key_filename is None and
            not ssh_gateway_config['ssh_gateway_password']
        ):
            raise SaltCloudConfigError(
                'No authentication method. Please define: '
                ' ssh_gateway_password or ssh_gateway_private_key'
            )
    
        return ssh_gateway_config
class Avail_locations(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        List all available locations
        '''
        if call == 'action':
            raise SaltCloudSystemExit(
                'The avail_locations function must be called with '
                '-f or --function, or with the --list-locations option'
            )
    
        ret = {}
    
        params = {'Action': 'DescribeRegions'}
        result = aws.query(params,
                           location=get_location(),
                           provider=get_provider(),
                           opts=__opts__,
                           sigver='4')
    
        for region in result:
            ret[region['regionName']] = {
                'name': region['regionName'],
                'endpoint': region['regionEndpoint'],
            }
    
        return ret
class Get_availability_zone(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Return the availability zone to use
        '''
        avz = config.get_cloud_config_value(
            'availability_zone', vm_, __opts__, search_global=False
        )
    
        if avz is None:
            return None
    
        zones = _list_availability_zones(vm_)
    
        # Validate user-specified AZ
        if avz not in zones:
            raise SaltCloudException(
                'The specified availability zone isn\'t valid in this region: '
                '{0}\n'.format(
                    avz
                )
            )
    
        # check specified AZ is available
        elif zones[avz] != 'available':
            raise SaltCloudException(
                'The specified availability zone isn\'t currently available: '
                '{0}\n'.format(
                    avz
                )
            )
    
        return avz
class Get_imageid(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Returns the ImageId to use
        '''
        image = config.get_cloud_config_value(
            'image', vm_, __opts__, search_global=False
        )
        if image.startswith('ami-'):
            return image
        # a poor man's cache
        if not hasattr(get_imageid, 'images'):
            get_imageid.images = {}
        elif image in get_imageid.images:
            return get_imageid.images[image]
        params = {'Action': 'DescribeImages',
                  'Filter.0.Name': 'name',
                  'Filter.0.Value.0': image}
        # Query AWS, sort by 'creationDate' and get the last imageId
        _t = lambda x: datetime.datetime.strptime(x['creationDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        image_id = sorted(aws.query(params, location=get_location(),
                                     provider=get_provider(), opts=__opts__, sigver='4'),
                          lambda i, j: salt.utils.compat.cmp(_t(i), _t(j))
                          )[-1]['imageId']
        get_imageid.images[image] = image_id
        return image_id
class _get_subnetname_id(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, subnetname):
        '''
        Returns the SubnetId of a SubnetName to use
        '''
        params = {'Action': 'DescribeSubnets'}
        for subnet in aws.query(params, location=get_location(),
                   provider=get_provider(), opts=__opts__, sigver='4'):
            tags = subnet.get('tagSet', {}).get('item', {})
            if not isinstance(tags, list):
                tags = [tags]
            for tag in tags:
                if tag['key'] == 'Name' and tag['value'] == subnetname:
                    log.debug(
                        'AWS Subnet ID of %s is %s',
                        subnetname, subnet['subnetId']
                    )
                    return subnet['subnetId']
        return None
class Get_subnetid(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Returns the SubnetId to use
        '''
        subnetid = config.get_cloud_config_value(
            'subnetid', vm_, __opts__, search_global=False
        )
        if subnetid:
            return subnetid
    
        subnetname = config.get_cloud_config_value(
            'subnetname', vm_, __opts__, search_global=False
        )
        if subnetname:
            return _get_subnetname_id(subnetname)
        return None
class _get_securitygroupname_id(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, securitygroupname_list):
        '''
        Returns the SecurityGroupId of a SecurityGroupName to use
        '''
        securitygroupid_set = set()
        if not isinstance(securitygroupname_list, list):
            securitygroupname_list = [securitygroupname_list]
        params = {'Action': 'DescribeSecurityGroups'}
        for sg in aws.query(params, location=get_location(),
                            provider=get_provider(), opts=__opts__, sigver='4'):
            if sg['groupName'] in securitygroupname_list:
                log.debug(
                    'AWS SecurityGroup ID of %s is %s',
                    sg['groupName'], sg['groupId']
                )
                securitygroupid_set.add(sg['groupId'])
        return list(securitygroupid_set)
class Securitygroupid(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        Returns the SecurityGroupId
        '''
        securitygroupid_set = set()
        securitygroupid_list = config.get_cloud_config_value(
            'securitygroupid',
            vm_,
            __opts__,
            search_global=False
        )
        # If the list is None, then the set will remain empty
        # If the list is already a set then calling 'set' on it is a no-op
        # If the list is a string, then calling 'set' generates a one-element set
        # If the list is anything else, stacktrace
        if securitygroupid_list:
            securitygroupid_set = securitygroupid_set.union(set(securitygroupid_list))
    
        securitygroupname_list = config.get_cloud_config_value(
            'securitygroupname', vm_, __opts__, search_global=False
        )
        if securitygroupname_list:
            if not isinstance(securitygroupname_list, list):
                securitygroupname_list = [securitygroupname_list]
            params = {'Action': 'DescribeSecurityGroups'}
            for sg in aws.query(params, location=get_location(),
                                provider=get_provider(), opts=__opts__, sigver='4'):
                if sg['groupName'] in securitygroupname_list:
                    log.debug(
                        'AWS SecurityGroup ID of %s is %s',
                        sg['groupName'], sg['groupId']
                    )
                    securitygroupid_set.add(sg['groupId'])
        return list(securitygroupid_set)
class Get_provider(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_=None):
        '''
        Extract the provider name from vm
        '''
        if vm_ is None:
            provider = __active_provider_name__ or 'ec2'
        else:
            provider = vm_.get('provider', 'ec2')
    
        if ':' in provider:
            prov_comps = provider.split(':')
            provider = prov_comps[0]
        return provider
class _list_availability_zones(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_=None):
        '''
        List all availability zones in the current region
        '''
        ret = {}
    
        params = {'Action': 'DescribeAvailabilityZones',
                  'Filter.0.Name': 'region-name',
                  'Filter.0.Value.0': get_location(vm_)}
        result = aws.query(params,
                           location=get_location(vm_),
                           provider=get_provider(),
                           opts=__opts__,
                           sigver='4')
    
        for zone in result:
            ret[zone['zoneName']] = zone['zoneState']
    
        return ret
class _list_interface_private_addrs(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, eni_desc):
        '''
        Returns a list of all of the private IP addresses attached to a
        network interface. The 'primary' address will be listed first.
        '''
        primary = eni_desc.get('privateIpAddress')
        if not primary:
            return None
    
        addresses = [primary]
    
        lst = eni_desc.get('privateIpAddressesSet', {}).get('item', [])
        if not isinstance(lst, list):
            return addresses
    
        for entry in lst:
            if entry.get('primary') == 'true':
                continue
            if entry.get('privateIpAddress'):
                addresses.append(entry.get('privateIpAddress'))
    
        return addresses
class Queue_instances(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, instances):
        '''
        Queue a set of instances to be provisioned later. Expects a list.
    
        Currently this only queries node data, and then places it in the cloud
        cache (if configured). If the salt-cloud-reactor is being used, these
        instances will be automatically provisioned using that.
    
        For more information about the salt-cloud-reactor, see:
    
        https://github.com/saltstack-formulas/salt-cloud-reactor
        '''
        for instance_id in instances:
            node = _get_node(instance_id=instance_id)
            __utils__['cloud.cache_node'](node, __active_provider_name__, __opts__)
class _extract_instance_info(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, instances):
        '''
        Given an instance query, return a dict of all instance data
        '''
        ret = {}
        for instance in instances:
            # items could be type dict or list (for stopped EC2 instances)
            if isinstance(instance['instancesSet']['item'], list):
                for item in instance['instancesSet']['item']:
                    name = _extract_name_tag(item)
                    ret[name] = item
                    ret[name]['name'] = name
                    ret[name].update(
                        dict(
                            id=item['instanceId'],
                            image=item['imageId'],
                            size=item['instanceType'],
                            state=item['instanceState']['name'],
                            private_ips=item.get('privateIpAddress', []),
                            public_ips=item.get('ipAddress', [])
                        )
                    )
            else:
                item = instance['instancesSet']['item']
                name = _extract_name_tag(item)
                ret[name] = item
                ret[name]['name'] = name
                ret[name].update(
                    dict(
                        id=item['instanceId'],
                        image=item['imageId'],
                        size=item['instanceType'],
                        state=item['instanceState']['name'],
                        private_ips=item.get('privateIpAddress', []),
                        public_ips=item.get('ipAddress', [])
                    )
                )
    
        return ret
class _list_nodes_full(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, location=None):
        '''
        Return a list of the VMs that in this location
        '''
        provider = __active_provider_name__ or 'ec2'
        if ':' in provider:
            comps = provider.split(':')
            provider = comps[0]
    
        params = {'Action': 'DescribeInstances'}
        instances = aws.query(params,
                              location=location,
                              provider=provider,
                              opts=__opts__,
                              sigver='4')
        if 'error' in instances:
            raise SaltCloudSystemExit(
                'An error occurred while listing nodes: {0}'.format(
                    instances['error']['Errors']['Error']['Message']
                )
            )
    
        ret = _extract_instance_info(instances)
    
        __utils__['cloud.cache_node_list'](ret, provider, __opts__)
        return ret
class List_nodes_select(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, call=None):
        '''
        Return a list of the VMs that are on the provider, with select fields
        '''
        return salt.utils.cloud.list_nodes_select(
            list_nodes_full(get_location()), __opts__['query.selection'], call,
        )
class Get_vm_info(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        get the information for a VM.
    
        :param name: salt_id name
        :return: dictionary of {'machine': x, 'cwd': y, ...}.
        '''
        try:
            vm_ = __utils__['sdb.sdb_get'](_build_sdb_uri(name), __opts__)
        except KeyError:
            raise SaltInvocationError(
                'Probable sdb driver not found. Check your configuration.')
        if vm_ is None or 'machine' not in vm_:
            raise SaltInvocationError(
                'No Vagrant machine defined for Salt_id {}'.format(name))
        return vm_
class _erase_vm_info(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, name):
        '''
        erase the information for a VM the we are destroying.
    
        some sdb drivers (such as the SQLite driver we expect to use)
        do not have a `delete` method, so if the delete fails, we have
        to replace the with a blank entry.
        '''
        try:
            # delete the machine record
            vm_ = get_vm_info(name)
            if vm_['machine']:
                key = _build_machine_uri(vm_['machine'], vm_.get('cwd', '.'))
                try:
                    __utils__['sdb.sdb_delete'](key, __opts__)
                except KeyError:
                    # no delete method found -- load a blank value
                    __utils__['sdb.sdb_set'](key, None, __opts__)
        except Exception:
            pass
    
        uri = _build_sdb_uri(name)
        try:
            # delete the name record
            __utils__['sdb.sdb_delete'](uri, __opts__)
        except KeyError:
            # no delete method found -- load an empty dictionary
            __utils__['sdb.sdb_set'](uri, {}, __opts__)
        except Exception:
            pass
class _vagrant_ssh_config(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_):
        '''
        get the information for ssh communication from the new VM
    
        :param vm_: the VM's info as we have it now
        :return: dictionary of ssh stuff
        '''
        machine = vm_['machine']
        log.info('requesting vagrant ssh-config for VM %s', machine or '(default)')
        cmd = 'vagrant ssh-config {}'.format(machine)
        reply = __salt__['cmd.shell'](cmd,
                                      runas=vm_.get('runas'),
                                      cwd=vm_.get('cwd'),
                                      ignore_retcode=True)
        ssh_config = {}
        for line in reply.split('\n'):  # build a dictionary of the text reply
            tokens = line.strip().split()
            if len(tokens) == 2:  # each two-token line becomes a key:value pair
                ssh_config[tokens[0]] = tokens[1]
        log.debug('ssh_config=%s', repr(ssh_config))
        return ssh_config
class List_domains(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return a list of the salt_id names of all available Vagrant VMs on
        this host without regard to the path where they are defined.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' vagrant.list_domains --log-level=info
    
        The log shows information about all known Vagrant environments
        on this machine. This data is cached and may not be completely
        up-to-date.
        '''
        vms = []
        cmd = 'vagrant global-status'
        reply = __salt__['cmd.shell'](cmd)
        log.info('--->\n%s', reply)
        for line in reply.split('\n'):  # build a list of the text reply
            tokens = line.strip().split()
            try:
                _ = int(tokens[0], 16)  # valid id numbers are hexadecimal
            except (ValueError, IndexError):
                continue  # skip lines without valid id numbers
            machine = tokens[1]
            cwd = tokens[-1]
            name = get_machine_id(machine, cwd)
            if name:
                vms.append(name)
        return vms
class List_active_vms(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, cwd=None):
        '''
        Return a list of machine names for active virtual machine on the host,
        which are defined in the Vagrantfile at the indicated path.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' vagrant.list_active_vms  cwd=/projects/project_1
        '''
        vms = []
        cmd = 'vagrant status'
        reply = __salt__['cmd.shell'](cmd, cwd=cwd)
        log.info('--->\n%s', reply)
        for line in reply.split('\n'):  # build a list of the text reply
            tokens = line.strip().split()
            if len(tokens) > 1:
                if tokens[1] == 'running':
                    vms.append(tokens[0])
        return vms
class Stop(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Hard shutdown the virtual machine. (vagrant halt)
    
        CLI Example:
    
        .. code-block:: bash
    
            salt <host> vagrant.stop <salt_id>
        '''
        vm_ = get_vm_info(name)
        machine = vm_['machine']
    
        cmd = 'vagrant halt {}'.format(machine)
        ret = __salt__['cmd.retcode'](cmd,
                                      runas=vm_.get('runas'),
                                      cwd=vm_.get('cwd'))
        return ret == 0
class Destroy(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Destroy and delete a virtual machine. (vagrant destroy -f)
    
        This also removes the salt_id name defined by vagrant.init.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt <host> vagrant.destroy <salt_id>
        '''
        vm_ = get_vm_info(name)
        machine = vm_['machine']
    
        cmd = 'vagrant destroy -f {}'.format(machine)
    
        ret = __salt__['cmd.run_all'](cmd,
                                      runas=vm_.get('runas'),
                                      cwd=vm_.get('cwd'),
                                      output_loglevel='info')
        if ret['retcode'] == 0:
            _erase_vm_info(name)
            return 'Destroyed VM {0}'.format(name)
        return False
class _parse_forward(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, mapping):
        '''
        Parses a port forwarding statement in the form used by this state:
    
        from_port:to_port:protocol[:destination]
    
        and returns a ForwardingMapping object
        '''
        if len(mapping.split(':')) > 3:
            (srcport, destport, protocol, destaddr) = mapping.split(':')
        else:
            (srcport, destport, protocol) = mapping.split(':')
            destaddr = ''
        return ForwardingMapping(srcport, destport, protocol, destaddr)
class Todict(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Returns a pretty dictionary meant for command line output.
            '''
            return {
                'Source port': self.srcport,
                'Destination port': self.destport,
                'Protocol': self.protocol,
                'Destination address': self.destaddr}
class _connect(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return server object used to interact with Jenkins.
    
        :return: server object used to interact with Jenkins
        '''
        jenkins_url = __salt__['config.get']('jenkins.url') or \
            __salt__['config.get']('jenkins:url') or \
            __salt__['pillar.get']('jenkins.url')
    
        jenkins_user = __salt__['config.get']('jenkins.user') or \
            __salt__['config.get']('jenkins:user') or \
            __salt__['pillar.get']('jenkins.user')
    
        jenkins_password = __salt__['config.get']('jenkins.password') or \
            __salt__['config.get']('jenkins:password') or \
            __salt__['pillar.get']('jenkins.password')
    
        if not jenkins_url:
            raise SaltInvocationError('No Jenkins URL found.')
    
        return jenkins.Jenkins(jenkins_url,
                               username=jenkins_user,
                               password=jenkins_password)
class Job_exists(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name=None):
        '''
        Check whether the job exists in configured Jenkins jobs.
    
        :param name: The name of the job is check if it exists.
        :return: True if job exists, False if job does not exist.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' jenkins.job_exists jobname
    
        '''
        if not name:
            raise SaltInvocationError('Required parameter \'name\' is missing')
    
        server = _connect()
        if server.job_exists(name):
            return True
        else:
            return False
class Get_job_info(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name=None):
        '''
        Return information about the Jenkins job.
    
        :param name: The name of the job is check if it exists.
        :return: Information about the Jenkins job.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' jenkins.get_job_info jobname
    
        '''
        if not name:
            raise SaltInvocationError('Required parameter \'name\' is missing')
    
        server = _connect()
    
        if not job_exists(name):
            raise CommandExecutionError('Job \'{0}\' does not exist'.format(name))
    
        job_info = server.get_job_info(name)
        if job_info:
            return job_info
        return False
class Delete_job(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name=None):
        '''
        Return true is job is deleted successfully.
    
        :param name: The name of the job to delete.
        :return: Return true if job is deleted successfully.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' jenkins.delete_job jobname
    
        '''
        if not name:
            raise SaltInvocationError('Required parameter \'name\' is missing')
    
        server = _connect()
    
        if not job_exists(name):
            raise CommandExecutionError('Job \'{0}\' does not exist'.format(name))
    
        try:
            server.delete_job(name)
        except jenkins.JenkinsException as err:
            raise CommandExecutionError(
                'Encountered error deleting job \'{0}\': {1}'.format(name, err)
            )
        return True
class Job_status(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name=None):
        '''
        Return the current status, enabled or disabled, of the job.
    
        :param name: The name of the job to return status for
        :return: Return true if enabled or false if disabled.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' jenkins.job_status jobname
    
        '''
    
        if not name:
            raise SaltInvocationError('Required parameter \'name\' is missing')
    
        server = _connect()
    
        if not job_exists(name):
            raise CommandExecutionError('Job \'{0}\' does not exist'.format(name))
    
        return server.get_job_info('empty')['buildable']
class Get_job_config(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name=None):
        '''
        Return the current job configuration for the provided job.
    
        :param name: The name of the job to return the configuration for.
        :return: The configuration for the job specified.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' jenkins.get_job_config jobname
    
        '''
    
        if not name:
            raise SaltInvocationError('Required parameter \'name\' is missing')
    
        server = _connect()
    
        if not job_exists(name):
            raise CommandExecutionError('Job \'{0}\' does not exist'.format(name))
    
        job_info = server.get_job_config(name)
        return job_info
class Plugin_installed(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        .. versionadded:: 2016.11.0
    
        Return if the plugin is installed for the provided plugin name.
    
        :param name: The name of the parameter to confirm installation.
        :return: True if plugin exists, False if plugin does not exist.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' jenkins.plugin_installed pluginName
    
        '''
    
        server = _connect()
        plugins = server.get_plugins()
    
        exists = [plugin for plugin in plugins.keys() if name in plugin]
    
        if exists:
            return True
        else:
            return False
class Listener_dict_to_tuple(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, listener):
        '''
        Convert an ELB listener dict into a listener tuple used by certain parts of
        the AWS ELB API.
    
        CLI example:
    
        .. code-block:: bash
    
            salt myminion boto_elb.listener_dict_to_tuple '{"elb_port":80,"instance_port":80,"elb_protocol":"HTTP"}'
        '''
        # We define all listeners as complex listeners.
        if 'instance_protocol' not in listener:
            instance_protocol = listener['elb_protocol'].upper()
        else:
            instance_protocol = listener['instance_protocol'].upper()
        listener_tuple = [listener['elb_port'], listener['instance_port'],
                          listener['elb_protocol'], instance_protocol]
        if 'certificate' in listener:
            listener_tuple.append(listener['certificate'])
        return tuple(listener_tuple)
class Version(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *names,**kwargs):
        '''
        Common interface for obtaining the version of installed packages.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' pkg_resource.version vim
            salt '*' pkg_resource.version foo bar baz
            salt '*' pkg_resource.version 'python*'
        '''
        ret = {}
        versions_as_list = \
            salt.utils.data.is_true(kwargs.pop('versions_as_list', False))
        pkg_glob = False
        if names:
            pkgs = __salt__['pkg.list_pkgs'](versions_as_list=True, **kwargs)
            for name in names:
                if '*' in name:
                    pkg_glob = True
                    for match in fnmatch.filter(pkgs, name):
                        ret[match] = pkgs.get(match, [])
                else:
                    ret[name] = pkgs.get(name, [])
        if not versions_as_list:
            __salt__['pkg_resource.stringify'](ret)
        # Return a string if no globbing is used, and there is one item in the
        # return dict
        if len(ret) == 1 and not pkg_glob:
            try:
                return next(six.itervalues(ret))
            except StopIteration:
                return ''
        return ret
class Sort_pkglist(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, pkgs):
        '''
        Accepts a dict obtained from pkg.list_pkgs() and sorts in place the list of
        versions for any packages that have multiple versions installed, so that
        two package lists can be compared to one another.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' pkg_resource.sort_pkglist '["3.45", "2.13"]'
        '''
        # It doesn't matter that ['4.9','4.10'] would be sorted to ['4.10','4.9'],
        # so long as the sorting is consistent.
        try:
            for key in pkgs:
                # Passing the pkglist to set() also removes duplicate version
                # numbers (if present).
                pkgs[key] = sorted(set(pkgs[key]))
        except AttributeError as exc:
            log.exception(exc)
class Stringify(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, pkgs):
        '''
        Takes a dict of package name/version information and joins each list of
        installed versions into a string.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' pkg_resource.stringify 'vim: 7.127'
        '''
        try:
            for key in pkgs:
                pkgs[key] = ','.join(pkgs[key])
        except AttributeError as exc:
            log.exception(exc)
class _make_set(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, var):
        '''
        Force var to be a set
        '''
        if var is None:
            return set()
        if not isinstance(var, list):
            if isinstance(var, six.string_types):
                var = var.split()
            else:
                var = list(var)
        return set(var)
class Absent(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Verify that the variable is not in the ``make.conf``.
    
        name
            The variable name. This will automatically be converted to upper
            case since variables in ``make.conf`` are in upper case
        '''
        ret = {'changes': {},
               'comment': '',
               'name': name,
               'result': True}
    
        # Make name all Uppers since make.conf uses all Upper vars
        upper_name = name.upper()
    
        old_value = __salt__['makeconf.get_var'](upper_name)
    
        if old_value is None:
            msg = 'Variable {0} is already absent from make.conf'
            ret['comment'] = msg.format(name)
        else:
            if __opts__['test']:
                msg = 'Variable {0} is set to be removed from make.conf'
                ret['comment'] = msg.format(name)
                ret['result'] = None
            else:
                __salt__['makeconf.remove_var'](upper_name)
    
                new_value = __salt__['makeconf.get_var'](upper_name)
                if new_value is not None:
                    msg = 'Variable {0} failed to be removed from make.conf'
                    ret['comment'] = msg.format(name)
                    ret['result'] = False
                else:
                    msg = 'Variable {0} was removed from make.conf'
                    ret['comment'] = msg.format(name)
                    ret['result'] = True
        return ret
class Info(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Return information for the specified user
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' shadow.info root
        '''
        if HAS_SPWD:
            try:
                data = spwd.getspnam(name)
                ret = {
                    'name': data.sp_nam,
                    'passwd': data.sp_pwd,
                    'lstchg': data.sp_lstchg,
                    'min': data.sp_min,
                    'max': data.sp_max,
                    'warn': data.sp_warn,
                    'inact': data.sp_inact,
                    'expire': data.sp_expire}
            except KeyError:
                ret = {
                    'name': '',
                    'passwd': '',
                    'lstchg': '',
                    'min': '',
                    'max': '',
                    'warn': '',
                    'inact': '',
                    'expire': ''}
            return ret
    
        # SmartOS joyent_20130322T181205Z does not have spwd, but not all is lost
        # Return what we can know
        ret = {
            'name': '',
            'passwd': '',
            'lstchg': '',
            'min': '',
            'max': '',
            'warn': '',
            'inact': '',
            'expire': ''}
    
        try:
            data = pwd.getpwnam(name)
            ret.update({
                'name': name
            })
        except KeyError:
            return ret
    
        # To compensate for lack of spwd module, read in password hash from /etc/shadow
        s_file = '/etc/shadow'
        if not os.path.isfile(s_file):
            return ret
        with salt.utils.files.fopen(s_file, 'rb') as ifile:
            for line in ifile:
                comps = line.strip().split(':')
                if comps[0] == name:
                    ret.update({'passwd': comps[1]})
    
        # For SmartOS `passwd -s <username>` and the output format is:
        #   name status mm/dd/yy min max warn
        #
        # Fields:
        #  1. Name: username
        #  2. Status:
        #      - LK: locked
        #      - NL: no login
        #      - NP: No password
        #      - PS: Password
        #  3. Last password change
        #  4. Minimum age
        #  5. Maximum age
        #  6. Warning period
    
        output = __salt__['cmd.run_all']('passwd -s {0}'.format(name), python_shell=False)
        if output['retcode'] != 0:
            return ret
    
        fields = output['stdout'].split()
        if len(fields) == 2:
            # For example:
            #   root      NL
            return ret
        # We have all fields:
        #   buildbot L 05/09/2013 0 99999 7
        ret.update({
            'name': data.pw_name,
            'lstchg': fields[2],
            'min': int(fields[3]),
            'max': int(fields[4]),
            'warn': int(fields[5]),
            'inact': '',
            'expire': ''
        })
        return ret
class Del_password(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        .. versionadded:: 2015.8.8
    
        Delete the password from name user
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' shadow.del_password username
        '''
        cmd = 'passwd -d {0}'.format(name)
        __salt__['cmd.run'](cmd, python_shell=False, output_loglevel='quiet')
        uinfo = info(name)
        return not uinfo['passwd']
class Set_remote_login(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, enable):
        '''
        Set the remote login (SSH) to either on or off.
    
        :param bool enable: True to enable, False to disable. "On" and "Off" are
            also acceptable values. Additionally you can pass 1 and 0 to represent
            True and False respectively
    
        :return: True if successful, False if not
        :rtype: bool
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' system.set_remote_login True
        '''
        state = __utils__['mac_utils.validate_enabled'](enable)
    
        cmd = 'systemsetup -f -setremotelogin {0}'.format(state)
        __utils__['mac_utils.execute_return_success'](cmd)
    
        return __utils__['mac_utils.confirm_updated'](state,
                                                      get_remote_login,
                                                      normalize_ret=True)
class Set_remote_events(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, enable):
        '''
        Set whether the server responds to events sent by other computers (such as
        AppleScripts)
    
        :param bool enable: True to enable, False to disable. "On" and "Off" are
            also acceptable values. Additionally you can pass 1 and 0 to represent
            True and False respectively
    
        :return: True if successful, False if not
        :rtype: bool
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' system.set_remote_events On
        '''
        state = __utils__['mac_utils.validate_enabled'](enable)
    
        cmd = 'systemsetup -setremoteappleevents {0}'.format(state)
        __utils__['mac_utils.execute_return_success'](cmd)
    
        return __utils__['mac_utils.confirm_updated'](
            state,
            get_remote_events,
            normalize_ret=True,
        )
class Set_computer_name(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Set the computer name
    
        :param str name: The new computer name
    
        :return: True if successful, False if not
        :rtype: bool
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' system.set_computer_name "Mike's Mac"
        '''
        cmd = 'systemsetup -setcomputername "{0}"'.format(name)
        __utils__['mac_utils.execute_return_success'](cmd)
    
        return __utils__['mac_utils.confirm_updated'](
            name,
            get_computer_name,
        )
class Set_subnet_name(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Set the local subnet name
    
        :param str name: The new local subnet name
    
        .. note::
           Spaces are changed to dashes. Other special characters are removed.
    
        :return: True if successful, False if not
        :rtype: bool
    
        CLI Example:
    
        .. code-block:: bash
    
            The following will be set as 'Mikes-Mac'
            salt '*' system.set_subnet_name "Mike's Mac"
        '''
        cmd = 'systemsetup -setlocalsubnetname "{0}"'.format(name)
        __utils__['mac_utils.execute_return_success'](cmd)
    
        return __utils__['mac_utils.confirm_updated'](
            name,
            get_subnet_name,
        )
class Set_startup_disk(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        Set the current startup disk to the indicated path. Use
        ``system.list_startup_disks`` to find valid startup disks on the system.
    
        :param str path: The valid startup disk path
    
        :return: True if successful, False if not
        :rtype: bool
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' system.set_startup_disk /System/Library/CoreServices
        '''
        if path not in list_startup_disks():
            msg = 'Invalid value passed for path.\n' \
                  'Must be a valid startup disk as found in ' \
                  'system.list_startup_disks.\n' \
                  'Passed: {0}'.format(path)
            raise SaltInvocationError(msg)
    
        cmd = 'systemsetup -setstartupdisk {0}'.format(path)
        __utils__['mac_utils.execute_return_result'](cmd)
    
        return __utils__['mac_utils.confirm_updated'](
            path,
            get_startup_disk,
        )
class Set_restart_delay(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, seconds):
        '''
        Set the number of seconds after which the computer will start up after a
        power failure.
    
        .. warning::
    
            This command fails with the following error:
    
            ``Error, IOServiceOpen returned 0x10000003``
    
            The setting is not updated. This is an apple bug. It seems like it may
            only work on certain versions of Mac Server X. This article explains the
            issue in more detail, though it is quite old.
    
            http://lists.apple.com/archives/macos-x-server/2006/Jul/msg00967.html
    
        :param int seconds: The number of seconds. Must be a multiple of 30
    
        :return: True if successful, False if not
        :rtype: bool
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' system.set_restart_delay 180
        '''
        if seconds % 30 != 0:
            msg = 'Invalid value passed for seconds.\n' \
                  'Must be a multiple of 30.\n' \
                  'Passed: {0}'.format(seconds)
            raise SaltInvocationError(msg)
    
        cmd = 'systemsetup -setwaitforstartupafterpowerfailure {0}'.format(seconds)
        __utils__['mac_utils.execute_return_success'](cmd)
    
        return __utils__['mac_utils.confirm_updated'](
            seconds,
            get_restart_delay,
        )
class Set_disable_keyboard_on_lock(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, enable):
        '''
        Get whether or not the keyboard should be disabled when the X Serve
        enclosure lock is engaged.
    
        :param bool enable: True to enable, False to disable. "On" and "Off" are
            also acceptable values. Additionally you can pass 1 and 0 to represent
            True and False respectively
    
        :return: True if successful, False if not
        :rtype: bool
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' system.set_disable_keyboard_on_lock False
        '''
        state = __utils__['mac_utils.validate_enabled'](enable)
    
        cmd = 'systemsetup -setdisablekeyboardwhenenclosurelockisengaged ' \
              '{0}'.format(state)
        __utils__['mac_utils.execute_return_success'](cmd)
    
        return __utils__['mac_utils.confirm_updated'](
            state,
            get_disable_keyboard_on_lock,
            normalize_ret=True,
        )
class Set_boot_arch(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, arch='default'):
        '''
        Set the kernel to boot in 32 or 64 bit mode on next boot.
    
        .. note::
            When this function fails with the error ``changes to kernel
            architecture failed to save!``, then the boot arch is not updated.
            This is either an Apple bug, not available on the test system, or a
            result of system files being locked down in macOS (SIP Protection).
    
        :param str arch: A string representing the desired architecture. If no
            value is passed, default is assumed. Valid values include:
    
            - i386
            - x86_64
            - default
    
        :return: True if successful, False if not
        :rtype: bool
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' system.set_boot_arch i386
        '''
        if arch not in ['i386', 'x86_64', 'default']:
            msg = 'Invalid value passed for arch.\n' \
                  'Must be i386, x86_64, or default.\n' \
                  'Passed: {0}'.format(arch)
            raise SaltInvocationError(msg)
    
        cmd = 'systemsetup -setkernelbootarchitecture {0}'.format(arch)
        __utils__['mac_utils.execute_return_success'](cmd)
    
        return __utils__['mac_utils.confirm_updated'](
            arch,
            get_boot_arch,
        )
class Base64_b64encode(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, instr):
        '''
        Encode a string as base64 using the "modern" Python interface.
    
        Among other possible differences, the "modern" encoder does not include
        newline ('\\n') characters in the encoded output.
        '''
        return salt.utils.stringutils.to_unicode(
            base64.b64encode(salt.utils.stringutils.to_bytes(instr)),
            encoding='utf8' if salt.utils.platform.is_windows() else None
        )
class Base64_b64decode(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, instr):
        '''
        Decode a base64-encoded string using the "modern" Python interface.
        '''
        decoded = base64.b64decode(salt.utils.stringutils.to_bytes(instr))
        try:
            return salt.utils.stringutils.to_unicode(
                decoded,
                encoding='utf8' if salt.utils.platform.is_windows() else None
            )
        except UnicodeDecodeError:
            return decoded
class Base64_encodestring(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, instr):
        '''
        Encode a string as base64 using the "legacy" Python interface.
    
        Among other possible differences, the "legacy" encoder includes
        a newline ('\\n') character after every 76 characters and always
        at the end of the encoded string.
        '''
        return salt.utils.stringutils.to_unicode(
            base64.encodestring(salt.utils.stringutils.to_bytes(instr)),
            encoding='utf8' if salt.utils.platform.is_windows() else None
        )
class Base64_decodestring(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, instr):
        '''
        Decode a base64-encoded string using the "legacy" Python interface.
        '''
        b = salt.utils.stringutils.to_bytes(instr)
        try:
            # PY3
            decoded = base64.decodebytes(b)
        except AttributeError:
            # PY2
            decoded = base64.decodestring(b)
        try:
            return salt.utils.stringutils.to_unicode(
                decoded,
                encoding='utf8' if salt.utils.platform.is_windows() else None
            )
        except UnicodeDecodeError:
            return decoded
class Md5_digest(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, instr):
        '''
        Generate an md5 hash of a given string.
        '''
        return salt.utils.stringutils.to_unicode(
            hashlib.md5(salt.utils.stringutils.to_bytes(instr)).hexdigest()
        )
class Sha1_digest(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, instr):
        '''
        Generate an sha1 hash of a given string.
        '''
        if six.PY3:
            b = salt.utils.stringutils.to_bytes(instr)
            return hashlib.sha1(b).hexdigest()
        return hashlib.sha1(instr).hexdigest()
class Sha256_digest(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, instr):
        '''
        Generate a sha256 hash of a given string.
        '''
        return salt.utils.stringutils.to_unicode(
            hashlib.sha256(salt.utils.stringutils.to_bytes(instr)).hexdigest()
        )
class Sha512_digest(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, instr):
        '''
        Generate a sha512 hash of a given string
        '''
        return salt.utils.stringutils.to_unicode(
            hashlib.sha512(salt.utils.stringutils.to_bytes(instr)).hexdigest()
        )
class Digest(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Get digest.
    
            :return:
            '''
    
            return salt.utils.stringutils.to_str(self.__digest.hexdigest() + os.linesep)
class _get_ssl_opts(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Parse out ssl_options for Cassandra cluster connection.
        Make sure that the ssl_version (if any specified) is valid.
        '''
        sslopts = __salt__['config.option']('cassandra').get('ssl_options', None)
        ssl_opts = {}
    
        if sslopts:
            ssl_opts['ca_certs'] = sslopts['ca_certs']
            if SSL_VERSION in sslopts:
                if not sslopts[SSL_VERSION].startswith('PROTOCOL_'):
                    valid_opts = ', '.join(
                        [x for x in dir(ssl) if x.startswith('PROTOCOL_')]
                    )
                    raise CommandExecutionError('Invalid protocol_version '
                                                'specified! '
                                                'Please make sure '
                                                'that the ssl protocol'
                                                'version is one from the SSL'
                                                'module. '
                                                'Valid options are '
                                                '{0}'.format(valid_opts))
                else:
                    ssl_opts[SSL_VERSION] = \
                        getattr(ssl, sslopts[SSL_VERSION])
            return ssl_opts
        else:
            return None
class _get_journal(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the active running journal object
        '''
        if 'systemd.journald' in __context__:
            return __context__['systemd.journald']
        __context__['systemd.journald'] = systemd.journal.Reader()
        # get to the end of the journal
        __context__['systemd.journald'].seek_tail()
        __context__['systemd.journald'].get_previous()
        return __context__['systemd.journald']
class Beacon(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, config):
        '''
        The journald beacon allows for the systemd journal to be parsed and linked
        objects to be turned into events.
    
        This beacons config will return all sshd jornal entries
    
        .. code-block:: yaml
    
            beacons:
              journald:
                - services:
                    sshd:
                      SYSLOG_IDENTIFIER: sshd
                      PRIORITY: 6
        '''
        ret = []
        journal = _get_journal()
    
        _config = {}
        list(map(_config.update, config))
    
        while True:
            cur = journal.get_next()
            if not cur:
                break
    
            for name in _config.get('services', {}):
                n_flag = 0
                for key in _config['services'][name]:
                    if isinstance(key, salt.ext.six.string_types):
                        key = salt.utils.data.decode(key)
                    if key in cur:
                        if _config['services'][name][key] == cur[key]:
                            n_flag += 1
                if n_flag == len(_config['services'][name]):
                    # Match!
                    sub = salt.utils.data.simple_types_filter(cur)
                    sub.update({'tag': name})
                    ret.append(sub)
        return ret
class _get_options(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, ret=None):
        '''
        Get the couchdb options from salt.
        '''
        attrs = {'url': 'url',
                 'db': 'db',
                 'user': 'user',
                 'passwd': 'passwd',
                 'redact_pws': 'redact_pws',
                 'minimum_return': 'minimum_return'}
    
        _options = salt.returners.get_returner_options(__virtualname__,
                                                       ret,
                                                       attrs,
                                                       __salt__=__salt__,
                                                       __opts__=__opts__)
        if 'url' not in _options:
            log.debug("Using default url.")
            _options['url'] = "http://salt:5984/"
    
        if 'db' not in _options:
            log.debug("Using default database.")
            _options['db'] = "salt"
    
        if 'user' not in _options:
            log.debug("Not athenticating with a user.")
            _options['user'] = None
    
        if 'passwd' not in _options:
            log.debug("Not athenticating with a password.")
            _options['passwd'] = None
    
        if 'redact_pws' not in _options:
            log.debug("Not redacting passwords.")
            _options['redact_pws'] = None
    
        if 'minimum_return' not in _options:
            log.debug("Not minimizing the return object.")
            _options['minimum_return'] = None
    
        return _options
class _generate_doc(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, ret):
        '''
        Create a object that will be saved into the database based on
        options.
        '''
    
        # Create a copy of the object that we will return.
        retc = ret.copy()
    
        # Set the ID of the document to be the JID.
        retc["_id"] = ret["jid"]
    
        # Add a timestamp field to the document
        retc["timestamp"] = time.time()
    
        return retc
class _generate_event_doc(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, event):
        '''
        Create a object that will be saved into the database based in
        options.
        '''
    
        # Create a copy of the object that we will return.
        eventc = event.copy()
    
        # Set the ID of the document to be the JID.
        eventc["_id"] = '{}-{}'.format(
                                        event.get('tag', '').split('/')[2],
                                        event.get('tag', '').split('/')[3]
                                      )
    
        # Add a timestamp field to the document
        eventc["timestamp"] = time.time()
    
        # remove any return data as it's captured in the "returner" function
        if eventc.get('data').get('return'):
            del eventc['data']['return']
    
        return eventc
class Returner(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, ret):
        '''
        Take in the return and shove it into the couchdb database.
        '''
    
        options = _get_options(ret)
    
        # Check to see if the database exists.
        _response = _request("GET",
                             options['url'] + "_all_dbs",
                             user=options['user'],
                             passwd=options['passwd'])
        if options['db'] not in _response:
    
            # Make a PUT request to create the database.
            _response = _request("PUT",
                                 options['url'] + options['db'],
                                 user=options['user'],
                                 passwd=options['passwd'])
    
            # Confirm that the response back was simple 'ok': true.
            if 'ok' not in _response or _response['ok'] is not True:
                log.error('Nothing logged! Lost data. Unable to create database "%s"', options['db'])
                log.debug('_response object is: %s', _response)
                return
            log.info('Created database "%s"', options['db'])
    
        if boltons_lib:
            # redact all passwords if options['redact_pws'] is True
            if options['redact_pws']:
                ret_remap_pws = remap(ret, visit=_redact_passwords)
            else:
                ret_remap_pws = ret
    
            # remove all return values starting with '__pub' if options['minimum_return'] is True
            if options['minimum_return']:
                ret_remapped = remap(ret_remap_pws, visit=_minimize_return)
            else:
                ret_remapped = ret_remap_pws
        else:
            log.info('boltons library not installed. pip install boltons. https://github.com/mahmoud/boltons.')
            ret_remapped = ret
    
        # Call _generate_doc to get a dict object of the document we're going to shove into the database.
        doc = _generate_doc(ret_remapped)
    
        # Make the actual HTTP PUT request to create the doc.
        _response = _request("PUT",
                             options['url'] + options['db'] + "/" + doc['_id'],
                             'application/json',
                             salt.utils.json.dumps(doc))
    
        # Sanity check regarding the response..
        if 'ok' not in _response or _response['ok'] is not True:
            log.error('Nothing logged! Lost data. Unable to create document: "%s"', _response)
class Event_return(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, events):
        '''
        Return event to CouchDB server
        Requires that configuration be enabled via 'event_return'
        option in master config.
    
        Example:
    
        event_return:
          - couchdb
    
        '''
        log.debug('events data is: %s', events)
    
        options = _get_options()
    
        # Check to see if the database exists.
        _response = _request("GET", options['url'] + "_all_dbs")
        event_db = '{}-events'.format(options['db'])
        if event_db not in _response:
    
            # Make a PUT request to create the database.
            log.info('Creating database "%s"', event_db)
            _response = _request("PUT",
                                 options['url'] + event_db,
                                 user=options['user'],
                                 passwd=options['passwd'])
    
            # Confirm that the response back was simple 'ok': true.
            if 'ok' not in _response or _response['ok'] is not True:
                log.error('Nothing logged! Lost data. Unable to create database "%s"', event_db)
                return
            log.info('Created database "%s"', event_db)
    
        for event in events:
            # Call _generate_doc to get a dict object of the document we're going to shove into the database.
            log.debug('event data is: %s', event)
            doc = _generate_event_doc(event)
    
            # Make the actual HTTP PUT request to create the doc.
            _response = _request("PUT",
                                 options['url'] + event_db + "/" + doc['_id'],
                                 'application/json',
                                 salt.utils.json.dumps(doc))
            # Sanity check regarding the response..
            if 'ok' not in _response or _response['ok'] is not True:
                log.error('Nothing logged! Lost data. Unable to create document: "%s"', _response)
class Get_jids(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        List all the jobs that we have..
        '''
        options = _get_options(ret=None)
        _response = _request("GET", options['url'] + options['db'] + "/_all_docs?include_docs=true")
    
        # Make sure the 'total_rows' is returned.. if not error out.
        if 'total_rows' not in _response:
            log.error('Didn\'t get valid response from requesting all docs: %s', _response)
            return {}
    
        # Return the rows.
        ret = {}
        for row in _response['rows']:
            # Because this shows all the documents in the database, including the
            # design documents, verify the id is salt jid
            jid = row['id']
            if not salt.utils.jid.is_jid(jid):
                continue
    
            ret[jid] = salt.utils.jid.format_jid_instance(jid, row['doc'])
    
        return ret
class Get_fun(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, fun):
        '''
        Return a dict with key being minion and value
        being the job details of the last run of function 'fun'.
        '''
    
        # Get the options..
        options = _get_options(ret=None)
    
        # Define a simple return object.
        _ret = {}
    
        # get_minions takes care of calling ensure_views for us. For each minion we know about
        for minion in get_minions():
    
            # Make a query of the by-minion-and-timestamp view and limit the count to 1.
            _response = _request("GET",
                                 options['url'] +
                                         options['db'] +
                                         ('/_design/salt/_view/by-minion-fun-times'
                                          'tamp?descending=true&endkey=["{0}","{1}'
                                          '",0]&startkey=["{2}","{3}",9999999999]&'
                                          'limit=1').format(minion,
                                                            fun,
                                                            minion,
                                                            fun))
            # Skip the minion if we got an error..
            if 'error' in _response:
                log.warning('Got an error when querying for last command '
                            'by a minion: %s', _response['error'])
                continue
    
            # Skip the minion if we didn't get any rows back. ( IE function that
            # they're looking for has a typo in it or some such ).
            if not _response['rows']:
                continue
    
            # Set the respnse ..
            _ret[minion] = _response['rows'][0]['value']
    
        return _ret
class Get_minions(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return a list of minion identifiers from a request of the view.
        '''
        options = _get_options(ret=None)
    
        # Make sure the views are valid, which includes the minions..
        if not ensure_views():
            return []
    
        # Make the request for the view..
        _response = _request("GET",
                             options['url'] +
                                     options['db'] +
                                     "/_design/salt/_view/minions?group=true")
    
        # Verify that we got a response back.
        if 'rows' not in _response:
            log.error('Unable to get available minions: %s', _response)
            return []
    
        # Iterate over the rows to build up a list return it.
        _ret = []
        for row in _response['rows']:
            _ret.append(row['key'])
        return _ret
class Ensure_views(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        This function makes sure that all the views that should
        exist in the design document do exist.
        '''
    
        # Get the options so we have the URL and DB..
        options = _get_options(ret=None)
    
        # Make a request to check if the design document exists.
        _response = _request("GET",
                             options['url'] + options['db'] + "/_design/salt")
    
        # If the document doesn't exist, or for some reason there are not views.
        if 'error' in _response:
            return set_salt_view()
    
        # Determine if any views are missing from the design doc stored on the
        # server..  If we come across one, simply set the salt view and return out.
        # set_salt_view will set all the views, so we don't need to continue t
        # check.
        for view in get_valid_salt_views():
            if view not in _response['views']:
                return set_salt_view()
    
        # Valid views, return true.
        return True
class Set_salt_view(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Helper function that sets the salt design
        document. Uses get_valid_salt_views and some hardcoded values.
        '''
    
        options = _get_options(ret=None)
    
        # Create the new object that we will shove in as the design doc.
        new_doc = {}
        new_doc['views'] = get_valid_salt_views()
        new_doc['language'] = "javascript"
    
        # Make the request to update the design doc.
        _response = _request("PUT",
                             options['url'] + options['db'] + "/_design/salt",
                             "application/json", salt.utils.json.dumps(new_doc))
        if 'error' in _response:
            log.warning('Unable to set the salt design document: %s', _response['error'])
            return False
        return True
class Get_load(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, jid):
        '''
        Included for API consistency
        '''
        options = _get_options(ret=None)
        _response = _request("GET", options['url'] + options['db'] + '/' + jid)
        if 'error' in _response:
            log.error('Unable to get JID "%s" : "%s"', jid, _response)
            return {}
        return {_response['id']: _response}
class _parse_environment(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, env_str):
        '''
        Parsing template
        '''
        try:
            env = salt.utils.yaml.safe_load(env_str)
        except salt.utils.yaml.YAMLError as exc:
            raise ValueError(six.text_type(exc))
        else:
            if env is None:
                env = {}
            elif not isinstance(env, dict):
                raise ValueError(
                    'The environment is not a valid YAML mapping data type.'
                )
    
        for param in env:
            if param not in SECTIONS:
                raise ValueError('environment has wrong section "{0}"'.format(param))
    
        return env
class List_stack(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, profile=None):
        '''
        Return a list of available stack (heat stack-list)
    
        profile
            Profile to use
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' heat.list_stack profile=openstack1
        '''
        ret = {}
        h_client = _auth(profile)
        for stack in h_client.stacks.list():
            links = {}
            for link in stack.links:
                links[link['rel']] = link['href']
            ret[stack.stack_name] = {
                'status': stack.stack_status,
                'id': stack.id,
                'name': stack.stack_name,
                'creation': stack.creation_time,
                'owner': stack.stack_owner,
                'reason': stack.stack_status_reason,
                'links': links,
            }
        return ret
class _default_logfile(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, exe_name):
        '''
        Retrieve the logfile name
        '''
        if salt.utils.platform.is_windows():
            tmp_dir = os.path.join(__opts__['cachedir'], 'tmp')
            if not os.path.isdir(tmp_dir):
                os.mkdir(tmp_dir)
            logfile_tmp = tempfile.NamedTemporaryFile(dir=tmp_dir,
                                                      prefix=exe_name,
                                                      suffix='.log',
                                                      delete=False)
            logfile = logfile_tmp.name
            logfile_tmp.close()
        else:
            logfile = salt.utils.path.join(
                '/var/log',
                '{0}.log'.format(exe_name)
            )
    
        return logfile
class _decode_embedded_list(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, src):
        '''
        Convert enbedded bytes to strings if possible.
        List helper.
        '''
        output = []
        for elem in src:
            if isinstance(elem, dict):
                elem = _decode_embedded_dict(elem)
            elif isinstance(elem, list):
                elem = _decode_embedded_list(elem)  # pylint: disable=redefined-variable-type
            elif isinstance(elem, bytes):
                try:
                    elem = elem.decode()
                except UnicodeError:
                    pass
            output.append(elem)
        return output
class _decode_embedded_dict(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, src):
        '''
        Convert enbedded bytes to strings if possible.
        Dict helper.
        '''
        output = {}
        for key, val in six.iteritems(src):
            if isinstance(val, dict):
                val = _decode_embedded_dict(val)
            elif isinstance(val, list):
                val = _decode_embedded_list(val)  # pylint: disable=redefined-variable-type
            elif isinstance(val, bytes):
                try:
                    val = val.decode()
                except UnicodeError:
                    pass
            if isinstance(key, bytes):
                try:
                    key = key.decode()
                except UnicodeError:
                    pass
            output[key] = val
        return output
class Decode_embedded_strs(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, src):
        '''
        Convert enbedded bytes to strings if possible.
        This is necessary because Python 3 makes a distinction
        between these types.
    
        This wouldn't be needed if we used "use_bin_type=True" when encoding
        and "encoding='utf-8'" when decoding. Unfortunately, this would break
        backwards compatibility due to a change in wire protocol, so this less
        than ideal solution is used instead.
        '''
        if not six.PY3:
            return src
    
        if isinstance(src, dict):
            return _decode_embedded_dict(src)
        elif isinstance(src, list):
            return _decode_embedded_list(src)
        elif isinstance(src, bytes):
            try:
                return src.decode()  # pylint: disable=redefined-variable-type
            except UnicodeError:
                return src
        else:
            return src
class Workers(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, profile='default'):
        '''
        Return a list of member workers and their status
    
        CLI Examples:
    
        .. code-block:: bash
    
            salt '*' modjk.workers
            salt '*' modjk.workers other-profile
        '''
    
        config = get_running(profile)
        lbn = config['worker.list'].split(',')
        worker_list = []
        ret = {}
    
        for lb in lbn:
            try:
                worker_list.extend(
                    config['worker.{0}.balance_workers'.format(lb)].split(',')
                )
            except KeyError:
                pass
    
        worker_list = list(set(worker_list))
    
        for worker in worker_list:
            ret[worker] = {
                'activation': config['worker.{0}.activation'.format(worker)],
                'state': config['worker.{0}.state'.format(worker)],
            }
    
        return ret
class Build_info(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return server and build arguments
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' nginx.build_info
        '''
        ret = {'info': []}
        out = __salt__['cmd.run']('{0} -V'.format(__detect_os()))
    
        for i in out.splitlines():
            if i.startswith('configure argument'):
                ret['build arguments'] = re.findall(r"(?:[^\s]*'.*')|(?:[^\s]+)", i)[2:]
                continue
    
            ret['info'].append(i)
    
        return ret
class Signal(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, signal=None):
        '''
        Signals nginx to start, reload, reopen or stop.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' nginx.signal reload
        '''
        valid_signals = ('start', 'reopen', 'stop', 'quit', 'reload')
    
        if signal not in valid_signals:
            return
    
        # Make sure you use the right arguments
        if signal == "start":
            arguments = ''
        else:
            arguments = ' -s {0}'.format(signal)
        cmd = __detect_os() + arguments
        out = __salt__['cmd.run_all'](cmd)
    
        # A non-zero return code means fail
        if out['retcode'] and out['stderr']:
            ret = out['stderr'].strip()
        # 'nginxctl configtest' returns 'Syntax OK' to stderr
        elif out['stderr']:
            ret = out['stderr'].strip()
        elif out['stdout']:
            ret = out['stdout'].strip()
        # No output for something like: nginxctl graceful
        else:
            ret = 'Command: "{0}" completed successfully!'.format(cmd)
        return ret
class Status(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, url="http://127.0.0.1/status"):
        """
        Return the data from an Nginx status page as a dictionary.
        http://wiki.nginx.org/HttpStubStatusModule
    
        url
            The URL of the status page. Defaults to 'http://127.0.0.1/status'
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' nginx.status
        """
        resp = _urlopen(url)
        status_data = resp.read()
        resp.close()
    
        lines = status_data.splitlines()
        if not len(lines) == 4:
            return
        # "Active connections: 1 "
        active_connections = lines[0].split()[2]
        # "server accepts handled requests"
        # "  12 12 9 "
        accepted, handled, requests = lines[2].split()
        # "Reading: 0 Writing: 1 Waiting: 0 "
        _, reading, _, writing, _, waiting = lines[3].split()
        return {
            'active connections': int(active_connections),
            'accepted': int(accepted),
            'handled': int(handled),
            'requests': int(requests),
            'reading': int(reading),
            'writing': int(writing),
            'waiting': int(waiting),
        }
class Init(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, opts):
        '''
        This function gets called when the proxy starts up. For
        ESXi devices, the host, login credentials, and, if configured,
        the protocol and port are cached.
        '''
        log.debug('Initting esxi proxy module in process %s', os.getpid())
        log.debug('Validating esxi proxy input')
        schema = EsxiProxySchema.serialize()
        log.trace('esxi_proxy_schema = %s', schema)
        proxy_conf = merge(opts.get('proxy', {}), __pillar__.get('proxy', {}))
        log.trace('proxy_conf = %s', proxy_conf)
        try:
            jsonschema.validate(proxy_conf, schema)
        except jsonschema.exceptions.ValidationError as exc:
            raise InvalidConfigError(exc)
    
        DETAILS['proxytype'] = proxy_conf['proxytype']
        if ('host' not in proxy_conf) and ('vcenter' not in proxy_conf):
            log.critical('Neither \'host\' nor \'vcenter\' keys found in pillar '
                         'for this proxy.')
            return False
        if 'host' in proxy_conf:
            # We have started the proxy by connecting directly to the host
            if 'username' not in proxy_conf:
                log.critical('No \'username\' key found in pillar for this proxy.')
                return False
            if 'passwords' not in proxy_conf:
                log.critical('No \'passwords\' key found in pillar for this proxy.')
                return False
            host = proxy_conf['host']
    
            # Get the correct login details
            try:
                username, password = find_credentials(host)
            except SaltSystemExit as err:
                log.critical('Error: %s', err)
                return False
    
            # Set configuration details
            DETAILS['host'] = host
            DETAILS['username'] = username
            DETAILS['password'] = password
            DETAILS['protocol'] = proxy_conf.get('protocol')
            DETAILS['port'] = proxy_conf.get('port')
            return True
    
        if 'vcenter' in proxy_conf:
            vcenter = proxy_conf['vcenter']
            if not proxy_conf.get('esxi_host'):
                log.critical('No \'esxi_host\' key found in pillar for this proxy.')
            DETAILS['esxi_host'] = proxy_conf['esxi_host']
            # We have started the proxy by connecting via the vCenter
            if 'mechanism' not in proxy_conf:
                log.critical('No \'mechanism\' key found in pillar for this proxy.')
                return False
            mechanism = proxy_conf['mechanism']
            # Save mandatory fields in cache
            for key in ('vcenter', 'mechanism'):
                DETAILS[key] = proxy_conf[key]
    
            if mechanism == 'userpass':
                if 'username' not in proxy_conf:
                    log.critical('No \'username\' key found in pillar for this '
                                 'proxy.')
                    return False
                if 'passwords' not in proxy_conf and proxy_conf['passwords']:
                    log.critical('Mechanism is set to \'userpass\' , but no '
                                 '\'passwords\' key found in pillar for this '
                                 'proxy.')
                    return False
                for key in ('username', 'passwords'):
                    DETAILS[key] = proxy_conf[key]
            elif mechanism == 'sspi':
                if 'domain' not in proxy_conf:
                    log.critical('Mechanism is set to \'sspi\' , but no '
                                 '\'domain\' key found in pillar for this proxy.')
                    return False
                if 'principal' not in proxy_conf:
                    log.critical('Mechanism is set to \'sspi\' , but no '
                                 '\'principal\' key found in pillar for this '
                                 'proxy.')
                    return False
                for key in ('domain', 'principal'):
                    DETAILS[key] = proxy_conf[key]
    
            if mechanism == 'userpass':
                # Get the correct login details
                log.debug('Retrieving credentials and testing vCenter connection'
                          ' for mehchanism \'userpass\'')
                try:
                    username, password = find_credentials(DETAILS['vcenter'])
                    DETAILS['password'] = password
                except SaltSystemExit as err:
                    log.critical('Error: %s', err)
                    return False
    
        # Save optional
        DETAILS['protocol'] = proxy_conf.get('protocol', 'https')
        DETAILS['port'] = proxy_conf.get('port', '443')
        DETAILS['credstore'] = proxy_conf.get('credstore')
class Ping(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Returns True if connection is to be done via a vCenter (no connection is attempted).
        Check to see if the host is responding when connecting directly via an ESXi
        host.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt esxi-host test.ping
        '''
        if DETAILS.get('esxi_host'):
            return True
        else:
            # TODO Check connection if mechanism is SSPI
            if DETAILS['mechanism'] == 'userpass':
                find_credentials(DETAILS['host'])
                try:
                    __salt__['vsphere.system_info'](host=DETAILS['host'],
                                                    username=DETAILS['username'],
                                                    password=DETAILS['password'])
                except SaltSystemExit as err:
                    log.warning(err)
                    return False
        return True
class _redis_client(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, opts):
        '''
        Connect to the redis host and return a StrictRedisCluster client object.
        If connection fails then return None.
        '''
        redis_host = opts.get("eauth_redis_host", "localhost")
        redis_port = opts.get("eauth_redis_port", 6379)
        try:
            return rediscluster.StrictRedisCluster(host=redis_host, port=redis_port, decode_responses=True)
        except rediscluster.exceptions.RedisClusterException as err:
            log.warning(
                'Failed to connect to redis at %s:%s - %s',
                redis_host, redis_port, err
            )
            return None
class List_tokens(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, opts):
        '''
        List all tokens in the store.
    
        :param opts: Salt master config options
        :returns: List of dicts (token_data)
        '''
        ret = []
        redis_client = _redis_client(opts)
        if not redis_client:
            return []
        serial = salt.payload.Serial(opts)
        try:
            return [k.decode('utf8') for k in redis_client.keys()]
        except Exception as err:
            log.warning('Failed to list keys: %s', err)
            return []
class _prepare_connection(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, **kwargs):
        '''
        Prepare the underlying SSH connection with the remote target.
        '''
        paramiko_kwargs, scp_kwargs = _select_kwargs(**kwargs)
        ssh = paramiko.SSHClient()
        if paramiko_kwargs.pop('auto_add_policy', False):
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(**paramiko_kwargs)
        scp_client = scp.SCPClient(ssh.get_transport(),
                                   **scp_kwargs)
        return scp_client
class _load_response(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, response):
        '''
        Load the response from json data, return the dictionary or raw text
        '''
    
        try:
            data = salt.utils.json.loads(response.text)
        except ValueError:
            data = response.text
    
        ret = {'code': response.status_code, 'content': data}
    
        return ret
class _loop_payload(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, params):
        '''
        Pass in a dictionary of parameters, loop through them and build a payload containing,
        parameters who's values are not None.
        '''
    
        #construct the payload
        payload = {}
    
        #set the payload
        for param, value in six.iteritems(params):
            if value is not None:
                payload[param] = value
    
        return payload
class _set_value(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, value):
        '''
        A function to detect if user is trying to pass a dictionary or list.  parse it and return a
        dictionary list or a string
        '''
        #don't continue if already an acceptable data-type
        if isinstance(value, bool) or isinstance(value, dict) or isinstance(value, list):
            return value
    
        #check if json
        if value.startswith('j{') and value.endswith('}j'):
    
            value = value.replace('j{', '{')
            value = value.replace('}j', '}')
    
            try:
                return salt.utils.json.loads(value)
            except Exception:
                raise salt.exceptions.CommandExecutionError
    
        #detect list of dictionaries
        if '|' in value and r'\|' not in value:
            values = value.split('|')
            items = []
            for value in values:
                items.append(_set_value(value))
            return items
    
        #parse out dictionary if detected
        if ':' in value and r'\:' not in value:
            options = {}
            #split out pairs
            key_pairs = value.split(',')
            for key_pair in key_pairs:
                k = key_pair.split(':')[0]
                v = key_pair.split(':')[1]
                options[k] = v
            return options
    
        #try making a list
        elif ',' in value and r'\,' not in value:
            value_items = value.split(',')
            return value_items
    
        #just return a string
        else:
    
            #remove escape chars if added
            if r'\|' in value:
                value = value.replace(r'\|', '|')
    
            if r'\:' in value:
                value = value.replace(r'\:', ':')
    
            if r'\,' in value:
                value = value.replace(r'\,', ',')
    
            return value
class Save(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, **kwargs):
        '''
        Save all configured beacons to the minion config.
    
        Returns:
            dict: Boolean and status message on success or failure of save.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' beacons.save
        '''
    
        ret = {'comment': [],
               'result': True}
    
        beacons = list_(return_yaml=False, include_pillar=False, **kwargs)
    
        # move this file into an configurable opt
        sfn = os.path.join(os.path.dirname(__opts__['conf_file']),
                           os.path.dirname(__opts__['default_include']),
                           'beacons.conf')
        if beacons:
            tmp = {'beacons': beacons}
            yaml_out = salt.utils.yaml.safe_dump(tmp, default_flow_style=False)
        else:
            yaml_out = ''
    
        try:
            with salt.utils.files.fopen(sfn, 'w+') as fp_:
                fp_.write(yaml_out)
            ret['comment'] = 'Beacons saved to {0}.'.format(sfn)
        except (IOError, OSError):
            ret['comment'] = 'Unable to write to beacons file at {0}. Check ' \
                             'permissions.'.format(sfn)
            ret['result'] = False
        return ret
class __parse_drac(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, output):
        '''
        Parse Dell DRAC output
        '''
        drac = {}
        section = ''
    
        for i in output.splitlines():
            if i.strip().endswith(':') and '=' not in i:
                section = i[0:-1]
                drac[section] = {}
            if i.rstrip() and '=' in i:
                if section in drac:
                    drac[section].update(dict(
                        [[prop.strip() for prop in i.split('=')]]
                    ))
                else:
                    section = i.strip()
                    if section not in drac and section:
                        drac[section] = {}
    
        return drac
class Finger_master(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, hash_type=None):
        '''
        Return the fingerprint of the master's public key
    
        hash_type
            The hash algorithm used to calculate the fingerprint
    
        .. code-block:: python
    
            >>> wheel.cmd('key.finger_master')
            {'local': {'master.pub': '5d:f6:79:43:5e:d4:42:3f:57:b8:45:a8:7e:a4:6e:ca'}}
        '''
        keyname = 'master.pub'
        if hash_type is None:
            hash_type = __opts__['hash_type']
    
        fingerprint = salt.utils.crypt.pem_finger(
            os.path.join(__opts__['pki_dir'], keyname), sum_type=hash_type)
        return {'local': {keyname: fingerprint}}
class Fileinfo(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        Return information on a file located on the Moose
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' moosefs.fileinfo /path/to/dir/
        '''
        cmd = 'mfsfileinfo ' + path
        ret = {}
        chunknum = ''
        out = __salt__['cmd.run_all'](cmd, python_shell=False)
    
        output = out['stdout'].splitlines()
        for line in output:
            if not line:
                continue
            if '/' in line:
                comps = line.split('/')
    
                chunknum = comps[0].strip().split(':')
                meta = comps[1].strip().split(' ')
    
                chunk = chunknum[0].replace('chunk ', '')
                loc = chunknum[1].strip()
                id_ = meta[0].replace('(id:', '')
                ver = meta[1].replace(')', '').replace('ver:', '')
    
                ret[chunknum[0]] = {
                    'chunk': chunk,
                    'loc': loc,
                    'id': id_,
                    'ver': ver,
                }
            if 'copy' in line:
                copyinfo = line.strip().split(':')
                ret[chunknum[0]][copyinfo[0]] = {
                    'copy': copyinfo[0].replace('copy ', ''),
                    'ip': copyinfo[1].strip(),
                    'port': copyinfo[2],
                }
        return ret
class Mounts(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return a list of current MooseFS mounts
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' moosefs.mounts
        '''
        cmd = 'mount'
        ret = {}
        out = __salt__['cmd.run_all'](cmd)
    
        output = out['stdout'].splitlines()
        for line in output:
            if not line:
                continue
            if 'fuse.mfs' in line:
                comps = line.split(' ')
                info1 = comps[0].split(':')
                info2 = info1[1].split('/')
                ret[comps[2]] = {
                    'remote': {
                        'master': info1[0],
                        'port': info2[0],
                        'subfolder': '/' + info2[1],
                    },
                    'local': comps[2],
                    'options': (comps[5].replace('(', '').replace(')', '')
                                .split(',')),
                }
        return ret
class _auditpol_cmd(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, cmd):
        '''
        Helper function for running the auditpol command
    
        Args:
            cmd (str): the auditpol command to run
    
        Returns:
            list: A list containing each line of the return (splitlines)
    
        Raises:
            CommandExecutionError: If the command encounters an error
        '''
        ret = salt.modules.cmdmod.run_all(cmd='auditpol {0}'.format(cmd),
                                          python_shell=True)
        if ret['retcode'] == 0:
            return ret['stdout'].splitlines()
    
        msg = 'Error executing auditpol command: {0}\n'.format(cmd)
        msg += '\n'.join(ret['stdout'])
        raise CommandExecutionError(msg)
class Get_settings(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, category='All'):
        '''
        Get the current configuration for all audit settings specified in the
        category
    
        Args:
            category (str):
                One of the nine categories to return. Can also be ``All`` to return
                the settings for all categories. Valid options are:
    
                - Account Logon
                - Account Management
                - Detailed Tracking
                - DS Access
                - Logon/Logoff
                - Object Access
                - Policy Change
                - Privilege Use
                - System
                - All
    
                Default value is ``All``
    
        Returns:
            dict: A dictionary containing all subcategories for the specified
                category along with their current configuration
    
        Raises:
            KeyError: On invalid category
            CommandExecutionError: If an error is encountered retrieving the settings
    
        Usage:
    
        .. code-block:: python
    
            import salt.utils.win_lgpo_auditpol
    
            # Get current state of all audit settings
            salt.utils.win_lgpo_auditpol.get_settings()
    
            # Get the current state of all audit settings in the "Account Logon"
            # category
            salt.utils.win_lgpo_auditpol.get_settings(category="Account Logon")
        '''
        # Parameter validation
        if category.lower() in ['all', '*']:
            category = '*'
        elif category.lower() not in [x.lower() for x in categories]:
            raise KeyError('Invalid category: "{0}"'.format(category))
    
        cmd = '/get /category:"{0}"'.format(category)
        results = _auditpol_cmd(cmd)
    
        ret = {}
        # Skip the first 2 lines
        for line in results[3:]:
            if '  ' in line.strip():
                ret.update(dict(list(zip(*[iter(re.split(r"\s{2,}", line.strip()))]*2))))
        return ret
class Get_setting(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Get the current configuration for the named audit setting
    
        Args:
            name (str): The name of the setting to retrieve
    
        Returns:
            str: The current configuration for the named setting
    
        Raises:
            KeyError: On invalid setting name
            CommandExecutionError: If an error is encountered retrieving the settings
    
        Usage:
    
        .. code-block:: python
    
            import salt.utils.win_lgpo_auditpol
    
            # Get current state of the "Credential Validation" setting
            salt.utils.win_lgpo_auditpol.get_setting(name='Credential Validation')
        '''
        current_settings = get_settings(category='All')
        for setting in current_settings:
            if name.lower() == setting.lower():
                return current_settings[setting]
        raise KeyError('Invalid name: {0}'.format(name))
class Get_auditpol_dump(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Gets the contents of an auditpol /backup. Used by the LGPO module to get
        fieldnames and GUIDs for Advanced Audit policies.
    
        Returns:
            list: A list of lines form the backup file
    
        Usage:
    
        .. code-block:: python
    
            import salt.utils.win_lgpo_auditpol
    
            dump = salt.utils.win_lgpo_auditpol.get_auditpol_dump()
        '''
        # Just get a temporary file name
        # NamedTemporaryFile will delete the file it creates by default on Windows
        with tempfile.NamedTemporaryFile(suffix='.csv') as tmp_file:
            csv_file = tmp_file.name
    
        cmd = '/backup /file:{0}'.format(csv_file)
        _auditpol_cmd(cmd)
    
        with salt.utils.files.fopen(csv_file) as fp:
            return fp.readlines()
class Get_saved_rules(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, conf_file=None):
        '''
        Return a data structure of the rules in the conf file
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' nftables.get_saved_rules
    
        '''
        if _conf() and not conf_file:
            conf_file = _conf()
    
        with salt.utils.files.fopen(conf_file) as fp_:
            lines = salt.utils.data.decode(fp_.readlines())
        rules = []
        for line in lines:
            tmpline = line.strip()
            if not tmpline:
                continue
            if tmpline.startswith('#'):
                continue
            rules.append(line)
        return rules
class Get_rules(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, family='ipv4'):
        '''
        Return a data structure of the current, in-memory rules
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' nftables.get_rules
    
            salt '*' nftables.get_rules family=ipv6
    
        '''
        nft_family = _NFTABLES_FAMILIES[family]
        rules = []
        cmd = '{0} --numeric --numeric --numeric ' \
              'list tables {1}'. format(_nftables_cmd(),
                                        nft_family)
        out = __salt__['cmd.run'](cmd, python_shell=False)
        if not out:
            return rules
    
        tables = re.split('\n+', out)
        for table in tables:
            table_name = table.split(' ')[1]
            cmd = '{0} --numeric --numeric --numeric ' \
                  'list table {1} {2}'.format(_nftables_cmd(),
                                              nft_family, table_name)
            out = __salt__['cmd.run'](cmd, python_shell=False)
            rules.append(out)
        return rules
class Rewrite_single_shorthand_state_decl(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, data):
      # pylint: disable=C0103
        '''
        Rewrite all state declarations that look like this::
    
          state_id_decl:
            state.func
    
        into::
    
          state_id_decl:
            state.func: []
        '''
        for sid, states in six.iteritems(data):
            if isinstance(states, six.string_types):
                data[sid] = {states: []}
class _validate_api_params(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, params):
        '''
        Validate the API params as specified in the config file.
        '''
        # page_id and API key are mandatory and they must be string/unicode
        return (isinstance(params['api_page_id'], (six.string_types, six.text_type)) and
                isinstance(params['api_key'], (six.string_types, six.text_type)))
class File_dict(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *packages,**kwargs):
        '''
        List the files that belong to a package, grouped by package. Not
        specifying any packages will return a list of _every_ file on the
        system's package database (not generally recommended).
    
        CLI Examples:
    
        .. code-block:: bash
    
            salt '*' pkg.file_list httpd
            salt '*' pkg.file_list httpd postfix
            salt '*' pkg.file_list
        '''
        errors = []
        files = {}
    
        if packages:
            match_pattern = '\'{0}-[0-9]*\''
            cmd = ['pkg_info', '-QL'] + [match_pattern.format(p) for p in packages]
        else:
            cmd = ['pkg_info', '-QLa']
    
        ret = __salt__['cmd.run_all'](cmd,
                                      output_loglevel='trace',
                                      python_shell=False)
    
        for line in ret['stderr'].splitlines():
            errors.append(line)
    
        pkg = None
        for line in ret['stdout'].splitlines():
            if pkg is not None and line.startswith('/'):
                files[pkg].append(line)
            elif ':/' in line:
                pkg, fn = line.split(':', 1)
                pkg, ver = pkg.rsplit('-', 1)
                files[pkg] = [fn]
            else:
                continue  # unexpected string
    
        return {'errors': errors, 'files': files}
class Beacon(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, config):
        '''
        Monitor the memory usage of the minion
    
        Specify thresholds for percent used and only emit a beacon
        if it is exceeded.
    
        .. code-block:: yaml
    
            beacons:
              memusage:
                - percent: 63%
        '''
        ret = []
    
        _config = {}
        list(map(_config.update, config))
    
        _current_usage = psutil.virtual_memory()
    
        current_usage = _current_usage.percent
        monitor_usage = _config['percent']
        if '%' in monitor_usage:
            monitor_usage = re.sub('%', '', monitor_usage)
        monitor_usage = float(monitor_usage)
        if current_usage >= monitor_usage:
            ret.append({'memusage': current_usage})
        return ret
class Format_name(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Format the function name
            '''
            if not hasattr(self.module, '__func_alias__'):
                # Resume normal sphinx.ext.autodoc operation
                return super(FunctionDocumenter, self).format_name()
    
            if not self.objpath:
                # Resume normal sphinx.ext.autodoc operation
                return super(FunctionDocumenter, self).format_name()
    
            if len(self.objpath) > 1:
                # Resume normal sphinx.ext.autodoc operation
                return super(FunctionDocumenter, self).format_name()
    
            # Use the salt func aliased name instead of the real name
            return self.module.__func_alias__.get(self.objpath[0], self.objpath[0])
class _iptables_cmd(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, family='ipv4'):
        '''
        Return correct command based on the family, e.g. ipv4 or ipv6
        '''
        if family == 'ipv6':
            return salt.utils.path.which('ip6tables')
        else:
            return salt.utils.path.which('iptables')
class _conf(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, family='ipv4'):
        '''
        Some distros have a specific location for config files
        '''
        if __grains__['os_family'] == 'RedHat':
            if family == 'ipv6':
                return '/etc/sysconfig/ip6tables'
            else:
                return '/etc/sysconfig/iptables'
        elif __grains__['os_family'] == 'Arch':
            if family == 'ipv6':
                return '/etc/iptables/ip6tables.rules'
            else:
                return '/etc/iptables/iptables.rules'
        elif __grains__['os_family'] == 'Debian':
            if family == 'ipv6':
                return '/etc/iptables/rules.v6'
            else:
                return '/etc/iptables/rules.v4'
        elif __grains__['os_family'] == 'Gentoo':
            if family == 'ipv6':
                return '/var/lib/ip6tables/rules-save'
            else:
                return '/var/lib/iptables/rules-save'
        elif __grains__['os_family'] == 'Suse':
            # SuSE does not seem to use separate files for IPv4 and IPv6
            return '/etc/sysconfig/scripts/SuSEfirewall2-custom'
        elif __grains__['os_family'] == 'Void':
            if family == 'ipv4':
                return '/etc/iptables/iptables.rules'
            else:
                return '/etc/iptables/ip6tables.rules'
        elif __grains__['os'] == 'Alpine':
            if family == 'ipv6':
                return '/etc/iptables/rules6-save'
            else:
                return '/etc/iptables/rules-save'
        else:
            raise SaltException('Saving iptables to file is not' +
                                ' supported on {0}.'.format(__grains__['os']) +
                                ' Please file an issue with SaltStack')
class Version(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, family='ipv4'):
        '''
        Return version from iptables --version
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' iptables.version
    
            IPv6:
            salt '*' iptables.version family=ipv6
        '''
        cmd = '{0} --version' . format(_iptables_cmd(family))
        out = __salt__['cmd.run'](cmd).split()
        return out[1]
class _parser(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        This function attempts to list all the options documented in the
        iptables(8) and iptables-extensions(8) man pages.  They will not all be
        used by all parts of the module; use them intelligently and appropriately.
        '''
        add_arg = None
        if sys.version.startswith('2.6'):
            import optparse
            parser = optparse.OptionParser()
            add_arg = parser.add_option
        else:
            import argparse  # pylint: disable=minimum-python-version
            parser = argparse.ArgumentParser()
            add_arg = parser.add_argument
    
        # COMMANDS
        add_arg('-A', '--append', dest='append', action='append')
        add_arg('-D', '--delete', dest='delete', action='append')
        add_arg('-I', '--insert', dest='insert', action='append')
        add_arg('-R', '--replace', dest='replace', action='append')
        add_arg('-L', '--list', dest='list', action='append')
        add_arg('-F', '--flush', dest='flush', action='append')
        add_arg('-Z', '--zero', dest='zero', action='append')
        add_arg('-N', '--new-chain', dest='new-chain', action='append')
        add_arg('-X', '--delete-chain', dest='delete-chain', action='append')
        add_arg('-P', '--policy', dest='policy', action='append')
        add_arg('-E', '--rename-chain', dest='rename-chain', action='append')
    
        # PARAMETERS
        add_arg('-p', '--protocol', dest='protocol', action='append')
        add_arg('-s', '--source', dest='source', action='append')
        add_arg('-d', '--destination', dest='destination', action='append')
        add_arg('-j', '--jump', dest='jump', action='append')
        add_arg('-g', '--goto', dest='goto', action='append')
        add_arg('-i', '--in-interface', dest='in-interface', action='append')
        add_arg('-o', '--out-interface', dest='out-interface', action='append')
        add_arg('-f', '--fragment', dest='fragment', action='append')
        add_arg('-c', '--set-counters', dest='set-counters', action='append')
    
        # MATCH EXTENSIONS
        add_arg('-m', '--match', dest='match', action='append')
        ## addrtype
        add_arg('--src-type', dest='src-type', action='append')
        add_arg('--dst-type', dest='dst-type', action='append')
        add_arg('--limit-iface-in', dest='limit-iface-in', action='append')
        add_arg('--limit-iface-out', dest='limit-iface-out', action='append')
        ## ah
        add_arg('--ahspi', dest='ahspi', action='append')
        add_arg('--ahlen', dest='ahlen', action='append')
        add_arg('--ahres', dest='ahres', action='append')
        ## bpf
        add_arg('--bytecode', dest='bytecode', action='append')
        ## cgroup
        add_arg('--cgroup', dest='cgroup', action='append')
        ## cluster
        add_arg('--cluster-total-nodes',
                dest='cluster-total-nodes',
                action='append')
        add_arg('--cluster-local-node', dest='cluster-local-node', action='append')
        add_arg('--cluster-local-nodemask',
                dest='cluster-local-nodemask',
                action='append')
        add_arg('--cluster-hash-seed', dest='cluster-hash-seed', action='append')
        add_arg('--h-length', dest='h-length', action='append')
        add_arg('--mangle-mac-s', dest='mangle-mac-s', action='append')
        add_arg('--mangle-mac-d', dest='mangle-mac-d', action='append')
        ## comment
        add_arg('--comment', dest='comment', action='append')
        ## connbytes
        add_arg('--connbytes', dest='connbytes', action='append')
        add_arg('--connbytes-dir', dest='connbytes-dir', action='append')
        add_arg('--connbytes-mode', dest='connbytes-mode', action='append')
        ## connlabel
        add_arg('--label', dest='label', action='append')
        ## connlimit
        add_arg('--connlimit-upto', dest='connlimit-upto', action='append')
        add_arg('--connlimit-above', dest='connlimit-above', action='append')
        add_arg('--connlimit-mask', dest='connlimit-mask', action='append')
        add_arg('--connlimit-saddr', dest='connlimit-saddr', action='append')
        add_arg('--connlimit-daddr', dest='connlimit-daddr', action='append')
        ## connmark
        add_arg('--mark', dest='mark', action='append')
        ## conntrack
        add_arg('--ctstate', dest='ctstate', action='append')
        add_arg('--ctproto', dest='ctproto', action='append')
        add_arg('--ctorigsrc', dest='ctorigsrc', action='append')
        add_arg('--ctorigdst', dest='ctorigdst', action='append')
        add_arg('--ctreplsrc', dest='ctreplsrc', action='append')
        add_arg('--ctrepldst', dest='ctrepldst', action='append')
        add_arg('--ctorigsrcport', dest='ctorigsrcport', action='append')
        add_arg('--ctorigdstport', dest='ctorigdstport', action='append')
        add_arg('--ctreplsrcport', dest='ctreplsrcport', action='append')
        add_arg('--ctrepldstport', dest='ctrepldstport', action='append')
        add_arg('--ctstatus', dest='ctstatus', action='append')
        add_arg('--ctexpire', dest='ctexpire', action='append')
        add_arg('--ctdir', dest='ctdir', action='append')
        ## cpu
        add_arg('--cpu', dest='cpu', action='append')
        ## dccp
        add_arg('--sport', '--source-port', dest='source_port', action='append')
        add_arg('--dport',
                '--destination-port',
                dest='destination_port',
                action='append')
        add_arg('--dccp-types', dest='dccp-types', action='append')
        add_arg('--dccp-option', dest='dccp-option', action='append')
        ## devgroup
        add_arg('--src-group', dest='src-group', action='append')
        add_arg('--dst-group', dest='dst-group', action='append')
        ## dscp
        add_arg('--dscp', dest='dscp', action='append')
        add_arg('--dscp-class', dest='dscp-class', action='append')
        ## dst
        add_arg('--dst-len', dest='dst-len', action='append')
        add_arg('--dst-opts', dest='dst-opts', action='append')
        ## ecn
        add_arg('--ecn-tcp-cwr', dest='ecn-tcp-cwr', action='append')
        add_arg('--ecn-tcp-ece', dest='ecn-tcp-ece', action='append')
        add_arg('--ecn-ip-ect', dest='ecn-ip-ect', action='append')
        ## esp
        add_arg('--espspi', dest='espspi', action='append')
        ## frag
        add_arg('--fragid', dest='fragid', action='append')
        add_arg('--fraglen', dest='fraglen', action='append')
        add_arg('--fragres', dest='fragres', action='append')
        add_arg('--fragfirst', dest='fragfirst', action='append')
        add_arg('--fragmore', dest='fragmore', action='append')
        add_arg('--fraglast', dest='fraglast', action='append')
        ## hashlimit
        add_arg('--hashlimit-upto', dest='hashlimit-upto', action='append')
        add_arg('--hashlimit-above', dest='hashlimit-above', action='append')
        add_arg('--hashlimit-burst', dest='hashlimit-burst', action='append')
        add_arg('--hashlimit-mode', dest='hashlimit-mode', action='append')
        add_arg('--hashlimit-srcmask', dest='hashlimit-srcmask', action='append')
        add_arg('--hashlimit-dstmask', dest='hashlimit-dstmask', action='append')
        add_arg('--hashlimit-name', dest='hashlimit-name', action='append')
        add_arg('--hashlimit-htable-size',
                dest='hashlimit-htable-size',
                action='append')
        add_arg('--hashlimit-htable-max',
                dest='hashlimit-htable-max',
                action='append')
        add_arg('--hashlimit-htable-expire',
                dest='hashlimit-htable-expire',
                action='append')
        add_arg('--hashlimit-htable-gcinterval',
                dest='hashlimit-htable-gcinterval',
                action='append')
        ## hbh
        add_arg('--hbh-len', dest='hbh-len', action='append')
        add_arg('--hbh-opts', dest='hbh-opts', action='append')
        ## helper
        add_arg('--helper', dest='helper', action='append')
        ## hl
        add_arg('--hl-eq', dest='hl-eq', action='append')
        add_arg('--hl-lt', dest='hl-lt', action='append')
        add_arg('--hl-gt', dest='hl-gt', action='append')
        ## icmp
        add_arg('--icmp-type', dest='icmp-type', action='append')
        ## icmp6
        add_arg('--icmpv6-type', dest='icmpv6-type', action='append')
        ## iprange
        add_arg('--src-range', dest='src-range', action='append')
        add_arg('--dst-range', dest='dst-range', action='append')
        ## ipv6header
        add_arg('--soft', dest='soft', action='append')
        add_arg('--header', dest='header', action='append')
        ## ipvs
        add_arg('--ipvs', dest='ipvs', action='append')
        add_arg('--vproto', dest='vproto', action='append')
        add_arg('--vaddr', dest='vaddr', action='append')
        add_arg('--vport', dest='vport', action='append')
        add_arg('--vdir', dest='vdir', action='append')
        add_arg('--vmethod', dest='vmethod', action='append')
        add_arg('--vportctl', dest='vportctl', action='append')
        ## length
        add_arg('--length', dest='length', action='append')
        ## limit
        add_arg('--limit', dest='limit', action='append')
        add_arg('--limit-burst', dest='limit-burst', action='append')
        ## mac
        add_arg('--mac-source', dest='mac-source', action='append')
        ## mh
        add_arg('--mh-type', dest='mh-type', action='append')
        ## multiport
        add_arg('--sports', '--source-ports', dest='source-ports', action='append')
        add_arg('--dports',
                '--destination-ports',
                dest='destination-ports',
                action='append')
        add_arg('--ports', dest='ports', action='append')
        ## nfacct
        add_arg('--nfacct-name', dest='nfacct-name', action='append')
        ## osf
        add_arg('--genre', dest='genre', action='append')
        add_arg('--ttl', dest='ttl', action='append')
        add_arg('--log', dest='log', action='append')
        ## owner
        add_arg('--uid-owner', dest='uid-owner', action='append')
        add_arg('--gid-owner', dest='gid-owner', action='append')
        add_arg('--socket-exists', dest='socket-exists', action='append')
        ## physdev
        add_arg('--physdev-in', dest='physdev-in', action='append')
        add_arg('--physdev-out', dest='physdev-out', action='append')
        add_arg('--physdev-is-in', dest='physdev-is-in', action='append')
        add_arg('--physdev-is-out', dest='physdev-is-out', action='append')
        add_arg('--physdev-is-bridged', dest='physdev-is-bridged', action='append')
        ## pkttype
        add_arg('--pkt-type', dest='pkt-type', action='append')
        ## policy
        add_arg('--dir', dest='dir', action='append')
        add_arg('--pol', dest='pol', action='append')
        add_arg('--strict', dest='strict', action='append')
        add_arg('--reqid', dest='reqid', action='append')
        add_arg('--spi', dest='spi', action='append')
        add_arg('--proto', dest='proto', action='append')
        add_arg('--mode', dest='mode', action='append')
        add_arg('--tunnel-src', dest='tunnel-src', action='append')
        add_arg('--tunnel-dst', dest='tunnel-dst', action='append')
        add_arg('--next', dest='next', action='append')
        ## quota
        add_arg('--quota', dest='quota', action='append')
        ## rateest
        add_arg('--rateest', dest='rateest', action='append')
        add_arg('--rateest1', dest='rateest1', action='append')
        add_arg('--rateest2', dest='rateest2', action='append')
        add_arg('--rateest-delta', dest='rateest-delta', action='append')
        add_arg('--rateest-bps', dest='rateest-bps', action='append')
        add_arg('--rateest-bps1', dest='rateest-bps1', action='append')
        add_arg('--rateest-bps2', dest='rateest-bps2', action='append')
        add_arg('--rateest-pps', dest='rateest-pps', action='append')
        add_arg('--rateest-pps1', dest='rateest-pps1', action='append')
        add_arg('--rateest-pps2', dest='rateest-pps2', action='append')
        add_arg('--rateest-lt', dest='rateest-lt', action='append')
        add_arg('--rateest-gt', dest='rateest-gt', action='append')
        add_arg('--rateest-eq', dest='rateest-eq', action='append')
        add_arg('--rateest-name', dest='rateest-name', action='append')
        add_arg('--rateest-interval', dest='rateest-interval', action='append')
        add_arg('--rateest-ewma', dest='rateest-ewma', action='append')
        ## realm
        add_arg('--realm', dest='realm', action='append')
        ## recent
        add_arg('--name', dest='name', action='append')
        add_arg('--set', dest='set', action='append')
        add_arg('--rsource', dest='rsource', action='append')
        add_arg('--rdest', dest='rdest', action='append')
        add_arg('--mask', dest='mask', action='append')
        add_arg('--rcheck', dest='rcheck', action='append')
        add_arg('--update', dest='update', action='append')
        add_arg('--remove', dest='remove', action='append')
        add_arg('--seconds', dest='seconds', action='append')
        add_arg('--reap', dest='reap', action='append')
        add_arg('--hitcount', dest='hitcount', action='append')
        add_arg('--rttl', dest='rttl', action='append')
        ## rpfilter
        add_arg('--loose', dest='loose', action='append')
        add_arg('--validmark', dest='validmark', action='append')
        add_arg('--accept-local', dest='accept-local', action='append')
        add_arg('--invert', dest='invert', action='append')
        ## rt
        add_arg('--rt-type', dest='rt-type', action='append')
        add_arg('--rt-segsleft', dest='rt-segsleft', action='append')
        add_arg('--rt-len', dest='rt-len', action='append')
        add_arg('--rt-0-res', dest='rt-0-res', action='append')
        add_arg('--rt-0-addrs', dest='rt-0-addrs', action='append')
        add_arg('--rt-0-not-strict', dest='rt-0-not-strict', action='append')
        ## sctp
        add_arg('--chunk-types', dest='chunk-types', action='append')
        ## set
        add_arg('--match-set', dest='match-set', action='append')
        add_arg('--return-nomatch', dest='return-nomatch', action='append')
        add_arg('--update-counters', dest='update-counters', action='append')
        add_arg('--update-subcounters', dest='update-subcounters', action='append')
        add_arg('--packets-eq', dest='packets-eq', action='append')
        add_arg('--packets-lt', dest='packets-lt', action='append')
        add_arg('--packets-gt', dest='packets-gt', action='append')
        add_arg('--bytes-eq', dest='bytes-eq', action='append')
        add_arg('--bytes-lt', dest='bytes-lt', action='append')
        add_arg('--bytes-gt', dest='bytes-gt', action='append')
        ## socket
        add_arg('--transparent', dest='transparent', action='append')
        add_arg('--nowildcard', dest='nowildcard', action='append')
        ## state
        add_arg('--state', dest='state', action='append')
        ## statistic
        add_arg('--probability', dest='probability', action='append')
        add_arg('--every', dest='every', action='append')
        add_arg('--packet', dest='packet', action='append')
        ## string
        add_arg('--algo', dest='algo', action='append')
        add_arg('--from', dest='from', action='append')
        add_arg('--to', dest='to', action='append')
        add_arg('--string', dest='string', action='append')
        add_arg('--hex-string', dest='hex-string', action='append')
        ## tcp
        add_arg('--tcp-flags', dest='tcp-flags', action='append')
        add_arg('--syn', dest='syn', action='append')
        add_arg('--tcp-option', dest='tcp-option', action='append')
        ## tcpmss
        add_arg('--mss', dest='mss', action='append')
        ## time
        add_arg('--datestart', dest='datestart', action='append')
        add_arg('--datestop', dest='datestop', action='append')
        add_arg('--timestart', dest='timestart', action='append')
        add_arg('--timestop', dest='timestop', action='append')
        add_arg('--monthdays', dest='monthdays', action='append')
        add_arg('--weekdays', dest='weekdays', action='append')
        add_arg('--contiguous', dest='contiguous', action='append')
        add_arg('--kerneltz', dest='kerneltz', action='append')
        add_arg('--utc', dest='utc', action='append')
        add_arg('--localtz', dest='localtz', action='append')
        ## tos
        add_arg('--tos', dest='tos', action='append')
        ## ttl
        add_arg('--ttl-eq', dest='ttl-eq', action='append')
        add_arg('--ttl-gt', dest='ttl-gt', action='append')
        add_arg('--ttl-lt', dest='ttl-lt', action='append')
        ## u32
        add_arg('--u32', dest='u32', action='append')
    
        # Xtables-addons matches
        ## condition
        add_arg('--condition', dest='condition', action='append')
        ## dhcpmac
        add_arg('--mac', dest='mac', action='append')
        ## fuzzy
        add_arg('--lower-limit', dest='lower-limit', action='append')
        add_arg('--upper-limit', dest='upper-limit', action='append')
        ## geoip
        add_arg('--src-cc',
                '--source-country',
                dest='source-country',
                action='append')
        add_arg('--dst-cc',
                '--destination-country',
                dest='destination-country',
                action='append')
        ## gradm
        add_arg('--enabled', dest='enabled', action='append')
        add_arg('--disabled', dest='disabled', action='append')
        ## iface
        add_arg('--iface', dest='iface', action='append')
        add_arg('--dev-in', dest='dev-in', action='append')
        add_arg('--dev-out', dest='dev-out', action='append')
        add_arg('--up', dest='up', action='append')
        add_arg('--down', dest='down', action='append')
        add_arg('--broadcast', dest='broadcast', action='append')
        add_arg('--loopback', dest='loopback', action='append')
        add_arg('--pointtopoint', dest='pointtopoint', action='append')
        add_arg('--running', dest='running', action='append')
        add_arg('--noarp', dest='noarp', action='append')
        add_arg('--arp', dest='arp', action='append')
        add_arg('--promisc', dest='promisc', action='append')
        add_arg('--multicast', dest='multicast', action='append')
        add_arg('--dynamic', dest='dynamic', action='append')
        add_arg('--lower-up', dest='lower-up', action='append')
        add_arg('--dormant', dest='dormant', action='append')
        ## ipp2p
        add_arg('--edk', dest='edk', action='append')
        add_arg('--kazaa', dest='kazaa', action='append')
        add_arg('--gnu', dest='gnu', action='append')
        add_arg('--dc', dest='dc', action='append')
        add_arg('--bit', dest='bit', action='append')
        add_arg('--apple', dest='apple', action='append')
        add_arg('--soul', dest='soul', action='append')
        add_arg('--winmx', dest='winmx', action='append')
        add_arg('--ares', dest='ares', action='append')
        add_arg('--debug', dest='debug', action='append')
        ## ipv4options
        add_arg('--flags', dest='flags', action='append')
        add_arg('--any', dest='any', action='append')
        ## length2
        add_arg('--layer3', dest='layer3', action='append')
        add_arg('--layer4', dest='layer4', action='append')
        add_arg('--layer5', dest='layer5', action='append')
        ## lscan
        add_arg('--stealth', dest='stealth', action='append')
        add_arg('--synscan', dest='synscan', action='append')
        add_arg('--cnscan', dest='cnscan', action='append')
        add_arg('--grscan', dest='grscan', action='append')
        ## psd
        add_arg('--psd-weight-threshold',
                dest='psd-weight-threshold',
                action='append')
        add_arg('--psd-delay-threshold',
                dest='psd-delay-threshold',
                action='append')
        add_arg('--psd-lo-ports-weight',
                dest='psd-lo-ports-weight',
                action='append')
        add_arg('--psd-hi-ports-weight',
                dest='psd-hi-ports-weight',
                action='append')
        ## quota2
        add_arg('--grow', dest='grow', action='append')
        add_arg('--no-change', dest='no-change', action='append')
        add_arg('--packets', dest='packets', action='append')
        ## pknock
        add_arg('--knockports', dest='knockports', action='append')
        add_arg('--time', dest='time', action='append')
        add_arg('--autoclose', dest='autoclose', action='append')
        add_arg('--checkip', dest='checkip', action='append')
    
        # TARGET EXTENSIONS
        ## AUDIT
        add_arg('--type', dest='type', action='append')
        ## CHECKSUM
        add_arg('--checksum-fill', dest='checksum-fill', action='append')
        ## CLASSIFY
        add_arg('--set-class', dest='set-class', action='append')
        ## CLUSTERIP
        add_arg('--new', dest='new', action='append')
        add_arg('--hashmode', dest='hashmode', action='append')
        add_arg('--clustermac', dest='clustermac', action='append')
        add_arg('--total-nodes', dest='total-nodes', action='append')
        add_arg('--local-node', dest='local-node', action='append')
        add_arg('--hash-init', dest='hash-init', action='append')
        ## CONNMARK
        add_arg('--set-xmark', dest='set-xmark', action='append')
        add_arg('--save-mark', dest='save-mark', action='append')
        add_arg('--restore-mark', dest='restore-mark', action='append')
        add_arg('--and-mark', dest='and-mark', action='append')
        add_arg('--or-mark', dest='or-mark', action='append')
        add_arg('--xor-mark', dest='xor-mark', action='append')
        add_arg('--set-mark', dest='set-mark', action='append')
        add_arg('--nfmask', dest='nfmask', action='append')
        add_arg('--ctmask', dest='ctmask', action='append')
        ## CONNSECMARK
        add_arg('--save', dest='save', action='append')
        add_arg('--restore', dest='restore', action='append')
        ## CT
        add_arg('--notrack', dest='notrack', action='append')
        add_arg('--ctevents', dest='ctevents', action='append')
        add_arg('--expevents', dest='expevents', action='append')
        add_arg('--zone', dest='zone', action='append')
        add_arg('--timeout', dest='timeout', action='append')
        ## DNAT
        add_arg('--to-destination', dest='to-destination', action='append')
        add_arg('--random', dest='random', action='append')
        add_arg('--persistent', dest='persistent', action='append')
        ## DNPT
        add_arg('--src-pfx', dest='src-pfx', action='append')
        add_arg('--dst-pfx', dest='dst-pfx', action='append')
        ## DSCP
        add_arg('--set-dscp', dest='set-dscp', action='append')
        add_arg('--set-dscp-class', dest='set-dscp-class', action='append')
        ## ECN
        add_arg('--ecn-tcp-remove', dest='ecn-tcp-remove', action='append')
        ## HL
        add_arg('--hl-set', dest='hl-set', action='append')
        add_arg('--hl-dec', dest='hl-dec', action='append')
        add_arg('--hl-inc', dest='hl-inc', action='append')
        ## HMARK
        add_arg('--hmark-tuple', dest='hmark-tuple', action='append')
        add_arg('--hmark-mod', dest='hmark-mod', action='append')
        add_arg('--hmark-offset', dest='hmark-offset', action='append')
        add_arg('--hmark-src-prefix', dest='hmark-src-prefix', action='append')
        add_arg('--hmark-dst-prefix', dest='hmark-dst-prefix', action='append')
        add_arg('--hmark-sport-mask', dest='hmark-sport-mask', action='append')
        add_arg('--hmark-dport-mask', dest='hmark-dport-mask', action='append')
        add_arg('--hmark-spi-mask', dest='hmark-spi-mask', action='append')
        add_arg('--hmark-proto-mask', dest='hmark-proto-mask', action='append')
        add_arg('--hmark-rnd', dest='hmark-rnd', action='append')
        ## LED
        add_arg('--led-trigger-id', dest='led-trigger-id', action='append')
        add_arg('--led-delay', dest='led-delay', action='append')
        add_arg('--led-always-blink', dest='led-always-blink', action='append')
        ## LOG
        add_arg('--log-level', dest='log-level', action='append')
        add_arg('--log-prefix', dest='log-prefix', action='append')
        add_arg('--log-tcp-sequence', dest='log-tcp-sequence', action='append')
        add_arg('--log-tcp-options', dest='log-tcp-options', action='append')
        add_arg('--log-ip-options', dest='log-ip-options', action='append')
        add_arg('--log-uid', dest='log-uid', action='append')
        ## MASQUERADE
        add_arg('--to-ports', dest='to-ports', action='append')
        ## NFLOG
        add_arg('--nflog-group', dest='nflog-group', action='append')
        add_arg('--nflog-prefix', dest='nflog-prefix', action='append')
        add_arg('--nflog-range', dest='nflog-range', action='append')
        add_arg('--nflog-threshold', dest='nflog-threshold', action='append')
        ## NFQUEUE
        add_arg('--queue-num', dest='queue-num', action='append')
        add_arg('--queue-balance', dest='queue-balance', action='append')
        add_arg('--queue-bypass', dest='queue-bypass', action='append')
        add_arg('--queue-cpu-fanout', dest='queue-cpu-fanout', action='append')
        ## RATEEST
        add_arg('--rateest-ewmalog', dest='rateest-ewmalog', action='append')
        ## REJECT
        add_arg('--reject-with', dest='reject-with', action='append')
        ## SAME
        add_arg('--nodst', dest='nodst', action='append')
        ## SECMARK
        add_arg('--selctx', dest='selctx', action='append')
        ## SET
        add_arg('--add-set', dest='add-set', action='append')
        add_arg('--del-set', dest='del-set', action='append')
        add_arg('--exist', dest='exist', action='append')
        ## SNAT
        add_arg('--to-source', dest='to-source', action='append')
        ## TCPMSS
        add_arg('--set-mss', dest='set-mss', action='append')
        add_arg('--clamp-mss-to-pmtu', dest='clamp-mss-to-pmtu', action='append')
        ## TCPOPTSTRIP
        add_arg('--strip-options', dest='strip-options', action='append')
        ## TEE
        add_arg('--gateway', dest='gateway', action='append')
        ## TOS
        add_arg('--set-tos', dest='set-tos', action='append')
        add_arg('--and-tos', dest='and-tos', action='append')
        add_arg('--or-tos', dest='or-tos', action='append')
        add_arg('--xor-tos', dest='xor-tos', action='append')
        ## TPROXY
        add_arg('--on-port', dest='on-port', action='append')
        add_arg('--on-ip', dest='on-ip', action='append')
        add_arg('--tproxy-mark', dest='tproxy-mark', action='append')
        ## TTL
        add_arg('--ttl-set', dest='ttl-set', action='append')
        add_arg('--ttl-dec', dest='ttl-dec', action='append')
        add_arg('--ttl-inc', dest='ttl-inc', action='append')
        ## ULOG
        add_arg('--ulog-nlgroup', dest='ulog-nlgroup', action='append')
        add_arg('--ulog-prefix', dest='ulog-prefix', action='append')
        add_arg('--ulog-cprange', dest='ulog-cprange', action='append')
        add_arg('--ulog-qthreshold', dest='ulog-qthreshold', action='append')
    
        # Xtables-addons targets
        ## ACCOUNT
        add_arg('--addr', dest='addr', action='append')
        add_arg('--tname', dest='tname', action='append')
        ## CHAOS
        add_arg('--delude', dest='delude', action='append')
        add_arg('--tarpit', dest='tarpit', action='append')
        ## DHCPMAC
        add_arg('--set-mac', dest='set-mac', action='append')
        ## DNETMAP
        add_arg('--prefix', dest='prefix', action='append')
        add_arg('--reuse', dest='reuse', action='append')
        add_arg('--static', dest='static', action='append')
        ## IPMARK
        add_arg('--and-mask', dest='and-mask', action='append')
        add_arg('--or-mask', dest='or-mask', action='append')
        add_arg('--shift', dest='shift', action='append')
        ## TARPIT
        add_arg('--honeypot', dest='honeypot', action='append')
        add_arg('--reset', dest='reset', action='append')
    
        return parser
class _run(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, cmd):
        '''
        Just a convenience function for ``__salt__['cmd.run_all'](cmd)``
        '''
        return __salt__['cmd.run_all'](cmd, env={'HOME': os.path.expanduser('~{0}'.format(__opts__['user']))})
class _nix_env(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        nix-env with quiet option. By default, nix is extremely verbose and prints the build log of every package to stderr. This tells nix to
        only show changes.
        '''
        nixhome = os.path.join(os.path.expanduser('~{0}'.format(__opts__['user'])), '.nix-profile/bin/')
        return [os.path.join(nixhome, 'nix-env')]
class _nix_collect_garbage(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Make sure we get the right nix-store, too.
        '''
        nixhome = os.path.join(os.path.expanduser('~{0}'.format(__opts__['user'])), '.nix-profile/bin/')
        return [os.path.join(nixhome, 'nix-collect-garbage')]
class Upgrade(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *pkgs):
        '''
        Runs an update operation on the specified packages, or all packages if none is specified.
    
        :type pkgs: list(str)
        :param pkgs:
            List of packages to update
    
        :return: The upgraded packages. Example element: ``['libxslt-1.1.0', 'libxslt-1.1.10']``
        :rtype: list(tuple(str, str))
    
        .. code-block:: bash
    
            salt '*' nix.update
            salt '*' nix.update pkgs=one,two
        '''
        cmd = _quietnix()
        cmd.append('--upgrade')
        cmd.extend(pkgs)
    
        out = _run(cmd)
    
        upgrades = [_format_upgrade(s.split(maxsplit=1)[1])
                    for s in out['stderr'].splitlines()
                    if s.startswith('upgrading')]
    
        return [[_strip_quotes(s_) for s_ in s]
                for s in upgrades]
class Install(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *pkgs,**kwargs):
        '''
        Installs a single or multiple packages via nix
    
        :type pkgs: list(str)
        :param pkgs:
            packages to update
        :param bool attributes:
            Pass the list of packages or single package as attribues, not package names.
            default: False
    
        :return: Installed packages. Example element: ``gcc-3.3.2``
        :rtype: list(str)
    
        .. code-block:: bash
    
            salt '*' nix.install package [package2 ...]
            salt '*' nix.install attributes=True attr.name [attr.name2 ...]
        '''
    
        attributes = kwargs.get('attributes', False)
    
        if not pkgs:
            return "Plese specify a package or packages to upgrade"
    
        cmd = _quietnix()
        cmd.append('--install')
    
        if kwargs.get('attributes', False):
            cmd.extend(_zip_flatten('--attr', pkgs))
        else:
            cmd.extend(pkgs)
    
        out = _run(cmd)
    
        installs = list(itertools.chain.from_iterable(
            [s.split()[1:] for s in out['stderr'].splitlines()
             if s.startswith('installing')]
            ))
    
        return [_strip_quotes(s) for s in installs]
class Uninstall(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *pkgs):
        '''
        Erases a package from the current nix profile. Nix uninstalls work differently than other package managers, and the symlinks in the
        profile are removed, while the actual package remains. There is also a ``nix.purge`` function, to clear the package cache of unused
        packages.
    
        :type pkgs: list(str)
        :param pkgs:
            List, single package to uninstall
    
        :return: Packages that have been uninstalled
        :rtype: list(str)
    
        .. code-block:: bash
    
            salt '*' nix.uninstall pkg1 [pkg2 ...]
        '''
    
        cmd = _quietnix()
        cmd.append('--uninstall')
        cmd.extend(pkgs)
    
        out = _run(cmd)
    
        fmtout = out['stderr'].splitlines(), 'uninstalling'
    
        return [_strip_quotes(s.split()[1])
                for s in out['stderr'].splitlines()
                if s.startswith('uninstalling')]
class Collect_garbage(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Completely removed all currently 'uninstalled' packages in the nix store.
    
        Tells the user how many store paths were removed and how much space was freed.
    
        :return: How much space was freed and how many derivations were removed
        :rtype: str
    
        .. warning::
           This is a destructive action on the nix store.
    
        .. code-block:: bash
    
            salt '*' nix.collect_garbage
        '''
        cmd = _nix_collect_garbage()
        cmd.append('--delete-old')
    
        out = _run(cmd)
    
        return out['stdout'].splitlines()
class Run(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *args,**kwargs):
        '''
        Execute a puppet run and return a dict with the stderr, stdout,
        return code, etc. The first positional argument given is checked as a
        subcommand. Following positional arguments should be ordered with arguments
        required by the subcommand first, followed by non-keyword arguments.
        Tags are specified by a tag keyword and comma separated list of values. --
        http://docs.puppetlabs.com/puppet/latest/reference/lang_tags.html
    
        CLI Examples:
    
        .. code-block:: bash
    
            salt '*' puppet.run
            salt '*' puppet.run tags=basefiles::edit,apache::server
            salt '*' puppet.run agent onetime no-daemonize no-usecacheonfailure no-splay ignorecache
            salt '*' puppet.run debug
            salt '*' puppet.run apply /a/b/manifest.pp modulepath=/a/b/modules tags=basefiles::edit,apache::server
        '''
        puppet = _Puppet()
    
        # new args tuple to filter out agent/apply for _Puppet.arguments()
        buildargs = ()
        for arg in range(len(args)):
            # based on puppet documentation action must come first. making the same
            # assertion. need to ensure the list of supported cmds here matches
            # those defined in _Puppet.arguments()
            if args[arg] in ['agent', 'apply']:
                puppet.subcmd = args[arg]
            else:
                buildargs += (args[arg],)
        # args will exist as an empty list even if none have been provided
        puppet.arguments(buildargs)
    
        puppet.kwargs.update(salt.utils.args.clean_kwargs(**kwargs))
    
        ret = __salt__['cmd.run_all'](repr(puppet), python_shell=True)
        return ret
class Enable(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        .. versionadded:: 2014.7.0
    
        Enable the puppet agent
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' puppet.enable
        '''
        puppet = _Puppet()
    
        if os.path.isfile(puppet.disabled_lockfile):
            try:
                os.remove(puppet.disabled_lockfile)
            except (IOError, OSError) as exc:
                msg = 'Failed to enable: {0}'.format(exc)
                log.error(msg)
                raise CommandExecutionError(msg)
            else:
                return True
        return False
class Disable(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, message=None):
        '''
        .. versionadded:: 2014.7.0
    
        Disable the puppet agent
    
        message
            .. versionadded:: 2015.5.2
    
            Disable message to send to puppet
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' puppet.disable
            salt '*' puppet.disable 'Disabled, contact XYZ before enabling'
        '''
    
        puppet = _Puppet()
    
        if os.path.isfile(puppet.disabled_lockfile):
            return False
        else:
            with salt.utils.files.fopen(puppet.disabled_lockfile, 'w') as lockfile:
                try:
                    # Puppet chokes when no valid json is found
                    msg = '{{"disabled_message":"{0}"}}'.format(message) if message is not None else '{}'
                    lockfile.write(salt.utils.stringutils.to_str(msg))
                    lockfile.close()
                    return True
                except (IOError, OSError) as exc:
                    msg = 'Failed to disable: {0}'.format(exc)
                    log.error(msg)
                    raise CommandExecutionError(msg)
class Status(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        .. versionadded:: 2014.7.0
    
        Display puppet agent status
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' puppet.status
        '''
        puppet = _Puppet()
    
        if os.path.isfile(puppet.disabled_lockfile):
            return 'Administratively disabled'
    
        if os.path.isfile(puppet.run_lockfile):
            try:
                with salt.utils.files.fopen(puppet.run_lockfile, 'r') as fp_:
                    pid = int(salt.utils.stringutils.to_unicode(fp_.read()))
                    os.kill(pid, 0)  # raise an OSError if process doesn't exist
            except (OSError, ValueError):
                return 'Stale lockfile'
            else:
                return 'Applying a catalog'
    
        if os.path.isfile(puppet.agent_pidfile):
            try:
                with salt.utils.files.fopen(puppet.agent_pidfile, 'r') as fp_:
                    pid = int(salt.utils.stringutils.to_unicode(fp_.read()))
                    os.kill(pid, 0)  # raise an OSError if process doesn't exist
            except (OSError, ValueError):
                return 'Stale pidfile'
            else:
                return 'Idle daemon'
    
        return 'Stopped'
class Summary(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        .. versionadded:: 2014.7.0
    
        Show a summary of the last puppet agent run
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' puppet.summary
        '''
    
        puppet = _Puppet()
    
        try:
            with salt.utils.files.fopen(puppet.lastrunfile, 'r') as fp_:
                report = salt.utils.yaml.safe_load(fp_)
            result = {}
    
            if 'time' in report:
                try:
                    result['last_run'] = datetime.datetime.fromtimestamp(
                        int(report['time']['last_run'])).isoformat()
                except (TypeError, ValueError, KeyError):
                    result['last_run'] = 'invalid or missing timestamp'
    
                result['time'] = {}
                for key in ('total', 'config_retrieval'):
                    if key in report['time']:
                        result['time'][key] = report['time'][key]
    
            if 'resources' in report:
                result['resources'] = report['resources']
    
        except salt.utils.yaml.YAMLError as exc:
            raise CommandExecutionError(
                'YAML error parsing puppet run summary: {0}'.format(exc)
            )
        except IOError as exc:
            raise CommandExecutionError(
                'Unable to read puppet run summary: {0}'.format(exc)
            )
    
        return result
class Facts(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, puppet=False):
        '''
        Run facter and return the results
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' puppet.facts
        '''
        ret = {}
        opt_puppet = '--puppet' if puppet else ''
        cmd_ret = __salt__['cmd.run_all']('facter {0}'.format(opt_puppet))
    
        if cmd_ret['retcode'] != 0:
            raise CommandExecutionError(cmd_ret['stderr'])
    
        output = cmd_ret['stdout']
    
        # Loop over the facter output and  properly
        # parse it into a nice dictionary for using
        # elsewhere
        for line in output.splitlines():
            if not line:
                continue
            fact, value = _format_fact(line)
            if not fact:
                continue
            ret[fact] = value
        return ret
class List_nodes_select(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, call=None):
        '''
        Return a list of the VMs that are on the provider, with select fields
        '''
        if not call:
            call = 'select'
        if not get_configured_provider():
            return
        info = ['id', 'name', 'image', 'size', 'state', 'public_ips', 'private_ips']
        return salt.utils.cloud.list_nodes_select(
            list_nodes_full(call='action'),
            __opts__.get('query.selection', info), call)
class Get_configured_provider(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, vm_=None):
        '''
        Return the contextual provider of None if no configured
        one can be found.
        '''
        if vm_ is None:
            vm_ = {}
        dalias, driver = __active_provider_name__.split(':')
        data = None
        tgt = 'unknown'
        img_provider = __opts__.get('list_images', '')
        arg_providers = __opts__.get('names', [])
        matched = False
        # --list-images level
        if img_provider:
            tgt = 'provider: {0}'.format(img_provider)
            if dalias == img_provider:
                data = get_provider(img_provider)
                matched = True
        # providers are set in configuration
        if not data and 'profile' not in __opts__ and arg_providers:
            for name in arg_providers:
                tgt = 'provider: {0}'.format(name)
                if dalias == name:
                    data = get_provider(name)
                if data:
                    matched = True
                    break
        # -p is providen, get the uplinked provider
        elif 'profile' in __opts__:
            curprof = __opts__['profile']
            profs = __opts__['profiles']
            tgt = 'profile: {0}'.format(curprof)
            if (
                curprof in profs and
                profs[curprof]['provider'] == __active_provider_name__
            ):
                prov, cdriver = profs[curprof]['provider'].split(':')
                tgt += ' provider: {0}'.format(prov)
                data = get_provider(prov)
                matched = True
        # fallback if we have only __active_provider_name__
        if (
            (__opts__.get('destroy', False) and not data) or (
                not matched and __active_provider_name__
            )
        ):
            data = __opts__.get('providers',
                                {}).get(dalias, {}).get(driver, {})
        # in all cases, verify that the linked saltmaster is alive.
        if data:
            ret = _salt('test.ping', salt_target=data['target'])
            if ret:
                return data
            else:
                log.error(
                    'Configured provider %s minion: %s is unreachable',
                    __active_provider_name__, data['target']
                )
        return False
class Write_launchd_plist(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, program):
        '''
        Write a launchd plist for managing salt-master or salt-minion
    
        CLI Example:
    
        .. code-block:: bash
    
            salt-run launchd.write_launchd_plist salt-master
        '''
        plist_sample_text = '''
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
      <dict>
        <key>Label</key>
        <string>org.saltstack.{program}</string>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
        <key>ProgramArguments</key>
        <array>
            <string>{script}</string>
        </array>
        <key>SoftResourceLimits</key>
        <dict>
            <key>NumberOfFiles</key>
            <integer>100000</integer>
        </dict>
        <key>HardResourceLimits</key>
        <dict>
            <key>NumberOfFiles</key>
            <integer>100000</integer>
        </dict>
      </dict>
    </plist>
        '''.strip()
    
        supported_programs = ['salt-master', 'salt-minion']
    
        if program not in supported_programs:
            sys.stderr.write(
                'Supported programs: \'{0}\'\n'.format(supported_programs)
            )
            sys.exit(-1)
    
            return plist_sample_text.format(
                program=program,
                python=sys.executable,
                script=os.path.join(os.path.dirname(sys.executable), program)
            )
class _windows_cpudata(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return some CPU information on Windows minions
        '''
        # Provides:
        #   num_cpus
        #   cpu_model
        grains = {}
        if 'NUMBER_OF_PROCESSORS' in os.environ:
            # Cast to int so that the logic isn't broken when used as a
            # conditional in templating. Also follows _linux_cpudata()
            try:
                grains['num_cpus'] = int(os.environ['NUMBER_OF_PROCESSORS'])
            except ValueError:
                grains['num_cpus'] = 1
        grains['cpu_model'] = salt.utils.win_reg.read_value(
            hive="HKEY_LOCAL_MACHINE",
            key="HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            vname="ProcessorNameString").get('vdata')
        return grains
class _linux_cpudata(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return some CPU information for Linux minions
        '''
        # Provides:
        #   num_cpus
        #   cpu_model
        #   cpu_flags
        grains = {}
        cpuinfo = '/proc/cpuinfo'
        # Parse over the cpuinfo file
        if os.path.isfile(cpuinfo):
            with salt.utils.files.fopen(cpuinfo, 'r') as _fp:
                grains['num_cpus'] = 0
                for line in _fp:
                    comps = line.split(':')
                    if not len(comps) > 1:
                        continue
                    key = comps[0].strip()
                    val = comps[1].strip()
                    if key == 'processor':
                        grains['num_cpus'] += 1
                    elif key == 'model name':
                        grains['cpu_model'] = val
                    elif key == 'flags':
                        grains['cpu_flags'] = val.split()
                    elif key == 'Features':
                        grains['cpu_flags'] = val.split()
                    # ARM support - /proc/cpuinfo
                    #
                    # Processor       : ARMv6-compatible processor rev 7 (v6l)
                    # BogoMIPS        : 697.95
                    # Features        : swp half thumb fastmult vfp edsp java tls
                    # CPU implementer : 0x41
                    # CPU architecture: 7
                    # CPU variant     : 0x0
                    # CPU part        : 0xb76
                    # CPU revision    : 7
                    #
                    # Hardware        : BCM2708
                    # Revision        : 0002
                    # Serial          : 00000000
                    elif key == 'Processor':
                        grains['cpu_model'] = val.split('-')[0]
                        grains['num_cpus'] = 1
        if 'num_cpus' not in grains:
            grains['num_cpus'] = 0
        if 'cpu_model' not in grains:
            grains['cpu_model'] = 'Unknown'
        if 'cpu_flags' not in grains:
            grains['cpu_flags'] = []
        return grains
class _linux_gpu_data(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        num_gpus: int
        gpus:
          - vendor: nvidia|amd|ati|...
            model: string
        '''
        if __opts__.get('enable_lspci', True) is False:
            return {}
    
        if __opts__.get('enable_gpu_grains', True) is False:
            return {}
    
        lspci = salt.utils.path.which('lspci')
        if not lspci:
            log.debug(
                'The `lspci` binary is not available on the system. GPU grains '
                'will not be available.'
            )
            return {}
    
        # dominant gpu vendors to search for (MUST be lowercase for matching below)
        known_vendors = ['nvidia', 'amd', 'ati', 'intel', 'cirrus logic', 'vmware', 'matrox', 'aspeed']
        gpu_classes = ('vga compatible controller', '3d controller')
    
        devs = []
        try:
            lspci_out = __salt__['cmd.run']('{0} -vmm'.format(lspci))
    
            cur_dev = {}
            error = False
            # Add a blank element to the lspci_out.splitlines() list,
            # otherwise the last device is not evaluated as a cur_dev and ignored.
            lspci_list = lspci_out.splitlines()
            lspci_list.append('')
            for line in lspci_list:
                # check for record-separating empty lines
                if line == '':
                    if cur_dev.get('Class', '').lower() in gpu_classes:
                        devs.append(cur_dev)
                    cur_dev = {}
                    continue
                if re.match(r'^\w+:\s+.*', line):
                    key, val = line.split(':', 1)
                    cur_dev[key.strip()] = val.strip()
                else:
                    error = True
                    log.debug('Unexpected lspci output: \'%s\'', line)
    
            if error:
                log.warning(
                    'Error loading grains, unexpected linux_gpu_data output, '
                    'check that you have a valid shell configured and '
                    'permissions to run lspci command'
                )
        except OSError:
            pass
    
        gpus = []
        for gpu in devs:
            vendor_strings = re.split('[^A-Za-z0-9]', gpu['Vendor'].lower())
            # default vendor to 'unknown', overwrite if we match a known one
            vendor = 'unknown'
            for name in known_vendors:
                # search for an 'expected' vendor name in the list of strings
                if name in vendor_strings:
                    vendor = name
                    break
            gpus.append({'vendor': vendor, 'model': gpu['Device']})
    
        grains = {}
        grains['num_gpus'] = len(gpus)
        grains['gpus'] = gpus
        return grains
class _netbsd_gpu_data(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        num_gpus: int
        gpus:
          - vendor: nvidia|amd|ati|...
            model: string
        '''
        known_vendors = ['nvidia', 'amd', 'ati', 'intel', 'cirrus logic', 'vmware', 'matrox', 'aspeed']
    
        gpus = []
        try:
            pcictl_out = __salt__['cmd.run']('pcictl pci0 list')
    
            for line in pcictl_out.splitlines():
                for vendor in known_vendors:
                    vendor_match = re.match(
                        r'[0-9:]+ ({0}) (.+) \(VGA .+\)'.format(vendor),
                        line,
                        re.IGNORECASE
                    )
                    if vendor_match:
                        gpus.append({'vendor': vendor_match.group(1), 'model': vendor_match.group(2)})
        except OSError:
            pass
    
        grains = {}
        grains['num_gpus'] = len(gpus)
        grains['gpus'] = gpus
        return grains
class _osx_gpudata(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        num_gpus: int
        gpus:
          - vendor: nvidia|amd|ati|...
            model: string
        '''
    
        gpus = []
        try:
            pcictl_out = __salt__['cmd.run']('system_profiler SPDisplaysDataType')
    
            for line in pcictl_out.splitlines():
                fieldname, _, fieldval = line.partition(': ')
                if fieldname.strip() == "Chipset Model":
                    vendor, _, model = fieldval.partition(' ')
                    vendor = vendor.lower()
                    gpus.append({'vendor': vendor, 'model': model})
    
        except OSError:
            pass
    
        grains = {}
        grains['num_gpus'] = len(gpus)
        grains['gpus'] = gpus
        return grains
class _bsd_cpudata(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, osdata):
        '''
        Return CPU information for BSD-like systems
        '''
        # Provides:
        #   cpuarch
        #   num_cpus
        #   cpu_model
        #   cpu_flags
        sysctl = salt.utils.path.which('sysctl')
        arch = salt.utils.path.which('arch')
        cmds = {}
    
        if sysctl:
            cmds.update({
                'num_cpus': '{0} -n hw.ncpu'.format(sysctl),
                'cpuarch': '{0} -n hw.machine'.format(sysctl),
                'cpu_model': '{0} -n hw.model'.format(sysctl),
            })
    
        if arch and osdata['kernel'] == 'OpenBSD':
            cmds['cpuarch'] = '{0} -s'.format(arch)
    
        if osdata['kernel'] == 'Darwin':
            cmds['cpu_model'] = '{0} -n machdep.cpu.brand_string'.format(sysctl)
            cmds['cpu_flags'] = '{0} -n machdep.cpu.features'.format(sysctl)
    
        grains = dict([(k, __salt__['cmd.run'](v)) for k, v in six.iteritems(cmds)])
    
        if 'cpu_flags' in grains and isinstance(grains['cpu_flags'], six.string_types):
            grains['cpu_flags'] = grains['cpu_flags'].split(' ')
    
        if osdata['kernel'] == 'NetBSD':
            grains['cpu_flags'] = []
            for line in __salt__['cmd.run']('cpuctl identify 0').splitlines():
                cpu_match = re.match(r'cpu[0-9]:\ features[0-9]?\ .+<(.+)>', line)
                if cpu_match:
                    flag = cpu_match.group(1).split(',')
                    grains['cpu_flags'].extend(flag)
    
        if osdata['kernel'] == 'FreeBSD' and os.path.isfile('/var/run/dmesg.boot'):
            grains['cpu_flags'] = []
            # TODO: at least it needs to be tested for BSD other then FreeBSD
            with salt.utils.files.fopen('/var/run/dmesg.boot', 'r') as _fp:
                cpu_here = False
                for line in _fp:
                    if line.startswith('CPU: '):
                        cpu_here = True  # starts CPU descr
                        continue
                    if cpu_here:
                        if not line.startswith(' '):
                            break  # game over
                        if 'Features' in line:
                            start = line.find('<')
                            end = line.find('>')
                            if start > 0 and end > 0:
                                flag = line[start + 1:end].split(',')
                                grains['cpu_flags'].extend(flag)
        try:
            grains['num_cpus'] = int(grains['num_cpus'])
        except ValueError:
            grains['num_cpus'] = 1
    
        return grains
class _sunos_cpudata(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the CPU information for Solaris-like systems
        '''
        # Provides:
        #   cpuarch
        #   num_cpus
        #   cpu_model
        #   cpu_flags
        grains = {}
        grains['cpu_flags'] = []
    
        grains['cpuarch'] = __salt__['cmd.run']('isainfo -k')
        psrinfo = '/usr/sbin/psrinfo 2>/dev/null'
        grains['num_cpus'] = len(__salt__['cmd.run'](psrinfo, python_shell=True).splitlines())
        kstat_info = 'kstat -p cpu_info:*:*:brand'
        for line in __salt__['cmd.run'](kstat_info).splitlines():
            match = re.match(r'(\w+:\d+:\w+\d+:\w+)\s+(.+)', line)
            if match:
                grains['cpu_model'] = match.group(2)
        isainfo = 'isainfo -n -v'
        for line in __salt__['cmd.run'](isainfo).splitlines():
            match = re.match(r'^\s+(.+)', line)
            if match:
                cpu_flags = match.group(1).split()
                grains['cpu_flags'].extend(cpu_flags)
    
        return grains
class _aix_cpudata(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return CPU information for AIX systems
        '''
        # Provides:
        #   cpuarch
        #   num_cpus
        #   cpu_model
        #   cpu_flags
        grains = {}
        cmd = salt.utils.path.which('prtconf')
        if cmd:
            data = __salt__['cmd.run']('{0}'.format(cmd)) + os.linesep
            for dest, regstring in (('cpuarch', r'(?im)^\s*Processor\s+Type:\s+(\S+)'),
                                    ('cpu_flags', r'(?im)^\s*Processor\s+Version:\s+(\S+)'),
                                    ('cpu_model', r'(?im)^\s*Processor\s+Implementation\s+Mode:\s+(.*)'),
                                    ('num_cpus', r'(?im)^\s*Number\s+Of\s+Processors:\s+(\S+)')):
                for regex in [re.compile(r) for r in [regstring]]:
                    res = regex.search(data)
                    if res and len(res.groups()) >= 1:
                        grains[dest] = res.group(1).strip().replace("'", '')
        else:
            log.error('The \'prtconf\' binary was not found in $PATH.')
        return grains
class _linux_memdata(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the memory information for Linux-like systems
        '''
        grains = {'mem_total': 0, 'swap_total': 0}
    
        meminfo = '/proc/meminfo'
        if os.path.isfile(meminfo):
            with salt.utils.files.fopen(meminfo, 'r') as ifile:
                for line in ifile:
                    comps = line.rstrip('\n').split(':')
                    if not len(comps) > 1:
                        continue
                    if comps[0].strip() == 'MemTotal':
                        # Use floor division to force output to be an integer
                        grains['mem_total'] = int(comps[1].split()[0]) // 1024
                    if comps[0].strip() == 'SwapTotal':
                        # Use floor division to force output to be an integer
                        grains['swap_total'] = int(comps[1].split()[0]) // 1024
        return grains
class _osx_memdata(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the memory information for BSD-like systems
        '''
        grains = {'mem_total': 0, 'swap_total': 0}
    
        sysctl = salt.utils.path.which('sysctl')
        if sysctl:
            mem = __salt__['cmd.run']('{0} -n hw.memsize'.format(sysctl))
            swap_total = __salt__['cmd.run']('{0} -n vm.swapusage'.format(sysctl)).split()[2].replace(',', '.')
            if swap_total.endswith('K'):
                _power = 2**10
            elif swap_total.endswith('M'):
                _power = 2**20
            elif swap_total.endswith('G'):
                _power = 2**30
            swap_total = float(swap_total[:-1]) * _power
    
            grains['mem_total'] = int(mem) // 1024 // 1024
            grains['swap_total'] = int(swap_total) // 1024 // 1024
        return grains
class _bsd_memdata(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, osdata):
        '''
        Return the memory information for BSD-like systems
        '''
        grains = {'mem_total': 0, 'swap_total': 0}
    
        sysctl = salt.utils.path.which('sysctl')
        if sysctl:
            mem = __salt__['cmd.run']('{0} -n hw.physmem'.format(sysctl))
            if osdata['kernel'] == 'NetBSD' and mem.startswith('-'):
                mem = __salt__['cmd.run']('{0} -n hw.physmem64'.format(sysctl))
            grains['mem_total'] = int(mem) // 1024 // 1024
    
            if osdata['kernel'] in ['OpenBSD', 'NetBSD']:
                swapctl = salt.utils.path.which('swapctl')
                swap_data = __salt__['cmd.run']('{0} -sk'.format(swapctl))
                if swap_data == 'no swap devices configured':
                    swap_total = 0
                else:
                    swap_total = swap_data.split(' ')[1]
            else:
                swap_total = __salt__['cmd.run']('{0} -n vm.swap_total'.format(sysctl))
            grains['swap_total'] = int(swap_total) // 1024 // 1024
        return grains
class _sunos_memdata(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the memory information for SunOS-like systems
        '''
        grains = {'mem_total': 0, 'swap_total': 0}
    
        prtconf = '/usr/sbin/prtconf 2>/dev/null'
        for line in __salt__['cmd.run'](prtconf, python_shell=True).splitlines():
            comps = line.split(' ')
            if comps[0].strip() == 'Memory' and comps[1].strip() == 'size:':
                grains['mem_total'] = int(comps[2].strip())
    
        swap_cmd = salt.utils.path.which('swap')
        swap_data = __salt__['cmd.run']('{0} -s'.format(swap_cmd)).split()
        try:
            swap_avail = int(swap_data[-2][:-1])
            swap_used = int(swap_data[-4][:-1])
            swap_total = (swap_avail + swap_used) // 1024
        except ValueError:
            swap_total = None
        grains['swap_total'] = swap_total
        return grains
class _aix_memdata(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the memory information for AIX systems
        '''
        grains = {'mem_total': 0, 'swap_total': 0}
        prtconf = salt.utils.path.which('prtconf')
        if prtconf:
            for line in __salt__['cmd.run'](prtconf, python_shell=True).splitlines():
                comps = [x for x in line.strip().split(' ') if x]
                if len(comps) > 2 and 'Memory' in comps[0] and 'Size' in comps[1]:
                    grains['mem_total'] = int(comps[2])
                    break
        else:
            log.error('The \'prtconf\' binary was not found in $PATH.')
    
        swap_cmd = salt.utils.path.which('swap')
        if swap_cmd:
            swap_data = __salt__['cmd.run']('{0} -s'.format(swap_cmd)).split()
            try:
                swap_total = (int(swap_data[-2]) + int(swap_data[-6])) * 4
            except ValueError:
                swap_total = None
            grains['swap_total'] = swap_total
        else:
            log.error('The \'swap\' binary was not found in $PATH.')
        return grains
class _memdata(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, osdata):
        '''
        Gather information about the system memory
        '''
        # Provides:
        #   mem_total
        #   swap_total, for supported systems.
        grains = {'mem_total': 0}
        if osdata['kernel'] == 'Linux':
            grains.update(_linux_memdata())
        elif osdata['kernel'] in ('FreeBSD', 'OpenBSD', 'NetBSD'):
            grains.update(_bsd_memdata(osdata))
        elif osdata['kernel'] == 'Darwin':
            grains.update(_osx_memdata())
        elif osdata['kernel'] == 'SunOS':
            grains.update(_sunos_memdata())
        elif osdata['kernel'] == 'AIX':
            grains.update(_aix_memdata())
        elif osdata['kernel'] == 'Windows' and HAS_WMI:
            grains.update(_windows_memdata())
        return grains
class _aix_get_machine_id(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Parse the output of lsattr -El sys0 for os_uuid
        '''
        grains = {}
        cmd = salt.utils.path.which('lsattr')
        if cmd:
            data = __salt__['cmd.run']('{0} -El sys0'.format(cmd)) + os.linesep
            uuid_regexes = [re.compile(r'(?im)^\s*os_uuid\s+(\S+)\s+(.*)')]
            for regex in uuid_regexes:
                res = regex.search(data)
                if res and len(res.groups()) >= 1:
                    grains['machine_id'] = res.group(1).strip()
                    break
        else:
            log.error('The \'lsattr\' binary was not found in $PATH.')
        return grains
class _windows_virtual(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, osdata):
        '''
        Returns what type of virtual hardware is under the hood, kvm or physical
        '''
        # Provides:
        #   virtual
        #   virtual_subtype
        grains = dict()
        if osdata['kernel'] != 'Windows':
            return grains
    
        grains['virtual'] = 'physical'
    
        # It is possible that the 'manufacturer' and/or 'productname' grains
        # exist but have a value of None.
        manufacturer = osdata.get('manufacturer', '')
        if manufacturer is None:
            manufacturer = ''
        productname = osdata.get('productname', '')
        if productname is None:
            productname = ''
    
        if 'QEMU' in manufacturer:
            # FIXME: Make this detect between kvm or qemu
            grains['virtual'] = 'kvm'
        if 'Bochs' in manufacturer:
            grains['virtual'] = 'kvm'
        # Product Name: (oVirt) www.ovirt.org
        # Red Hat Community virtualization Project based on kvm
        elif 'oVirt' in productname:
            grains['virtual'] = 'kvm'
            grains['virtual_subtype'] = 'oVirt'
        # Red Hat Enterprise Virtualization
        elif 'RHEV Hypervisor' in productname:
            grains['virtual'] = 'kvm'
            grains['virtual_subtype'] = 'rhev'
        # Product Name: VirtualBox
        elif 'VirtualBox' in productname:
            grains['virtual'] = 'VirtualBox'
        # Product Name: VMware Virtual Platform
        elif 'VMware Virtual Platform' in productname:
            grains['virtual'] = 'VMware'
        # Manufacturer: Microsoft Corporation
        # Product Name: Virtual Machine
        elif 'Microsoft' in manufacturer and \
             'Virtual Machine' in productname:
            grains['virtual'] = 'VirtualPC'
        # Manufacturer: Parallels Software International Inc.
        elif 'Parallels Software' in manufacturer:
            grains['virtual'] = 'Parallels'
        # Apache CloudStack
        elif 'CloudStack KVM Hypervisor' in productname:
            grains['virtual'] = 'kvm'
            grains['virtual_subtype'] = 'cloudstack'
        return grains
class _virtual(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, osdata):
        '''
        Returns what type of virtual hardware is under the hood, kvm or physical
        '''
        # This is going to be a monster, if you are running a vm you can test this
        # grain with please submit patches!
        # Provides:
        #   virtual
        #   virtual_subtype
        grains = {'virtual': 'physical'}
    
        # Skip the below loop on platforms which have none of the desired cmds
        # This is a temporary measure until we can write proper virtual hardware
        # detection.
        skip_cmds = ('AIX',)
    
        # list of commands to be executed to determine the 'virtual' grain
        _cmds = ['systemd-detect-virt', 'virt-what', 'dmidecode']
        # test first for virt-what, which covers most of the desired functionality
        # on most platforms
        if not salt.utils.platform.is_windows() and osdata['kernel'] not in skip_cmds:
            if salt.utils.path.which('virt-what'):
                _cmds = ['virt-what']
    
        # Check if enable_lspci is True or False
        if __opts__.get('enable_lspci', True) is True:
            # /proc/bus/pci does not exists, lspci will fail
            if os.path.exists('/proc/bus/pci'):
                _cmds += ['lspci']
    
        # Add additional last resort commands
        if osdata['kernel'] in skip_cmds:
            _cmds = ()
    
        # Quick backout for BrandZ (Solaris LX Branded zones)
        # Don't waste time trying other commands to detect the virtual grain
        if HAS_UNAME and osdata['kernel'] == 'Linux' and 'BrandZ virtual linux' in os.uname():
            grains['virtual'] = 'zone'
            return grains
    
        failed_commands = set()
        for command in _cmds:
            args = []
            if osdata['kernel'] == 'Darwin':
                command = 'system_profiler'
                args = ['SPDisplaysDataType']
            elif osdata['kernel'] == 'SunOS':
                virtinfo = salt.utils.path.which('virtinfo')
                if virtinfo:
                    try:
                        ret = __salt__['cmd.run_all']('{0} -a'.format(virtinfo))
                    except salt.exceptions.CommandExecutionError:
                        if salt.log.is_logging_configured():
                            failed_commands.add(virtinfo)
                    else:
                        if ret['stdout'].endswith('not supported'):
                            command = 'prtdiag'
                        else:
                            command = 'virtinfo'
                else:
                    command = 'prtdiag'
    
            cmd = salt.utils.path.which(command)
    
            if not cmd:
                continue
    
            cmd = '{0} {1}'.format(cmd, ' '.join(args))
    
            try:
                ret = __salt__['cmd.run_all'](cmd)
    
                if ret['retcode'] > 0:
                    if salt.log.is_logging_configured():
                        # systemd-detect-virt always returns > 0 on non-virtualized
                        # systems
                        # prtdiag only works in the global zone, skip if it fails
                        if salt.utils.platform.is_windows() or 'systemd-detect-virt' in cmd or 'prtdiag' in cmd:
                            continue
                        failed_commands.add(command)
                    continue
            except salt.exceptions.CommandExecutionError:
                if salt.log.is_logging_configured():
                    if salt.utils.platform.is_windows():
                        continue
                    failed_commands.add(command)
                continue
    
            output = ret['stdout']
            if command == "system_profiler":
                macoutput = output.lower()
                if '0x1ab8' in macoutput:
                    grains['virtual'] = 'Parallels'
                if 'parallels' in macoutput:
                    grains['virtual'] = 'Parallels'
                if 'vmware' in macoutput:
                    grains['virtual'] = 'VMware'
                if '0x15ad' in macoutput:
                    grains['virtual'] = 'VMware'
                if 'virtualbox' in macoutput:
                    grains['virtual'] = 'VirtualBox'
                # Break out of the loop so the next log message is not issued
                break
            elif command == 'systemd-detect-virt':
                if output in ('qemu', 'kvm', 'oracle', 'xen', 'bochs', 'chroot', 'uml', 'systemd-nspawn'):
                    grains['virtual'] = output
                    break
                elif 'vmware' in output:
                    grains['virtual'] = 'VMware'
                    break
                elif 'microsoft' in output:
                    grains['virtual'] = 'VirtualPC'
                    break
                elif 'lxc' in output:
                    grains['virtual'] = 'LXC'
                    break
                elif 'systemd-nspawn' in output:
                    grains['virtual'] = 'LXC'
                    break
            elif command == 'virt-what':
                try:
                    output = output.splitlines()[-1]
                except IndexError:
                    pass
                if output in ('kvm', 'qemu', 'uml', 'xen', 'lxc'):
                    grains['virtual'] = output
                    break
                elif 'vmware' in output:
                    grains['virtual'] = 'VMware'
                    break
                elif 'parallels' in output:
                    grains['virtual'] = 'Parallels'
                    break
                elif 'hyperv' in output:
                    grains['virtual'] = 'HyperV'
                    break
            elif command == 'dmidecode':
                # Product Name: VirtualBox
                if 'Vendor: QEMU' in output:
                    # FIXME: Make this detect between kvm or qemu
                    grains['virtual'] = 'kvm'
                if 'Manufacturer: QEMU' in output:
                    grains['virtual'] = 'kvm'
                if 'Vendor: Bochs' in output:
                    grains['virtual'] = 'kvm'
                if 'Manufacturer: Bochs' in output:
                    grains['virtual'] = 'kvm'
                if 'BHYVE' in output:
                    grains['virtual'] = 'bhyve'
                # Product Name: (oVirt) www.ovirt.org
                # Red Hat Community virtualization Project based on kvm
                elif 'Manufacturer: oVirt' in output:
                    grains['virtual'] = 'kvm'
                    grains['virtual_subtype'] = 'ovirt'
                # Red Hat Enterprise Virtualization
                elif 'Product Name: RHEV Hypervisor' in output:
                    grains['virtual'] = 'kvm'
                    grains['virtual_subtype'] = 'rhev'
                elif 'VirtualBox' in output:
                    grains['virtual'] = 'VirtualBox'
                # Product Name: VMware Virtual Platform
                elif 'VMware' in output:
                    grains['virtual'] = 'VMware'
                # Manufacturer: Microsoft Corporation
                # Product Name: Virtual Machine
                elif ': Microsoft' in output and 'Virtual Machine' in output:
                    grains['virtual'] = 'VirtualPC'
                # Manufacturer: Parallels Software International Inc.
                elif 'Parallels Software' in output:
                    grains['virtual'] = 'Parallels'
                elif 'Manufacturer: Google' in output:
                    grains['virtual'] = 'kvm'
                # Proxmox KVM
                elif 'Vendor: SeaBIOS' in output:
                    grains['virtual'] = 'kvm'
                # Break out of the loop, lspci parsing is not necessary
                break
            elif command == 'lspci':
                # dmidecode not available or the user does not have the necessary
                # permissions
                model = output.lower()
                if 'vmware' in model:
                    grains['virtual'] = 'VMware'
                # 00:04.0 System peripheral: InnoTek Systemberatung GmbH
                #         VirtualBox Guest Service
                elif 'virtualbox' in model:
                    grains['virtual'] = 'VirtualBox'
                elif 'qemu' in model:
                    grains['virtual'] = 'kvm'
                elif 'virtio' in model:
                    grains['virtual'] = 'kvm'
                # Break out of the loop so the next log message is not issued
                break
            elif command == 'prtdiag':
                model = output.lower().split("\n")[0]
                if 'vmware' in model:
                    grains['virtual'] = 'VMware'
                elif 'virtualbox' in model:
                    grains['virtual'] = 'VirtualBox'
                elif 'qemu' in model:
                    grains['virtual'] = 'kvm'
                elif 'joyent smartdc hvm' in model:
                    grains['virtual'] = 'kvm'
                break
            elif command == 'virtinfo':
                grains['virtual'] = 'LDOM'
                break
    
        choices = ('Linux', 'HP-UX')
        isdir = os.path.isdir
        sysctl = salt.utils.path.which('sysctl')
        if osdata['kernel'] in choices:
            if os.path.isdir('/proc'):
                try:
                    self_root = os.stat('/')
                    init_root = os.stat('/proc/1/root/.')
                    if self_root != init_root:
                        grains['virtual_subtype'] = 'chroot'
                except (IOError, OSError):
                    pass
            if isdir('/proc/vz'):
                if os.path.isfile('/proc/vz/version'):
                    grains['virtual'] = 'openvzhn'
                elif os.path.isfile('/proc/vz/veinfo'):
                    grains['virtual'] = 'openvzve'
                    # a posteriori, it's expected for these to have failed:
                    failed_commands.discard('lspci')
                    failed_commands.discard('dmidecode')
            # Provide additional detection for OpenVZ
            if os.path.isfile('/proc/self/status'):
                with salt.utils.files.fopen('/proc/self/status') as status_file:
                    vz_re = re.compile(r'^envID:\s+(\d+)$')
                    for line in status_file:
                        vz_match = vz_re.match(line.rstrip('\n'))
                        if vz_match and int(vz_match.groups()[0]) != 0:
                            grains['virtual'] = 'openvzve'
                        elif vz_match and int(vz_match.groups()[0]) == 0:
                            grains['virtual'] = 'openvzhn'
            if isdir('/proc/sys/xen') or \
                    isdir('/sys/bus/xen') or isdir('/proc/xen'):
                if os.path.isfile('/proc/xen/xsd_kva'):
                    # Tested on CentOS 5.3 / 2.6.18-194.26.1.el5xen
                    # Tested on CentOS 5.4 / 2.6.18-164.15.1.el5xen
                    grains['virtual_subtype'] = 'Xen Dom0'
                else:
                    if osdata.get('productname', '') == 'HVM domU':
                        # Requires dmidecode!
                        grains['virtual_subtype'] = 'Xen HVM DomU'
                    elif os.path.isfile('/proc/xen/capabilities') and \
                            os.access('/proc/xen/capabilities', os.R_OK):
                        with salt.utils.files.fopen('/proc/xen/capabilities') as fhr:
                            if 'control_d' not in fhr.read():
                                # Tested on CentOS 5.5 / 2.6.18-194.3.1.el5xen
                                grains['virtual_subtype'] = 'Xen PV DomU'
                            else:
                                # Shouldn't get to this, but just in case
                                grains['virtual_subtype'] = 'Xen Dom0'
                    # Tested on Fedora 10 / 2.6.27.30-170.2.82 with xen
                    # Tested on Fedora 15 / 2.6.41.4-1 without running xen
                    elif isdir('/sys/bus/xen'):
                        if 'xen:' in __salt__['cmd.run']('dmesg').lower():
                            grains['virtual_subtype'] = 'Xen PV DomU'
                        elif os.path.isfile('/sys/bus/xen/drivers/xenconsole'):
                            # An actual DomU will have the xenconsole driver
                            grains['virtual_subtype'] = 'Xen PV DomU'
                # If a Dom0 or DomU was detected, obviously this is xen
                if 'dom' in grains.get('virtual_subtype', '').lower():
                    grains['virtual'] = 'xen'
            # Check container type after hypervisors, to avoid variable overwrite on containers running in virtual environment.
            if os.path.isfile('/proc/1/cgroup'):
                try:
                    with salt.utils.files.fopen('/proc/1/cgroup', 'r') as fhr:
                        fhr_contents = fhr.read()
                    if ':/lxc/' in fhr_contents:
                        grains['virtual_subtype'] = 'LXC'
                    elif ':/kubepods/' in fhr_contents:
                        grains['virtual_subtype'] = 'kubernetes'
                    elif ':/libpod_parent/' in fhr_contents:
                        grains['virtual_subtype'] = 'libpod'
                    else:
                        if any(x in fhr_contents
                               for x in (':/system.slice/docker', ':/docker/',
                                         ':/docker-ce/')):
                            grains['virtual_subtype'] = 'Docker'
                except IOError:
                    pass
            if os.path.isfile('/proc/cpuinfo'):
                with salt.utils.files.fopen('/proc/cpuinfo', 'r') as fhr:
                    if 'QEMU Virtual CPU' in fhr.read():
                        grains['virtual'] = 'kvm'
            if os.path.isfile('/sys/devices/virtual/dmi/id/product_name'):
                try:
                    with salt.utils.files.fopen('/sys/devices/virtual/dmi/id/product_name', 'r') as fhr:
                        output = salt.utils.stringutils.to_unicode(fhr.read(), errors='replace')
                        if 'VirtualBox' in output:
                            grains['virtual'] = 'VirtualBox'
                        elif 'RHEV Hypervisor' in output:
                            grains['virtual'] = 'kvm'
                            grains['virtual_subtype'] = 'rhev'
                        elif 'oVirt Node' in output:
                            grains['virtual'] = 'kvm'
                            grains['virtual_subtype'] = 'ovirt'
                        elif 'Google' in output:
                            grains['virtual'] = 'gce'
                        elif 'BHYVE' in output:
                            grains['virtual'] = 'bhyve'
                except IOError:
                    pass
        elif osdata['kernel'] == 'FreeBSD':
            kenv = salt.utils.path.which('kenv')
            if kenv:
                product = __salt__['cmd.run'](
                    '{0} smbios.system.product'.format(kenv)
                )
                maker = __salt__['cmd.run'](
                    '{0} smbios.system.maker'.format(kenv)
                )
                if product.startswith('VMware'):
                    grains['virtual'] = 'VMware'
                if product.startswith('VirtualBox'):
                    grains['virtual'] = 'VirtualBox'
                if maker.startswith('Xen'):
                    grains['virtual_subtype'] = '{0} {1}'.format(maker, product)
                    grains['virtual'] = 'xen'
                if maker.startswith('Microsoft') and product.startswith('Virtual'):
                    grains['virtual'] = 'VirtualPC'
                if maker.startswith('OpenStack'):
                    grains['virtual'] = 'OpenStack'
                if maker.startswith('Bochs'):
                    grains['virtual'] = 'kvm'
            if sysctl:
                hv_vendor = __salt__['cmd.run']('{0} hw.hv_vendor'.format(sysctl))
                model = __salt__['cmd.run']('{0} hw.model'.format(sysctl))
                jail = __salt__['cmd.run'](
                    '{0} -n security.jail.jailed'.format(sysctl)
                )
                if 'bhyve' in hv_vendor:
                    grains['virtual'] = 'bhyve'
                if jail == '1':
                    grains['virtual_subtype'] = 'jail'
                if 'QEMU Virtual CPU' in model:
                    grains['virtual'] = 'kvm'
        elif osdata['kernel'] == 'OpenBSD':
            if 'manufacturer' in osdata:
                if osdata['manufacturer'] in ['QEMU', 'Red Hat', 'Joyent']:
                    grains['virtual'] = 'kvm'
                if osdata['manufacturer'] == 'OpenBSD':
                    grains['virtual'] = 'vmm'
        elif osdata['kernel'] == 'SunOS':
            if grains['virtual'] == 'LDOM':
                roles = []
                for role in ('control', 'io', 'root', 'service'):
                    subtype_cmd = '{0} -c current get -H -o value {1}-role'.format(cmd, role)
                    ret = __salt__['cmd.run_all']('{0}'.format(subtype_cmd))
                    if ret['stdout'] == 'true':
                        roles.append(role)
                if roles:
                    grains['virtual_subtype'] = roles
            else:
                # Check if it's a "regular" zone. (i.e. Solaris 10/11 zone)
                zonename = salt.utils.path.which('zonename')
                if zonename:
                    zone = __salt__['cmd.run']('{0}'.format(zonename))
                    if zone != 'global':
                        grains['virtual'] = 'zone'
                # Check if it's a branded zone (i.e. Solaris 8/9 zone)
                if isdir('/.SUNWnative'):
                    grains['virtual'] = 'zone'
        elif osdata['kernel'] == 'NetBSD':
            if sysctl:
                if 'QEMU Virtual CPU' in __salt__['cmd.run'](
                        '{0} -n machdep.cpu_brand'.format(sysctl)):
                    grains['virtual'] = 'kvm'
                elif 'invalid' not in __salt__['cmd.run'](
                        '{0} -n machdep.xen.suspend'.format(sysctl)):
                    grains['virtual'] = 'Xen PV DomU'
                elif 'VMware' in __salt__['cmd.run'](
                        '{0} -n machdep.dmi.system-vendor'.format(sysctl)):
                    grains['virtual'] = 'VMware'
                # NetBSD has Xen dom0 support
                elif __salt__['cmd.run'](
                        '{0} -n machdep.idle-mechanism'.format(sysctl)) == 'xen':
                    if os.path.isfile('/var/run/xenconsoled.pid'):
                        grains['virtual_subtype'] = 'Xen Dom0'
    
        for command in failed_commands:
            log.info(
                "Although '%s' was found in path, the current user "
                'cannot execute it. Grains output might not be '
                'accurate.', command
            )
        return grains
class _virtual_hv(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, osdata):
        '''
        Returns detailed hypervisor information from sysfs
        Currently this seems to be used only by Xen
        '''
        grains = {}
    
        # Bail early if we're not running on Xen
        try:
            if 'xen' not in osdata['virtual']:
                return grains
        except KeyError:
            return grains
    
        # Try to get the exact hypervisor version from sysfs
        try:
            version = {}
            for fn in ('major', 'minor', 'extra'):
                with salt.utils.files.fopen('/sys/hypervisor/version/{}'.format(fn), 'r') as fhr:
                    version[fn] = salt.utils.stringutils.to_unicode(fhr.read().strip())
            grains['virtual_hv_version'] = '{}.{}{}'.format(version['major'], version['minor'], version['extra'])
            grains['virtual_hv_version_info'] = [version['major'], version['minor'], version['extra']]
        except (IOError, OSError, KeyError):
            pass
    
        # Try to read and decode the supported feature set of the hypervisor
        # Based on https://github.com/brendangregg/Misc/blob/master/xen/xen-features.py
        # Table data from include/xen/interface/features.h
        xen_feature_table = {0: 'writable_page_tables',
                             1: 'writable_descriptor_tables',
                             2: 'auto_translated_physmap',
                             3: 'supervisor_mode_kernel',
                             4: 'pae_pgdir_above_4gb',
                             5: 'mmu_pt_update_preserve_ad',
                             7: 'gnttab_map_avail_bits',
                             8: 'hvm_callback_vector',
                             9: 'hvm_safe_pvclock',
                            10: 'hvm_pirqs',
                            11: 'dom0',
                            12: 'grant_map_identity',
                            13: 'memory_op_vnode_supported',
                            14: 'ARM_SMCCC_supported'}
        try:
            with salt.utils.files.fopen('/sys/hypervisor/properties/features', 'r') as fhr:
                features = salt.utils.stringutils.to_unicode(fhr.read().strip())
            enabled_features = []
            for bit, feat in six.iteritems(xen_feature_table):
                if int(features, 16) & (1 << bit):
                    enabled_features.append(feat)
            grains['virtual_hv_features'] = features
            grains['virtual_hv_features_list'] = enabled_features
        except (IOError, OSError, KeyError):
            pass
    
        return grains
class _ps(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, osdata):
        '''
        Return the ps grain
        '''
        grains = {}
        bsd_choices = ('FreeBSD', 'NetBSD', 'OpenBSD', 'MacOS')
        if osdata['os'] in bsd_choices:
            grains['ps'] = 'ps auxwww'
        elif osdata['os_family'] == 'Solaris':
            grains['ps'] = '/usr/ucb/ps auxwww'
        elif osdata['os'] == 'Windows':
            grains['ps'] = 'tasklist.exe'
        elif osdata.get('virtual', '') == 'openvzhn':
            grains['ps'] = (
                'ps -fH -p $(grep -l \"^envID:[[:space:]]*0\\$\" '
                '/proc/[0-9]*/status | sed -e \"s=/proc/\\([0-9]*\\)/.*=\\1=\")  '
                '| awk \'{ $7=\"\"; print }\''
            )
        elif osdata['os_family'] == 'AIX':
            grains['ps'] = '/usr/bin/ps auxww'
        elif osdata['os_family'] == 'NILinuxRT':
            grains['ps'] = 'ps -o user,pid,ppid,tty,time,comm'
        else:
            grains['ps'] = 'ps -efHww'
        return grains
class _windows_platform_data(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Use the platform module for as much as we can.
        '''
        # Provides:
        #    kernelrelease
        #    kernelversion
        #    osversion
        #    osrelease
        #    osservicepack
        #    osmanufacturer
        #    manufacturer
        #    productname
        #    biosversion
        #    serialnumber
        #    osfullname
        #    timezone
        #    windowsdomain
        #    windowsdomaintype
        #    motherboard.productname
        #    motherboard.serialnumber
        #    virtual
    
        if not HAS_WMI:
            return {}
    
        with salt.utils.winapi.Com():
            wmi_c = wmi.WMI()
            # http://msdn.microsoft.com/en-us/library/windows/desktop/aa394102%28v=vs.85%29.aspx
            systeminfo = wmi_c.Win32_ComputerSystem()[0]
            # https://msdn.microsoft.com/en-us/library/aa394239(v=vs.85).aspx
            osinfo = wmi_c.Win32_OperatingSystem()[0]
            # http://msdn.microsoft.com/en-us/library/windows/desktop/aa394077(v=vs.85).aspx
            biosinfo = wmi_c.Win32_BIOS()[0]
            # http://msdn.microsoft.com/en-us/library/windows/desktop/aa394498(v=vs.85).aspx
            timeinfo = wmi_c.Win32_TimeZone()[0]
    
            # http://msdn.microsoft.com/en-us/library/windows/desktop/aa394072(v=vs.85).aspx
            motherboard = {'product': None,
                           'serial': None}
            try:
                motherboardinfo = wmi_c.Win32_BaseBoard()[0]
                motherboard['product'] = motherboardinfo.Product
                motherboard['serial'] = motherboardinfo.SerialNumber
            except IndexError:
                log.debug('Motherboard info not available on this system')
    
            os_release = platform.release()
            kernel_version = platform.version()
            info = salt.utils.win_osinfo.get_os_version_info()
            net_info = salt.utils.win_osinfo.get_join_info()
    
            service_pack = None
            if info['ServicePackMajor'] > 0:
                service_pack = ''.join(['SP', six.text_type(info['ServicePackMajor'])])
    
            # This creates the osrelease grain based on the Windows Operating
            # System Product Name. As long as Microsoft maintains a similar format
            # this should be future proof
            version = 'Unknown'
            release = ''
            if 'Server' in osinfo.Caption:
                for item in osinfo.Caption.split(' '):
                    # If it's all digits, then it's version
                    if re.match(r'\d+', item):
                        version = item
                    # If it starts with R and then numbers, it's the release
                    # ie: R2
                    if re.match(r'^R\d+$', item):
                        release = item
                os_release = '{0}Server{1}'.format(version, release)
            else:
                for item in osinfo.Caption.split(' '):
                    # If it's a number, decimal number, Thin or Vista, then it's the
                    # version
                    if re.match(r'^(\d+(\.\d+)?)|Thin|Vista$', item):
                        version = item
                os_release = version
    
            grains = {
                'kernelrelease': _clean_value('kernelrelease', osinfo.Version),
                'kernelversion': _clean_value('kernelversion', kernel_version),
                'osversion': _clean_value('osversion', osinfo.Version),
                'osrelease': _clean_value('osrelease', os_release),
                'osservicepack': _clean_value('osservicepack', service_pack),
                'osmanufacturer': _clean_value('osmanufacturer', osinfo.Manufacturer),
                'manufacturer': _clean_value('manufacturer', systeminfo.Manufacturer),
                'productname': _clean_value('productname', systeminfo.Model),
                # bios name had a bunch of whitespace appended to it in my testing
                # 'PhoenixBIOS 4.0 Release 6.0     '
                'biosversion': _clean_value('biosversion', biosinfo.Name.strip()),
                'serialnumber': _clean_value('serialnumber', biosinfo.SerialNumber),
                'osfullname': _clean_value('osfullname', osinfo.Caption),
                'timezone': _clean_value('timezone', timeinfo.Description),
                'windowsdomain': _clean_value('windowsdomain', net_info['Domain']),
                'windowsdomaintype': _clean_value('windowsdomaintype', net_info['DomainType']),
                'motherboard': {
                    'productname': _clean_value('motherboard.productname', motherboard['product']),
                    'serialnumber': _clean_value('motherboard.serialnumber', motherboard['serial']),
                }
            }
    
            # test for virtualized environments
            # I only had VMware available so the rest are unvalidated
            if 'VRTUAL' in biosinfo.Version:  # (not a typo)
                grains['virtual'] = 'HyperV'
            elif 'A M I' in biosinfo.Version:
                grains['virtual'] = 'VirtualPC'
            elif 'VMware' in systeminfo.Model:
                grains['virtual'] = 'VMware'
            elif 'VirtualBox' in systeminfo.Model:
                grains['virtual'] = 'VirtualBox'
            elif 'Xen' in biosinfo.Version:
                grains['virtual'] = 'Xen'
                if 'HVM domU' in systeminfo.Model:
                    grains['virtual_subtype'] = 'HVM domU'
            elif 'OpenStack' in systeminfo.Model:
                grains['virtual'] = 'OpenStack'
    
        return grains
class _osx_platform_data(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Additional data for macOS systems
        Returns: A dictionary containing values for the following:
            - model_name
            - boot_rom_version
            - smc_version
            - system_serialnumber
        '''
        cmd = 'system_profiler SPHardwareDataType'
        hardware = __salt__['cmd.run'](cmd)
    
        grains = {}
        for line in hardware.splitlines():
            field_name, _, field_val = line.partition(': ')
            if field_name.strip() == "Model Name":
                key = 'model_name'
                grains[key] = _clean_value(key, field_val)
            if field_name.strip() == "Boot ROM Version":
                key = 'boot_rom_version'
                grains[key] = _clean_value(key, field_val)
            if field_name.strip() == "SMC Version (system)":
                key = 'smc_version'
                grains[key] = _clean_value(key, field_val)
            if field_name.strip() == "Serial Number (system)":
                key = 'system_serialnumber'
                grains[key] = _clean_value(key, field_val)
    
        return grains
class _linux_bin_exists(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, binary):
        '''
        Does a binary exist in linux (depends on which, type, or whereis)
        '''
        for search_cmd in ('which', 'type -ap'):
            try:
                return __salt__['cmd.retcode'](
                    '{0} {1}'.format(search_cmd, binary)
                ) == 0
            except salt.exceptions.CommandExecutionError:
                pass
    
        try:
            return len(__salt__['cmd.run_all'](
                'whereis -b {0}'.format(binary)
            )['stdout'].split()) > 1
        except salt.exceptions.CommandExecutionError:
            return False
class _parse_os_release(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *os_release_files):
        '''
        Parse os-release and return a parameter dictionary
    
        See http://www.freedesktop.org/software/systemd/man/os-release.html
        for specification of the file format.
        '''
        ret = {}
        for filename in os_release_files:
            try:
                with salt.utils.files.fopen(filename) as ifile:
                    regex = re.compile('^([\\w]+)=(?:\'|")?(.*?)(?:\'|")?$')
                    for line in ifile:
                        match = regex.match(line.strip())
                        if match:
                            # Shell special characters ("$", quotes, backslash,
                            # backtick) are escaped with backslashes
                            ret[match.group(1)] = re.sub(
                                r'\\([$"\'\\`])', r'\1', match.group(2)
                            )
                break
            except (IOError, OSError):
                pass
    
        return ret
class _parse_cpe_name(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, cpe):
        '''
        Parse CPE_NAME data from the os-release
    
        Info: https://csrc.nist.gov/projects/security-content-automation-protocol/scap-specifications/cpe
    
        :param cpe:
        :return:
        '''
        part = {
            'o': 'operating system',
            'h': 'hardware',
            'a': 'application',
        }
        ret = {}
        cpe = (cpe or '').split(':')
        if len(cpe) > 4 and cpe[0] == 'cpe':
            if cpe[1].startswith('/'):  # WFN to URI
                ret['vendor'], ret['product'], ret['version'] = cpe[2:5]
                ret['phase'] = cpe[5] if len(cpe) > 5 else None
                ret['part'] = part.get(cpe[1][1:])
            elif len(cpe) == 13 and cpe[1] == '2.3':  # WFN to a string
                ret['vendor'], ret['product'], ret['version'], ret['phase'] = [x if x != '*' else None for x in cpe[3:7]]
                ret['part'] = part.get(cpe[2])
    
        return ret
class Os_data(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return grains pertaining to the operating system
        '''
        grains = {
            'num_gpus': 0,
            'gpus': [],
            }
    
        # Windows Server 2008 64-bit
        # ('Windows', 'MINIONNAME', '2008ServerR2', '6.1.7601', 'AMD64',
        #  'Intel64 Fam ily 6 Model 23 Stepping 6, GenuineIntel')
        # Ubuntu 10.04
        # ('Linux', 'MINIONNAME', '2.6.32-38-server',
        # '#83-Ubuntu SMP Wed Jan 4 11:26:59 UTC 2012', 'x86_64', '')
    
        # pylint: disable=unpacking-non-sequence
        (grains['kernel'], grains['nodename'],
         grains['kernelrelease'], grains['kernelversion'], grains['cpuarch'], _) = platform.uname()
        # pylint: enable=unpacking-non-sequence
    
        if salt.utils.platform.is_proxy():
            grains['kernel'] = 'proxy'
            grains['kernelrelease'] = 'proxy'
            grains['kernelversion'] = 'proxy'
            grains['osrelease'] = 'proxy'
            grains['os'] = 'proxy'
            grains['os_family'] = 'proxy'
            grains['osfullname'] = 'proxy'
        elif salt.utils.platform.is_windows():
            grains['os'] = 'Windows'
            grains['os_family'] = 'Windows'
            grains.update(_memdata(grains))
            grains.update(_windows_platform_data())
            grains.update(_windows_cpudata())
            grains.update(_windows_virtual(grains))
            grains.update(_ps(grains))
    
            if 'Server' in grains['osrelease']:
                osrelease_info = grains['osrelease'].split('Server', 1)
                osrelease_info[1] = osrelease_info[1].lstrip('R')
            else:
                osrelease_info = grains['osrelease'].split('.')
    
            for idx, value in enumerate(osrelease_info):
                if not value.isdigit():
                    continue
                osrelease_info[idx] = int(value)
            grains['osrelease_info'] = tuple(osrelease_info)
    
            grains['osfinger'] = '{os}-{ver}'.format(
                os=grains['os'],
                ver=grains['osrelease'])
    
            grains['init'] = 'Windows'
    
            return grains
        elif salt.utils.platform.is_linux():
            # Add SELinux grain, if you have it
            if _linux_bin_exists('selinuxenabled'):
                log.trace('Adding selinux grains')
                grains['selinux'] = {}
                grains['selinux']['enabled'] = __salt__['cmd.retcode'](
                    'selinuxenabled'
                ) == 0
                if _linux_bin_exists('getenforce'):
                    grains['selinux']['enforced'] = __salt__['cmd.run'](
                        'getenforce'
                    ).strip()
    
            # Add systemd grain, if you have it
            if _linux_bin_exists('systemctl') and _linux_bin_exists('localectl'):
                log.trace('Adding systemd grains')
                grains['systemd'] = {}
                systemd_info = __salt__['cmd.run'](
                    'systemctl --version'
                ).splitlines()
                grains['systemd']['version'] = systemd_info[0].split()[1]
                grains['systemd']['features'] = systemd_info[1]
    
            # Add init grain
            grains['init'] = 'unknown'
            log.trace('Adding init grain')
            try:
                os.stat('/run/systemd/system')
                grains['init'] = 'systemd'
            except (OSError, IOError):
                try:
                    with salt.utils.files.fopen('/proc/1/cmdline') as fhr:
                        init_cmdline = fhr.read().replace('\x00', ' ').split()
                except (IOError, OSError):
                    pass
                else:
                    try:
                        init_bin = salt.utils.path.which(init_cmdline[0])
                    except IndexError:
                        # Emtpy init_cmdline
                        init_bin = None
                        log.warning('Unable to fetch data from /proc/1/cmdline')
                    if init_bin is not None and init_bin.endswith('bin/init'):
                        supported_inits = (b'upstart', b'sysvinit', b'systemd')
                        edge_len = max(len(x) for x in supported_inits) - 1
                        try:
                            buf_size = __opts__['file_buffer_size']
                        except KeyError:
                            # Default to the value of file_buffer_size for the minion
                            buf_size = 262144
                        try:
                            with salt.utils.files.fopen(init_bin, 'rb') as fp_:
                                edge = b''
                                buf = fp_.read(buf_size).lower()
                                while buf:
                                    buf = edge + buf
                                    for item in supported_inits:
                                        if item in buf:
                                            if six.PY3:
                                                item = item.decode('utf-8')
                                            grains['init'] = item
                                            buf = b''
                                            break
                                    edge = buf[-edge_len:]
                                    buf = fp_.read(buf_size).lower()
                        except (IOError, OSError) as exc:
                            log.error(
                                'Unable to read from init_bin (%s): %s',
                                init_bin, exc
                            )
                    elif salt.utils.path.which('supervisord') in init_cmdline:
                        grains['init'] = 'supervisord'
                    elif salt.utils.path.which('dumb-init') in init_cmdline:
                        # https://github.com/Yelp/dumb-init
                        grains['init'] = 'dumb-init'
                    elif salt.utils.path.which('tini') in init_cmdline:
                        # https://github.com/krallin/tini
                        grains['init'] = 'tini'
                    elif init_cmdline == ['runit']:
                        grains['init'] = 'runit'
                    elif '/sbin/my_init' in init_cmdline:
                        # Phusion Base docker container use runit for srv mgmt, but
                        # my_init as pid1
                        grains['init'] = 'runit'
                    else:
                        log.debug(
                            'Could not determine init system from command line: (%s)',
                            ' '.join(init_cmdline)
                        )
    
            # Add lsb grains on any distro with lsb-release. Note that this import
            # can fail on systems with lsb-release installed if the system package
            # does not install the python package for the python interpreter used by
            # Salt (i.e. python2 or python3)
            try:
                log.trace('Getting lsb_release distro information')
                import lsb_release  # pylint: disable=import-error
                release = lsb_release.get_distro_information()
                for key, value in six.iteritems(release):
                    key = key.lower()
                    lsb_param = 'lsb_{0}{1}'.format(
                        '' if key.startswith('distrib_') else 'distrib_',
                        key
                    )
                    grains[lsb_param] = value
            # Catch a NameError to workaround possible breakage in lsb_release
            # See https://github.com/saltstack/salt/issues/37867
            except (ImportError, NameError):
                # if the python library isn't available, try to parse
                # /etc/lsb-release using regex
                log.trace('lsb_release python bindings not available')
                grains.update(_parse_lsb_release())
    
                if grains.get('lsb_distrib_description', '').lower().startswith('antergos'):
                    # Antergos incorrectly configures their /etc/lsb-release,
                    # setting the DISTRIB_ID to "Arch". This causes the "os" grain
                    # to be incorrectly set to "Arch".
                    grains['osfullname'] = 'Antergos Linux'
                elif 'lsb_distrib_id' not in grains:
                    log.trace(
                        'Failed to get lsb_distrib_id, trying to parse os-release'
                    )
                    os_release = _parse_os_release('/etc/os-release', '/usr/lib/os-release')
                    if os_release:
                        if 'NAME' in os_release:
                            grains['lsb_distrib_id'] = os_release['NAME'].strip()
                        if 'VERSION_ID' in os_release:
                            grains['lsb_distrib_release'] = os_release['VERSION_ID']
                        if 'VERSION_CODENAME' in os_release:
                            grains['lsb_distrib_codename'] = os_release['VERSION_CODENAME']
                        elif 'PRETTY_NAME' in os_release:
                            codename = os_release['PRETTY_NAME']
                            # https://github.com/saltstack/salt/issues/44108
                            if os_release['ID'] == 'debian':
                                codename_match = re.search(r'\((\w+)\)$', codename)
                                if codename_match:
                                    codename = codename_match.group(1)
                            grains['lsb_distrib_codename'] = codename
                        if 'CPE_NAME' in os_release:
                            cpe = _parse_cpe_name(os_release['CPE_NAME'])
                            if not cpe:
                                log.error('Broken CPE_NAME format in /etc/os-release!')
                            elif cpe.get('vendor', '').lower() in ['suse', 'opensuse']:
                                grains['os'] = "SUSE"
                                # openSUSE `osfullname` grain normalization
                                if os_release.get("NAME") == "openSUSE Leap":
                                    grains['osfullname'] = "Leap"
                                elif os_release.get("VERSION") == "Tumbleweed":
                                    grains['osfullname'] = os_release["VERSION"]
                                # Override VERSION_ID, if CPE_NAME around
                                if cpe.get('version') and cpe.get('vendor') == 'opensuse':  # Keep VERSION_ID for SLES
                                    grains['lsb_distrib_release'] = cpe['version']
    
                    elif os.path.isfile('/etc/SuSE-release'):
                        log.trace('Parsing distrib info from /etc/SuSE-release')
                        grains['lsb_distrib_id'] = 'SUSE'
                        version = ''
                        patch = ''
                        with salt.utils.files.fopen('/etc/SuSE-release') as fhr:
                            for line in fhr:
                                if 'enterprise' in line.lower():
                                    grains['lsb_distrib_id'] = 'SLES'
                                    grains['lsb_distrib_codename'] = re.sub(r'\(.+\)', '', line).strip()
                                elif 'version' in line.lower():
                                    version = re.sub(r'[^0-9]', '', line)
                                elif 'patchlevel' in line.lower():
                                    patch = re.sub(r'[^0-9]', '', line)
                        grains['lsb_distrib_release'] = version
                        if patch:
                            grains['lsb_distrib_release'] += '.' + patch
                            patchstr = 'SP' + patch
                            if grains['lsb_distrib_codename'] and patchstr not in grains['lsb_distrib_codename']:
                                grains['lsb_distrib_codename'] += ' ' + patchstr
                        if not grains.get('lsb_distrib_codename'):
                            grains['lsb_distrib_codename'] = 'n.a'
                    elif os.path.isfile('/etc/altlinux-release'):
                        log.trace('Parsing distrib info from /etc/altlinux-release')
                        # ALT Linux
                        grains['lsb_distrib_id'] = 'altlinux'
                        with salt.utils.files.fopen('/etc/altlinux-release') as ifile:
                            # This file is symlinked to from:
                            #     /etc/fedora-release
                            #     /etc/redhat-release
                            #     /etc/system-release
                            for line in ifile:
                                # ALT Linux Sisyphus (unstable)
                                comps = line.split()
                                if comps[0] == 'ALT':
                                    grains['lsb_distrib_release'] = comps[2]
                                    grains['lsb_distrib_codename'] = \
                                        comps[3].replace('(', '').replace(')', '')
                    elif os.path.isfile('/etc/centos-release'):
                        log.trace('Parsing distrib info from /etc/centos-release')
                        # Maybe CentOS Linux; could also be SUSE Expanded Support.
                        # SUSE ES has both, centos-release and redhat-release.
                        if os.path.isfile('/etc/redhat-release'):
                            with salt.utils.files.fopen('/etc/redhat-release') as ifile:
                                for line in ifile:
                                    if "red hat enterprise linux server" in line.lower():
                                        # This is a SUSE Expanded Support Rhel installation
                                        grains['lsb_distrib_id'] = 'RedHat'
                                        break
                        grains.setdefault('lsb_distrib_id', 'CentOS')
                        with salt.utils.files.fopen('/etc/centos-release') as ifile:
                            for line in ifile:
                                # Need to pull out the version and codename
                                # in the case of custom content in /etc/centos-release
                                find_release = re.compile(r'\d+\.\d+')
                                find_codename = re.compile(r'(?<=\()(.*?)(?=\))')
                                release = find_release.search(line)
                                codename = find_codename.search(line)
                                if release is not None:
                                    grains['lsb_distrib_release'] = release.group()
                                if codename is not None:
                                    grains['lsb_distrib_codename'] = codename.group()
                    elif os.path.isfile('/etc.defaults/VERSION') \
                            and os.path.isfile('/etc.defaults/synoinfo.conf'):
                        grains['osfullname'] = 'Synology'
                        log.trace(
                            'Parsing Synology distrib info from /etc/.defaults/VERSION'
                        )
                        with salt.utils.files.fopen('/etc.defaults/VERSION', 'r') as fp_:
                            synoinfo = {}
                            for line in fp_:
                                try:
                                    key, val = line.rstrip('\n').split('=')
                                except ValueError:
                                    continue
                                if key in ('majorversion', 'minorversion',
                                           'buildnumber'):
                                    synoinfo[key] = val.strip('"')
                            if len(synoinfo) != 3:
                                log.warning(
                                    'Unable to determine Synology version info. '
                                    'Please report this, as it is likely a bug.'
                                )
                            else:
                                grains['osrelease'] = (
                                    '{majorversion}.{minorversion}-{buildnumber}'
                                    .format(**synoinfo)
                                )
    
            # Use the already intelligent platform module to get distro info
            # (though apparently it's not intelligent enough to strip quotes)
            log.trace(
                'Getting OS name, release, and codename from '
                'distro.linux_distribution()'
            )
            (osname, osrelease, oscodename) = \
                [x.strip('"').strip("'") for x in
                 linux_distribution(supported_dists=_supported_dists)]
            # Try to assign these three names based on the lsb info, they tend to
            # be more accurate than what python gets from /etc/DISTRO-release.
            # It's worth noting that Ubuntu has patched their Python distribution
            # so that linux_distribution() does the /etc/lsb-release parsing, but
            # we do it anyway here for the sake for full portability.
            if 'osfullname' not in grains:
                # If NI Linux RT distribution, set the grains['osfullname'] to 'nilrt'
                if grains.get('lsb_distrib_id', '').lower().startswith('nilrt'):
                    grains['osfullname'] = 'nilrt'
                else:
                    grains['osfullname'] = grains.get('lsb_distrib_id', osname).strip()
            if 'osrelease' not in grains:
                # NOTE: This is a workaround for CentOS 7 os-release bug
                # https://bugs.centos.org/view.php?id=8359
                # /etc/os-release contains no minor distro release number so we fall back to parse
                # /etc/centos-release file instead.
                # Commit introducing this comment should be reverted after the upstream bug is released.
                if 'CentOS Linux 7' in grains.get('lsb_distrib_codename', ''):
                    grains.pop('lsb_distrib_release', None)
                grains['osrelease'] = grains.get('lsb_distrib_release', osrelease).strip()
            grains['oscodename'] = grains.get('lsb_distrib_codename', '').strip() or oscodename
            if 'Red Hat' in grains['oscodename']:
                grains['oscodename'] = oscodename
            distroname = _REPLACE_LINUX_RE.sub('', grains['osfullname']).strip()
            # return the first ten characters with no spaces, lowercased
            shortname = distroname.replace(' ', '').lower()[:10]
            # this maps the long names from the /etc/DISTRO-release files to the
            # traditional short names that Salt has used.
            if 'os' not in grains:
                grains['os'] = _OS_NAME_MAP.get(shortname, distroname)
            grains.update(_linux_cpudata())
            grains.update(_linux_gpu_data())
        elif grains['kernel'] == 'SunOS':
            if salt.utils.platform.is_smartos():
                # See https://github.com/joyent/smartos-live/issues/224
                if HAS_UNAME:
                    uname_v = os.uname()[3]  # format: joyent_20161101T004406Z
                else:
                    uname_v = os.name
                uname_v = uname_v[uname_v.index('_')+1:]
                grains['os'] = grains['osfullname'] = 'SmartOS'
                # store a parsed version of YYYY.MM.DD as osrelease
                grains['osrelease'] = ".".join([
                    uname_v.split('T')[0][0:4],
                    uname_v.split('T')[0][4:6],
                    uname_v.split('T')[0][6:8],
                ])
                # store a untouched copy of the timestamp in osrelease_stamp
                grains['osrelease_stamp'] = uname_v
            elif os.path.isfile('/etc/release'):
                with salt.utils.files.fopen('/etc/release', 'r') as fp_:
                    rel_data = fp_.read()
                    try:
                        release_re = re.compile(
                            r'((?:Open|Oracle )?Solaris|OpenIndiana|OmniOS) (Development)?'
                            r'\s*(\d+\.?\d*|v\d+)\s?[A-Z]*\s?(r\d+|\d+\/\d+|oi_\S+|snv_\S+)?'
                        )
                        osname, development, osmajorrelease, osminorrelease = release_re.search(rel_data).groups()
                    except AttributeError:
                        # Set a blank osrelease grain and fallback to 'Solaris'
                        # as the 'os' grain.
                        grains['os'] = grains['osfullname'] = 'Solaris'
                        grains['osrelease'] = ''
                    else:
                        if development is not None:
                            osname = ' '.join((osname, development))
                        if HAS_UNAME:
                            uname_v = os.uname()[3]
                        else:
                            uname_v = os.name
                        grains['os'] = grains['osfullname'] = osname
                        if osname in ['Oracle Solaris'] and uname_v.startswith(osmajorrelease):
                            # Oracla Solars 11 and up have minor version in uname
                            grains['osrelease'] = uname_v
                        elif osname in ['OmniOS']:
                            # OmniOS
                            osrelease = []
                            osrelease.append(osmajorrelease[1:])
                            osrelease.append(osminorrelease[1:])
                            grains['osrelease'] = ".".join(osrelease)
                            grains['osrelease_stamp'] = uname_v
                        else:
                            # Sun Solaris 10 and earlier/comparable
                            osrelease = []
                            osrelease.append(osmajorrelease)
                            if osminorrelease:
                                osrelease.append(osminorrelease)
                            grains['osrelease'] = ".".join(osrelease)
                            grains['osrelease_stamp'] = uname_v
    
            grains.update(_sunos_cpudata())
        elif grains['kernel'] == 'VMkernel':
            grains['os'] = 'ESXi'
        elif grains['kernel'] == 'Darwin':
            osrelease = __salt__['cmd.run']('sw_vers -productVersion')
            osname = __salt__['cmd.run']('sw_vers -productName')
            osbuild = __salt__['cmd.run']('sw_vers -buildVersion')
            grains['os'] = 'MacOS'
            grains['os_family'] = 'MacOS'
            grains['osfullname'] = "{0} {1}".format(osname, osrelease)
            grains['osrelease'] = osrelease
            grains['osbuild'] = osbuild
            grains['init'] = 'launchd'
            grains.update(_bsd_cpudata(grains))
            grains.update(_osx_gpudata())
            grains.update(_osx_platform_data())
        elif grains['kernel'] == 'AIX':
            osrelease = __salt__['cmd.run']('oslevel')
            osrelease_techlevel = __salt__['cmd.run']('oslevel -r')
            osname = __salt__['cmd.run']('uname')
            grains['os'] = 'AIX'
            grains['osfullname'] = osname
            grains['osrelease'] = osrelease
            grains['osrelease_techlevel'] = osrelease_techlevel
            grains.update(_aix_cpudata())
        else:
            grains['os'] = grains['kernel']
        if grains['kernel'] == 'FreeBSD':
            try:
                grains['osrelease'] = __salt__['cmd.run']('freebsd-version -u').split('-')[0]
            except salt.exceptions.CommandExecutionError:
                # freebsd-version was introduced in 10.0.
                # derive osrelease from kernelversion prior to that
                grains['osrelease'] = grains['kernelrelease'].split('-')[0]
            grains.update(_bsd_cpudata(grains))
        if grains['kernel'] in ('OpenBSD', 'NetBSD'):
            grains.update(_bsd_cpudata(grains))
            grains['osrelease'] = grains['kernelrelease'].split('-')[0]
            if grains['kernel'] == 'NetBSD':
                grains.update(_netbsd_gpu_data())
        if not grains['os']:
            grains['os'] = 'Unknown {0}'.format(grains['kernel'])
            grains['os_family'] = 'Unknown'
        else:
            # this assigns family names based on the os name
            # family defaults to the os name if not found
            grains['os_family'] = _OS_FAMILY_MAP.get(grains['os'],
                                                     grains['os'])
    
        # Build the osarch grain. This grain will be used for platform-specific
        # considerations such as package management. Fall back to the CPU
        # architecture.
        if grains.get('os_family') == 'Debian':
            osarch = __salt__['cmd.run']('dpkg --print-architecture').strip()
        elif grains.get('os_family') in ['RedHat', 'Suse']:
            osarch = salt.utils.pkg.rpm.get_osarch()
        elif grains.get('os_family') in ('NILinuxRT', 'Poky'):
            archinfo = {}
            for line in __salt__['cmd.run']('opkg print-architecture').splitlines():
                if line.startswith('arch'):
                    _, arch, priority = line.split()
                    archinfo[arch.strip()] = int(priority.strip())
    
            # Return osarch in priority order (higher to lower)
            osarch = sorted(archinfo, key=archinfo.get, reverse=True)
        else:
            osarch = grains['cpuarch']
        grains['osarch'] = osarch
    
        grains.update(_memdata(grains))
    
        # Get the hardware and bios data
        grains.update(_hw_data(grains))
    
        # Load the virtual machine info
        grains.update(_virtual(grains))
        grains.update(_virtual_hv(grains))
        grains.update(_ps(grains))
    
        if grains.get('osrelease', ''):
            osrelease_info = grains['osrelease'].split('.')
            for idx, value in enumerate(osrelease_info):
                if not value.isdigit():
                    continue
                osrelease_info[idx] = int(value)
            grains['osrelease_info'] = tuple(osrelease_info)
            try:
                grains['osmajorrelease'] = int(grains['osrelease_info'][0])
            except (IndexError, TypeError, ValueError):
                log.debug(
                    'Unable to derive osmajorrelease from osrelease_info \'%s\'. '
                    'The osmajorrelease grain will not be set.',
                    grains['osrelease_info']
                )
            os_name = grains['os' if grains.get('os') in (
                'Debian', 'FreeBSD', 'OpenBSD', 'NetBSD', 'Mac', 'Raspbian') else 'osfullname']
            grains['osfinger'] = '{0}-{1}'.format(
                os_name, grains['osrelease'] if os_name in ('Ubuntu',) else grains['osrelease_info'][0])
    
        return grains
class Locale_info(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Provides
            defaultlanguage
            defaultencoding
        '''
        grains = {}
        grains['locale_info'] = {}
    
        if salt.utils.platform.is_proxy():
            return grains
    
        try:
            (
                grains['locale_info']['defaultlanguage'],
                grains['locale_info']['defaultencoding']
            ) = locale.getdefaultlocale()
        except Exception:
            # locale.getdefaultlocale can ValueError!! Catch anything else it
            # might do, per #2205
            grains['locale_info']['defaultlanguage'] = 'unknown'
            grains['locale_info']['defaultencoding'] = 'unknown'
        grains['locale_info']['detectedencoding'] = __salt_system_encoding__
        if _DATEUTIL_TZ:
            grains['locale_info']['timezone'] = datetime.datetime.now(dateutil.tz.tzlocal()).tzname()
        return grains
class Hostname(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return fqdn, hostname, domainname
        '''
        # This is going to need some work
        # Provides:
        #   fqdn
        #   host
        #   localhost
        #   domain
        global __FQDN__
        grains = {}
    
        if salt.utils.platform.is_proxy():
            return grains
    
        grains['localhost'] = socket.gethostname()
        if __FQDN__ is None:
            __FQDN__ = salt.utils.network.get_fqhostname()
    
        # On some distros (notably FreeBSD) if there is no hostname set
        # salt.utils.network.get_fqhostname() will return None.
        # In this case we punt and log a message at error level, but force the
        # hostname and domain to be localhost.localdomain
        # Otherwise we would stacktrace below
        if __FQDN__ is None:   # still!
            log.error('Having trouble getting a hostname.  Does this machine have its hostname and domain set properly?')
            __FQDN__ = 'localhost.localdomain'
    
        grains['fqdn'] = __FQDN__
        (grains['host'], grains['domain']) = grains['fqdn'].partition('.')[::2]
        return grains
class Append_domain(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return append_domain if set
        '''
    
        grain = {}
    
        if salt.utils.platform.is_proxy():
            return grain
    
        if 'append_domain' in __opts__:
            grain['append_domain'] = __opts__['append_domain']
        return grain
class Fqdns(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return all known FQDNs for the system by enumerating all interfaces and
        then trying to reverse resolve them (excluding 'lo' interface).
        '''
        # Provides:
        # fqdns
    
        grains = {}
        fqdns = set()
    
        addresses = salt.utils.network.ip_addrs(include_loopback=False, interface_data=_get_interfaces())
        addresses.extend(salt.utils.network.ip_addrs6(include_loopback=False, interface_data=_get_interfaces()))
        err_message = 'Exception during resolving address: %s'
        for ip in addresses:
            try:
                name, aliaslist, addresslist = socket.gethostbyaddr(ip)
                fqdns.update([socket.getfqdn(name)] + [als for als in aliaslist if salt.utils.network.is_fqdn(als)])
            except socket.herror as err:
                if err.errno == 0:
                    # No FQDN for this IP address, so we don't need to know this all the time.
                    log.debug("Unable to resolve address %s: %s", ip, err)
                else:
                    log.error(err_message, err)
            except (socket.error, socket.gaierror, socket.timeout) as err:
                log.error(err_message, err)
    
        return {"fqdns": sorted(list(fqdns))}
class Ip_fqdn(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return ip address and FQDN grains
        '''
        if salt.utils.platform.is_proxy():
            return {}
    
        ret = {}
        ret['ipv4'] = salt.utils.network.ip_addrs(include_loopback=True)
        ret['ipv6'] = salt.utils.network.ip_addrs6(include_loopback=True)
    
        _fqdn = hostname()['fqdn']
        for socket_type, ipv_num in ((socket.AF_INET, '4'), (socket.AF_INET6, '6')):
            key = 'fqdn_ip' + ipv_num
            if not ret['ipv' + ipv_num]:
                ret[key] = []
            else:
                try:
                    start_time = datetime.datetime.utcnow()
                    info = socket.getaddrinfo(_fqdn, None, socket_type)
                    ret[key] = list(set(item[4][0] for item in info))
                except socket.error:
                    timediff = datetime.datetime.utcnow() - start_time
                    if timediff.seconds > 5 and __opts__['__role'] == 'master':
                        log.warning(
                            'Unable to find IPv%s record for "%s" causing a %s '
                            'second timeout when rendering grains. Set the dns or '
                            '/etc/hosts for IPv%s to clear this.',
                            ipv_num, _fqdn, timediff, ipv_num
                        )
                    ret[key] = []
    
        return ret
class Ip_interfaces(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Provide a dict of the connected interfaces and their ip addresses
        The addresses will be passed as a list for each interface
        '''
        # Provides:
        #   ip_interfaces
    
        if salt.utils.platform.is_proxy():
            return {}
    
        ret = {}
        ifaces = _get_interfaces()
        for face in ifaces:
            iface_ips = []
            for inet in ifaces[face].get('inet', []):
                if 'address' in inet:
                    iface_ips.append(inet['address'])
            for inet in ifaces[face].get('inet6', []):
                if 'address' in inet:
                    iface_ips.append(inet['address'])
            for secondary in ifaces[face].get('secondary', []):
                if 'address' in secondary:
                    iface_ips.append(secondary['address'])
            ret[face] = iface_ips
        return {'ip_interfaces': ret}
class Hwaddr_interfaces(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Provide a dict of the connected interfaces and their
        hw addresses (Mac Address)
        '''
        # Provides:
        #   hwaddr_interfaces
        ret = {}
        ifaces = _get_interfaces()
        for face in ifaces:
            if 'hwaddr' in ifaces[face]:
                ret[face] = ifaces[face]['hwaddr']
        return {'hwaddr_interfaces': ret}
class Dns(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Parse the resolver configuration file
    
         .. versionadded:: 2016.3.0
        '''
        # Provides:
        #   dns
        if salt.utils.platform.is_windows() or 'proxyminion' in __opts__:
            return {}
    
        resolv = salt.utils.dns.parse_resolv()
        for key in ('nameservers', 'ip4_nameservers', 'ip6_nameservers',
                    'sortlist'):
            if key in resolv:
                resolv[key] = [six.text_type(i) for i in resolv[key]]
    
        return {'dns': resolv} if resolv else {}
class Get_machine_id(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Provide the machine-id for machine/virtualization combination
        '''
        # Provides:
        #   machine-id
        if platform.system() == 'AIX':
            return _aix_get_machine_id()
    
        locations = ['/etc/machine-id', '/var/lib/dbus/machine-id']
        existing_locations = [loc for loc in locations if os.path.exists(loc)]
        if not existing_locations:
            return {}
        else:
            with salt.utils.files.fopen(existing_locations[0]) as machineid:
                return {'machine_id': machineid.read().strip()}
class Saltpath(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the path of the salt module
        '''
        # Provides:
        #   saltpath
        salt_path = os.path.abspath(os.path.join(__file__, os.path.pardir))
        return {'saltpath': os.path.dirname(salt_path)}
class _hw_data(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, osdata):
        '''
        Get system specific hardware data from dmidecode
    
        Provides
            biosversion
            productname
            manufacturer
            serialnumber
            biosreleasedate
            uuid
    
        .. versionadded:: 0.9.5
        '''
    
        if salt.utils.platform.is_proxy():
            return {}
    
        grains = {}
        if osdata['kernel'] == 'Linux' and os.path.exists('/sys/class/dmi/id'):
            # On many Linux distributions basic firmware information is available via sysfs
            # requires CONFIG_DMIID to be enabled in the Linux kernel configuration
            sysfs_firmware_info = {
                'biosversion': 'bios_version',
                'productname': 'product_name',
                'manufacturer': 'sys_vendor',
                'biosreleasedate': 'bios_date',
                'uuid': 'product_uuid',
                'serialnumber': 'product_serial'
            }
            for key, fw_file in sysfs_firmware_info.items():
                contents_file = os.path.join('/sys/class/dmi/id', fw_file)
                if os.path.exists(contents_file):
                    try:
                        with salt.utils.files.fopen(contents_file, 'r') as ifile:
                            grains[key] = salt.utils.stringutils.to_unicode(ifile.read().strip(), errors='replace')
                            if key == 'uuid':
                                grains['uuid'] = grains['uuid'].lower()
                    except (IOError, OSError) as err:
                        # PermissionError is new to Python 3, but corresponds to the EACESS and
                        # EPERM error numbers. Use those instead here for PY2 compatibility.
                        if err.errno == EACCES or err.errno == EPERM:
                            # Skip the grain if non-root user has no access to the file.
                            pass
        elif salt.utils.path.which_bin(['dmidecode', 'smbios']) is not None and not (
                salt.utils.platform.is_smartos() or
                (  # SunOS on SPARC - 'smbios: failed to load SMBIOS: System does not export an SMBIOS table'
                    osdata['kernel'] == 'SunOS' and
                    osdata['cpuarch'].startswith('sparc')
                )):
            # On SmartOS (possibly SunOS also) smbios only works in the global zone
            # smbios is also not compatible with linux's smbios (smbios -s = print summarized)
            grains = {
                'biosversion': __salt__['smbios.get']('bios-version'),
                'productname': __salt__['smbios.get']('system-product-name'),
                'manufacturer': __salt__['smbios.get']('system-manufacturer'),
                'biosreleasedate': __salt__['smbios.get']('bios-release-date'),
                'uuid': __salt__['smbios.get']('system-uuid')
            }
            grains = dict([(key, val) for key, val in grains.items() if val is not None])
            uuid = __salt__['smbios.get']('system-uuid')
            if uuid is not None:
                grains['uuid'] = uuid.lower()
            for serial in ('system-serial-number', 'chassis-serial-number', 'baseboard-serial-number'):
                serial = __salt__['smbios.get'](serial)
                if serial is not None:
                    grains['serialnumber'] = serial
                    break
        elif salt.utils.path.which_bin(['fw_printenv']) is not None:
            # ARM Linux devices expose UBOOT env variables via fw_printenv
            hwdata = {
                'manufacturer': 'manufacturer',
                'serialnumber': 'serial#',
                'productname': 'DeviceDesc',
            }
            for grain_name, cmd_key in six.iteritems(hwdata):
                result = __salt__['cmd.run_all']('fw_printenv {0}'.format(cmd_key))
                if result['retcode'] == 0:
                    uboot_keyval = result['stdout'].split('=')
                    grains[grain_name] = _clean_value(grain_name, uboot_keyval[1])
        elif osdata['kernel'] == 'FreeBSD':
            # On FreeBSD /bin/kenv (already in base system)
            # can be used instead of dmidecode
            kenv = salt.utils.path.which('kenv')
            if kenv:
                # In theory, it will be easier to add new fields to this later
                fbsd_hwdata = {
                    'biosversion': 'smbios.bios.version',
                    'manufacturer': 'smbios.system.maker',
                    'serialnumber': 'smbios.system.serial',
                    'productname': 'smbios.system.product',
                    'biosreleasedate': 'smbios.bios.reldate',
                    'uuid': 'smbios.system.uuid',
                }
                for key, val in six.iteritems(fbsd_hwdata):
                    value = __salt__['cmd.run']('{0} {1}'.format(kenv, val))
                    grains[key] = _clean_value(key, value)
        elif osdata['kernel'] == 'OpenBSD':
            sysctl = salt.utils.path.which('sysctl')
            hwdata = {'biosversion': 'hw.version',
                      'manufacturer': 'hw.vendor',
                      'productname': 'hw.product',
                      'serialnumber': 'hw.serialno',
                      'uuid': 'hw.uuid'}
            for key, oid in six.iteritems(hwdata):
                value = __salt__['cmd.run']('{0} -n {1}'.format(sysctl, oid))
                if not value.endswith(' value is not available'):
                    grains[key] = _clean_value(key, value)
        elif osdata['kernel'] == 'NetBSD':
            sysctl = salt.utils.path.which('sysctl')
            nbsd_hwdata = {
                'biosversion': 'machdep.dmi.board-version',
                'manufacturer': 'machdep.dmi.system-vendor',
                'serialnumber': 'machdep.dmi.system-serial',
                'productname': 'machdep.dmi.system-product',
                'biosreleasedate': 'machdep.dmi.bios-date',
                'uuid': 'machdep.dmi.system-uuid',
            }
            for key, oid in six.iteritems(nbsd_hwdata):
                result = __salt__['cmd.run_all']('{0} -n {1}'.format(sysctl, oid))
                if result['retcode'] == 0:
                    grains[key] = _clean_value(key, result['stdout'])
        elif osdata['kernel'] == 'Darwin':
            grains['manufacturer'] = 'Apple Inc.'
            sysctl = salt.utils.path.which('sysctl')
            hwdata = {'productname': 'hw.model'}
            for key, oid in hwdata.items():
                value = __salt__['cmd.run']('{0} -b {1}'.format(sysctl, oid))
                if not value.endswith(' is invalid'):
                    grains[key] = _clean_value(key, value)
        elif osdata['kernel'] == 'SunOS' and osdata['cpuarch'].startswith('sparc'):
            # Depending on the hardware model, commands can report different bits
            # of information.  With that said, consolidate the output from various
            # commands and attempt various lookups.
            data = ""
            for (cmd, args) in (('/usr/sbin/prtdiag', '-v'), ('/usr/sbin/prtconf', '-vp'), ('/usr/sbin/virtinfo', '-a')):
                if salt.utils.path.which(cmd):  # Also verifies that cmd is executable
                    data += __salt__['cmd.run']('{0} {1}'.format(cmd, args))
                    data += '\n'
    
            sn_regexes = [
                re.compile(r) for r in [
                    r'(?im)^\s*Chassis\s+Serial\s+Number\n-+\n(\S+)',  # prtdiag
                    r'(?im)^\s*chassis-sn:\s*(\S+)',  # prtconf
                    r'(?im)^\s*Chassis\s+Serial#:\s*(\S+)',  # virtinfo
                ]
            ]
    
            obp_regexes = [
                re.compile(r) for r in [
                    r'(?im)^\s*System\s+PROM\s+revisions.*\nVersion\n-+\nOBP\s+(\S+)\s+(\S+)',  # prtdiag
                    r'(?im)^\s*version:\s*\'OBP\s+(\S+)\s+(\S+)',  # prtconf
                ]
            ]
    
            fw_regexes = [
                re.compile(r) for r in [
                    r'(?im)^\s*Sun\s+System\s+Firmware\s+(\S+)\s+(\S+)',  # prtdiag
                ]
            ]
    
            uuid_regexes = [
                re.compile(r) for r in [
                    r'(?im)^\s*Domain\s+UUID:\s*(\S+)',  # virtinfo
                ]
            ]
    
            manufacture_regexes = [
                re.compile(r) for r in [
                    r'(?im)^\s*System\s+Configuration:\s*(.*)(?=sun)',  # prtdiag
                ]
            ]
    
            product_regexes = [
                re.compile(r) for r in [
                    r'(?im)^\s*System\s+Configuration:\s*.*?sun\d\S+[^\S\r\n]*(.*)',  # prtdiag
                    r'(?im)^[^\S\r\n]*banner-name:[^\S\r\n]*(.*)',  # prtconf
                    r'(?im)^[^\S\r\n]*product-name:[^\S\r\n]*(.*)',  # prtconf
                ]
            ]
    
            sn_regexes = [
                re.compile(r) for r in [
                    r'(?im)Chassis\s+Serial\s+Number\n-+\n(\S+)',  # prtdiag
                    r'(?i)Chassis\s+Serial#:\s*(\S+)',  # virtinfo
                    r'(?i)chassis-sn:\s*(\S+)',  # prtconf
                ]
            ]
    
            obp_regexes = [
                re.compile(r) for r in [
                    r'(?im)System\s+PROM\s+revisions.*\nVersion\n-+\nOBP\s+(\S+)\s+(\S+)',  # prtdiag
                    r'(?im)version:\s*\'OBP\s+(\S+)\s+(\S+)',  # prtconf
                ]
            ]
    
            fw_regexes = [
                re.compile(r) for r in [
                    r'(?i)Sun\s+System\s+Firmware\s+(\S+)\s+(\S+)',  # prtdiag
                ]
            ]
    
            uuid_regexes = [
                re.compile(r) for r in [
                    r'(?i)Domain\s+UUID:\s+(\S+)',  # virtinfo
                ]
            ]
    
            for regex in sn_regexes:
                res = regex.search(data)
                if res and len(res.groups()) >= 1:
                    grains['serialnumber'] = res.group(1).strip().replace("'", "")
                    break
    
            for regex in obp_regexes:
                res = regex.search(data)
                if res and len(res.groups()) >= 1:
                    obp_rev, obp_date = res.groups()[0:2]  # Limit the number in case we found the data in multiple places
                    grains['biosversion'] = obp_rev.strip().replace("'", "")
                    grains['biosreleasedate'] = obp_date.strip().replace("'", "")
    
            for regex in fw_regexes:
                res = regex.search(data)
                if res and len(res.groups()) >= 1:
                    fw_rev, fw_date = res.groups()[0:2]
                    grains['systemfirmware'] = fw_rev.strip().replace("'", "")
                    grains['systemfirmwaredate'] = fw_date.strip().replace("'", "")
                    break
    
            for regex in uuid_regexes:
                res = regex.search(data)
                if res and len(res.groups()) >= 1:
                    grains['uuid'] = res.group(1).strip().replace("'", "")
                    break
    
            for regex in manufacture_regexes:
                res = regex.search(data)
                if res and len(res.groups()) >= 1:
                    grains['manufacture'] = res.group(1).strip().replace("'", "")
                    break
    
            for regex in product_regexes:
                res = regex.search(data)
                if res and len(res.groups()) >= 1:
                    t_productname = res.group(1).strip().replace("'", "")
                    if t_productname:
                        grains['product'] = t_productname
                        grains['productname'] = t_productname
                        break
        elif osdata['kernel'] == 'AIX':
            cmd = salt.utils.path.which('prtconf')
            if cmd:
                data = __salt__['cmd.run']('{0}'.format(cmd)) + os.linesep
                for dest, regstring in (('serialnumber', r'(?im)^\s*Machine\s+Serial\s+Number:\s+(\S+)'),
                                        ('systemfirmware', r'(?im)^\s*Firmware\s+Version:\s+(.*)')):
                    for regex in [re.compile(r) for r in [regstring]]:
                        res = regex.search(data)
                        if res and len(res.groups()) >= 1:
                            grains[dest] = res.group(1).strip().replace("'", '')
    
                product_regexes = [re.compile(r'(?im)^\s*System\s+Model:\s+(\S+)')]
                for regex in product_regexes:
                    res = regex.search(data)
                    if res and len(res.groups()) >= 1:
                        grains['manufacturer'], grains['productname'] = res.group(1).strip().replace("'", "").split(",")
                        break
            else:
                log.error('The \'prtconf\' binary was not found in $PATH.')
    
        elif osdata['kernel'] == 'AIX':
            cmd = salt.utils.path.which('prtconf')
            if data:
                data = __salt__['cmd.run']('{0}'.format(cmd)) + os.linesep
                for dest, regstring in (('serialnumber', r'(?im)^\s*Machine\s+Serial\s+Number:\s+(\S+)'),
                                        ('systemfirmware', r'(?im)^\s*Firmware\s+Version:\s+(.*)')):
                    for regex in [re.compile(r) for r in [regstring]]:
                        res = regex.search(data)
                        if res and len(res.groups()) >= 1:
                            grains[dest] = res.group(1).strip().replace("'", '')
    
                product_regexes = [re.compile(r'(?im)^\s*System\s+Model:\s+(\S+)')]
                for regex in product_regexes:
                    res = regex.search(data)
                    if res and len(res.groups()) >= 1:
                        grains['manufacturer'], grains['productname'] = res.group(1).strip().replace("'", "").split(",")
                        break
            else:
                log.error('The \'prtconf\' binary was not found in $PATH.')
    
        return grains
class _get_hash_by_shell(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Shell-out Python 3 for compute reliable hash
        :return:
        '''
        id_ = __opts__.get('id', '')
        id_hash = None
        py_ver = sys.version_info[:2]
        if py_ver >= (3, 3):
            # Python 3.3 enabled hash randomization, so we need to shell out to get
            # a reliable hash.
            id_hash = __salt__['cmd.run']([sys.executable, '-c', 'print(hash("{0}"))'.format(id_)],
                                          env={'PYTHONHASHSEED': '0'})
            try:
                id_hash = int(id_hash)
            except (TypeError, ValueError):
                log.debug('Failed to hash the ID to get the server_id grain. Result of hash command: %s', id_hash)
                id_hash = None
        if id_hash is None:
            # Python < 3.3 or error encountered above
            id_hash = hash(id_)
    
        return abs(id_hash % (2 ** 31))
class Get_server_id(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Provides an integer based on the FQDN of a machine.
        Useful as server-id in MySQL replication or anywhere else you'll need an ID
        like this.
        '''
        # Provides:
        #   server_id
    
        if salt.utils.platform.is_proxy():
            server_id = {}
        else:
            use_crc = __opts__.get('server_id_use_crc')
            if bool(use_crc):
                id_hash = getattr(zlib, use_crc, zlib.adler32)(__opts__.get('id', '').encode()) & 0xffffffff
            else:
                log.debug('This server_id is computed not by Adler32 nor by CRC32. '
                          'Please use "server_id_use_crc" option and define algorithm you '
                          'prefer (default "Adler32"). Starting with Sodium, the '
                          'server_id will be computed with Adler32 by default.')
                id_hash = _get_hash_by_shell()
            server_id = {'server_id': id_hash}
    
        return server_id
class Default_gateway(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Populates grains which describe whether a server has a default gateway
        configured or not. Uses `ip -4 route show` and `ip -6 route show` and greps
        for a `default` at the beginning of any line. Assuming the standard
        `default via <ip>` format for default gateways, it will also parse out the
        ip address of the default gateway, and put it in ip4_gw or ip6_gw.
    
        If the `ip` command is unavailable, no grains will be populated.
    
        Currently does not support multiple default gateways. The grains will be
        set to the first default gateway found.
    
        List of grains:
    
            ip4_gw: True  # ip/True/False if default ipv4 gateway
            ip6_gw: True  # ip/True/False if default ipv6 gateway
            ip_gw: True   # True if either of the above is True, False otherwise
        '''
        grains = {}
        ip_bin = salt.utils.path.which('ip')
        if not ip_bin:
            return {}
        grains['ip_gw'] = False
        grains['ip4_gw'] = False
        grains['ip6_gw'] = False
        for ip_version in ('4', '6'):
            try:
                out = __salt__['cmd.run']([ip_bin, '-' + ip_version, 'route', 'show'])
                for line in out.splitlines():
                    if line.startswith('default'):
                        grains['ip_gw'] = True
                        grains['ip{0}_gw'.format(ip_version)] = True
                        try:
                            via, gw_ip = line.split()[1:3]
                        except ValueError:
                            pass
                        else:
                            if via == 'via':
                                grains['ip{0}_gw'.format(ip_version)] = gw_ip
                        break
            except Exception:
                continue
        return grains
class Kernelparams(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the kernel boot parameters
        '''
        if salt.utils.platform.is_windows():
            # TODO: add grains using `bcdedit /enum {current}`
            return {}
        else:
            try:
                with salt.utils.files.fopen('/proc/cmdline', 'r') as fhr:
                    cmdline = fhr.read()
                    grains = {'kernelparams': []}
                    for data in [item.split('=') for item in salt.utils.args.shlex_split(cmdline)]:
                        value = None
                        if len(data) == 2:
                            value = data[1].strip('"')
    
                        grains['kernelparams'] += [(data[0], value)]
            except IOError as exc:
                grains = {}
                log.debug('Failed to read /proc/cmdline: %s', exc)
    
            return grains
class _table_attrs(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, table):
        '''
        Helper function to find valid table attributes
        '''
        cmd = ['osqueryi'] + ['--json'] + ['pragma table_info({0})'.format(table)]
        res = __salt__['cmd.run_all'](cmd)
        if res['retcode'] == 0:
            attrs = []
            text = salt.utils.json.loads(res['stdout'])
            for item in text:
                attrs.append(item['name'])
            return attrs
        return False
class Version(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return version of osquery
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' osquery.version
        '''
        _false_return = {'result': False,
                         'comment': 'OSQuery version unavailable.'}
        res = _osquery_cmd(table='osquery_info', attrs=['version'])
        if 'result' in res and res['result']:
            if 'data' in res and isinstance(res['data'], list):
                return res['data'][0].get('version', '') or _false_return
        return _false_return
class Beacon(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, config):
        '''
        Emit the status of all devices returned by adb
    
        Specify the device states that should emit an event,
        there will be an event for each device with the
        event type and device specified.
    
        .. code-block:: yaml
    
            beacons:
              adb:
                - states:
                    - offline
                    - unauthorized
                    - missing
                - no_devices_event: True
                - battery_low: 25
    
        '''
    
        log.trace('adb beacon starting')
        ret = []
    
        _config = {}
        list(map(_config.update, config))
    
        out = __salt__['cmd.run']('adb devices', runas=_config.get('user', None))
    
        lines = out.split('\n')[1:]
        last_state_devices = list(last_state.keys())
        found_devices = []
    
        for line in lines:
            try:
                device, state = line.split('\t')
                found_devices.append(device)
                if device not in last_state_devices or \
                        ('state' in last_state[device] and last_state[device]['state'] != state):
                    if state in _config['states']:
                        ret.append({'device': device, 'state': state, 'tag': state})
                        last_state[device] = {'state': state}
    
                if 'battery_low' in _config:
                    val = last_state.get(device, {})
                    cmd = 'adb -s {0} shell cat /sys/class/power_supply/*/capacity'.format(device)
                    battery_levels = __salt__['cmd.run'](cmd, runas=_config.get('user', None)).split('\n')
    
                    for l in battery_levels:
                        battery_level = int(l)
                        if 0 < battery_level < 100:
                            if 'battery' not in val or battery_level != val['battery']:
                                if ('battery' not in val or val['battery'] > _config['battery_low']) and \
                                                battery_level <= _config['battery_low']:
                                    ret.append({'device': device, 'battery_level': battery_level, 'tag': 'battery_low'})
    
                            if device not in last_state:
                                last_state[device] = {}
    
                            last_state[device].update({'battery': battery_level})
    
            except ValueError:
                continue
    
        # Find missing devices and remove them / send an event
        for device in last_state_devices:
            if device not in found_devices:
                if 'missing' in _config['states']:
                    ret.append({'device': device, 'state': 'missing', 'tag': 'missing'})
    
                del last_state[device]
    
        # Maybe send an event if we don't have any devices
        if 'no_devices_event' in _config and _config['no_devices_event'] is True:
            if not found_devices and not last_state_extra['no_devices']:
                ret.append({'tag': 'no_devices'})
    
        # Did we have no devices listed this time around?
    
        last_state_extra['no_devices'] = not found_devices
    
        return ret
class Clear(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Clear the namespace from the register
    
        USAGE:
    
        .. code-block:: yaml
    
            clearns:
              reg.clear:
                - name: myregister
        '''
        ret = {'name': name,
               'changes': {},
               'comment': '',
               'result': True}
        if name in __reg__:
            __reg__[name].clear()
        return ret
class Delete(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Delete the namespace from the register
    
        USAGE:
    
        .. code-block:: yaml
    
            deletens:
              reg.delete:
                - name: myregister
        '''
        ret = {'name': name,
               'changes': {},
               'comment': '',
               'result': True}
        if name in __reg__:
            del __reg__[name]
        return ret
class Running_service_owners(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, exclude=('/dev','/home','/media','/proc','/run','/sys/','/tmp','/var')):
        '''
        Determine which packages own the currently running services. By default,
        excludes files whose full path starts with ``/dev``, ``/home``, ``/media``,
        ``/proc``, ``/run``, ``/sys``, ``/tmp`` and ``/var``. This can be
        overridden by passing in a new list to ``exclude``.
    
        CLI Example:
    
            salt myminion introspect.running_service_owners
        '''
        error = {}
        if 'pkg.owner' not in __salt__:
            error['Unsupported Package Manager'] = (
                'The module for the package manager on this system does not '
                'support looking up which package(s) owns which file(s)'
            )
    
        if 'file.open_files' not in __salt__:
            error['Unsupported File Module'] = (
                'The file module on this system does not '
                'support looking up open files on the system'
            )
    
        if error:
            return {'Error': error}
    
        ret = {}
        open_files = __salt__['file.open_files']()
    
        execs = __salt__['service.execs']()
        for path in open_files:
            ignore = False
            for bad_dir in exclude:
                if path.startswith(bad_dir):
                    ignore = True
    
            if ignore:
                continue
    
            if not os.access(path, os.X_OK):
                continue
    
            for service in execs:
                if path == execs[service]:
                    pkg = __salt__['pkg.owner'](path)
                    ret[service] = next(six.itervalues(pkg))
    
        return ret
class Enabled_service_owners(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return which packages own each of the services that are currently enabled.
    
        CLI Example:
    
            salt myminion introspect.enabled_service_owners
        '''
        error = {}
        if 'pkg.owner' not in __salt__:
            error['Unsupported Package Manager'] = (
                'The module for the package manager on this system does not '
                'support looking up which package(s) owns which file(s)'
            )
    
        if 'service.show' not in __salt__:
            error['Unsupported Service Manager'] = (
                'The module for the service manager on this system does not '
                'support showing descriptive service data'
            )
    
        if error:
            return {'Error': error}
    
        ret = {}
        services = __salt__['service.get_enabled']()
    
        for service in services:
            data = __salt__['service.show'](service)
            if 'ExecStart' not in data:
                continue
            start_cmd = data['ExecStart']['path']
            pkg = __salt__['pkg.owner'](start_cmd)
            ret[service] = next(six.itervalues(pkg))
    
        return ret
class Service_highstate(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, requires=True):
        '''
        Return running and enabled services in a highstate structure. By default
        also returns package dependencies for those services, which means that
        package definitions must be created outside this function. To drop the
        package dependencies, set ``requires`` to False.
    
        CLI Example:
    
            salt myminion introspect.service_highstate
            salt myminion introspect.service_highstate requires=False
        '''
        ret = {}
        running = running_service_owners()
        for service in running:
            ret[service] = {'service': ['running']}
    
            if requires:
                ret[service]['service'].append(
                    {'require': {'pkg': running[service]}}
                )
    
        enabled = enabled_service_owners()
        for service in enabled:
            if service in ret:
                ret[service]['service'].append({'enabled': True})
            else:
                ret[service] = {'service': [{'enabled': True}]}
    
            if requires:
                exists = False
                for item in ret[service]['service']:
                    if isinstance(item, dict) and next(six.iterkeys(item)) == 'require':
                        exists = True
                if not exists:
                    ret[service]['service'].append(
                        {'require': {'pkg': enabled[service]}}
                    )
    
        return ret
class _gather_buffer_space(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Gather some system data and then calculate
        buffer space.
    
        Result is in bytes.
        '''
        if HAS_PSUTIL and psutil.version_info >= (0, 6, 0):
            # Oh good, we have psutil. This will be quick.
            total_mem = psutil.virtual_memory().total
        else:
            # Avoid loading core grains unless absolutely required
            import platform
            import salt.grains.core
            # We need to load up ``mem_total`` grain. Let's mimic required OS data.
            os_data = {'kernel': platform.system()}
            grains = salt.grains.core._memdata(os_data)
            total_mem = grains['mem_total'] * 1024 * 1024
        # Return the higher number between 5% of the system memory and 10MiB
        return max([total_mem * 0.05, 10 << 20])
class _normalize_roots(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, file_roots):
        '''
        Normalize file or pillar roots.
        '''
        for saltenv, dirs in six.iteritems(file_roots):
            normalized_saltenv = six.text_type(saltenv)
            if normalized_saltenv != saltenv:
                file_roots[normalized_saltenv] = file_roots.pop(saltenv)
            if not isinstance(dirs, (list, tuple)):
                file_roots[normalized_saltenv] = []
            file_roots[normalized_saltenv] = \
                    _expand_glob_path(file_roots[normalized_saltenv])
        return file_roots
class _validate_pillar_roots(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, pillar_roots):
        '''
        If the pillar_roots option has a key that is None then we will error out,
        just replace it with an empty list
        '''
        if not isinstance(pillar_roots, dict):
            log.warning('The pillar_roots parameter is not properly formatted,'
                        ' using defaults')
            return {'base': _expand_glob_path([salt.syspaths.BASE_PILLAR_ROOTS_DIR])}
        return _normalize_roots(pillar_roots)
class _validate_file_roots(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, file_roots):
        '''
        If the file_roots option has a key that is None then we will error out,
        just replace it with an empty list
        '''
        if not isinstance(file_roots, dict):
            log.warning('The file_roots parameter is not properly formatted,'
                        ' using defaults')
            return {'base': _expand_glob_path([salt.syspaths.BASE_FILE_ROOTS_DIR])}
        return _normalize_roots(file_roots)
class _expand_glob_path(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, file_roots):
        '''
        Applies shell globbing to a set of directories and returns
        the expanded paths
        '''
        unglobbed_path = []
        for path in file_roots:
            try:
                if glob.has_magic(path):
                    unglobbed_path.extend(glob.glob(path))
                else:
                    unglobbed_path.append(path)
            except Exception:
                unglobbed_path.append(path)
        return unglobbed_path
class _validate_opts(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, opts):
        '''
        Check that all of the types of values passed into the config are
        of the right types
        '''
        def format_multi_opt(valid_type):
            try:
                num_types = len(valid_type)
            except TypeError:
                # Bare type name won't have a length, return the name of the type
                # passed.
                return valid_type.__name__
            else:
                def get_types(types, type_tuple):
                    for item in type_tuple:
                        if isinstance(item, tuple):
                            get_types(types, item)
                        else:
                            try:
                                types.append(item.__name__)
                            except AttributeError:
                                log.warning(
                                    'Unable to interpret type %s while validating '
                                    'configuration', item
                                )
                types = []
                get_types(types, valid_type)
    
                ret = ', '.join(types[:-1])
                ret += ' or ' + types[-1]
                return ret
    
        errors = []
    
        err = (
            'Config option \'{0}\' with value {1} has an invalid type of {2}, a '
            '{3} is required for this option'
        )
        for key, val in six.iteritems(opts):
            if key in VALID_OPTS:
                if val is None:
                    if VALID_OPTS[key] is None:
                        continue
                    else:
                        try:
                            if None in VALID_OPTS[key]:
                                continue
                        except TypeError:
                            # VALID_OPTS[key] is not iterable and not None
                            pass
    
                if isinstance(val, VALID_OPTS[key]):
                    continue
    
                # We don't know what data type sdb will return at run-time so we
                # simply cannot check it for correctness here at start-time.
                if isinstance(val, six.string_types) and val.startswith('sdb://'):
                    continue
    
                if hasattr(VALID_OPTS[key], '__call__'):
                    try:
                        VALID_OPTS[key](val)
                        if isinstance(val, (list, dict)):
                            # We'll only get here if VALID_OPTS[key] is str or
                            # bool, and the passed value is a list/dict. Attempting
                            # to run int() or float() on a list/dict will raise an
                            # exception, but running str() or bool() on it will
                            # pass despite not being the correct type.
                            errors.append(
                                err.format(
                                    key,
                                    val,
                                    type(val).__name__,
                                    VALID_OPTS[key].__name__
                                )
                            )
                    except (TypeError, ValueError):
                        errors.append(
                            err.format(key,
                                       val,
                                       type(val).__name__,
                                       VALID_OPTS[key].__name__)
                        )
                    continue
    
                errors.append(
                    err.format(key,
                               val,
                               type(val).__name__,
                               format_multi_opt(VALID_OPTS[key]))
                )
    
        # Convert list to comma-delimited string for 'return' config option
        if isinstance(opts.get('return'), list):
            opts['return'] = ','.join(opts['return'])
    
        for error in errors:
            log.warning(error)
        if errors:
            return False
        return True
class _validate_ssh_minion_opts(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, opts):
        '''
        Ensure we're not using any invalid ssh_minion_opts. We want to make sure
        that the ssh_minion_opts does not override any pillar or fileserver options
        inherited from the master config. To add other items, modify the if
        statement in the for loop below.
        '''
        ssh_minion_opts = opts.get('ssh_minion_opts', {})
        if not isinstance(ssh_minion_opts, dict):
            log.error('Invalidly-formatted ssh_minion_opts')
            opts.pop('ssh_minion_opts')
    
        for opt_name in list(ssh_minion_opts):
            if re.match('^[a-z0-9]+fs_', opt_name, flags=re.IGNORECASE) \
                    or ('pillar' in opt_name and not 'ssh_merge_pillar' == opt_name) \
                    or opt_name in ('fileserver_backend',):
                log.warning(
                    '\'%s\' is not a valid ssh_minion_opts parameter, ignoring',
                    opt_name
                )
                ssh_minion_opts.pop(opt_name)
class _append_domain(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, opts):
        '''
        Append a domain to the existing id if it doesn't already exist
        '''
        # Domain already exists
        if opts['id'].endswith(opts['append_domain']):
            return opts['id']
        # Trailing dot should mean an FQDN that is terminated, leave it alone.
        if opts['id'].endswith('.'):
            return opts['id']
        return '{0[id]}.{0[append_domain]}'.format(opts)
class _read_conf_file(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        Read in a config file from a given path and process it into a dictionary
        '''
        log.debug('Reading configuration from %s', path)
        with salt.utils.files.fopen(path, 'r') as conf_file:
            try:
                conf_opts = salt.utils.yaml.safe_load(conf_file) or {}
            except salt.utils.yaml.YAMLError as err:
                message = 'Error parsing configuration file: {0} - {1}'.format(path, err)
                log.error(message)
                raise salt.exceptions.SaltConfigurationError(message)
    
            # only interpret documents as a valid conf, not things like strings,
            # which might have been caused by invalid yaml syntax
            if not isinstance(conf_opts, dict):
                message = 'Error parsing configuration file: {0} - conf ' \
                          'should be a document, not {1}.'.format(path, type(conf_opts))
                log.error(message)
                raise salt.exceptions.SaltConfigurationError(message)
    
            # allow using numeric ids: convert int to string
            if 'id' in conf_opts:
                if not isinstance(conf_opts['id'], six.string_types):
                    conf_opts['id'] = six.text_type(conf_opts['id'])
                else:
                    conf_opts['id'] = salt.utils.data.decode(conf_opts['id'])
            return conf_opts
class Call_id_function(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, opts):
        '''
        Evaluate the function that determines the ID if the 'id_function'
        option is set and return the result
        '''
        if opts.get('id'):
            return opts['id']
    
        # Import 'salt.loader' here to avoid a circular dependency
        import salt.loader as loader
    
        if isinstance(opts['id_function'], six.string_types):
            mod_fun = opts['id_function']
            fun_kwargs = {}
        elif isinstance(opts['id_function'], dict):
            mod_fun, fun_kwargs = six.next(six.iteritems(opts['id_function']))
            if fun_kwargs is None:
                fun_kwargs = {}
        else:
            log.error('\'id_function\' option is neither a string nor a dictionary')
            sys.exit(salt.defaults.exitcodes.EX_GENERIC)
    
        # split module and function and try loading the module
        mod, fun = mod_fun.split('.')
        if not opts.get('grains'):
            # Get grains for use by the module
            opts['grains'] = loader.grains(opts)
    
        try:
            id_mod = loader.raw_mod(opts, mod, fun)
            if not id_mod:
                raise KeyError
            # we take whatever the module returns as the minion ID
            newid = id_mod[mod_fun](**fun_kwargs)
            if not isinstance(newid, six.string_types) or not newid:
                log.error(
                    'Function %s returned value "%s" of type %s instead of string',
                    mod_fun, newid, type(newid)
                )
                sys.exit(salt.defaults.exitcodes.EX_GENERIC)
            log.info('Evaluated minion ID from module: %s', mod_fun)
            return newid
        except TypeError:
            log.error(
                'Function arguments %s are incorrect for function %s',
                fun_kwargs, mod_fun
            )
            sys.exit(salt.defaults.exitcodes.EX_GENERIC)
        except KeyError:
            log.error('Failed to load module %s', mod_fun)
            sys.exit(salt.defaults.exitcodes.EX_GENERIC)
class _update_ssl_config(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, opts):
        '''
        Resolves string names to integer constant in ssl configuration.
        '''
        if opts['ssl'] in (None, False):
            opts['ssl'] = None
            return
        if opts['ssl'] is True:
            opts['ssl'] = {}
            return
        import ssl
        for key, prefix in (('cert_reqs', 'CERT_'),
                            ('ssl_version', 'PROTOCOL_')):
            val = opts['ssl'].get(key)
            if val is None:
                continue
            if not isinstance(val, six.string_types) or not val.startswith(prefix) or not hasattr(ssl, val):
                message = 'SSL option \'{0}\' must be set to one of the following values: \'{1}\'.' \
                        .format(key, '\', \''.join([val for val in dir(ssl) if val.startswith(prefix)]))
                log.error(message)
                raise salt.exceptions.SaltConfigurationError(message)
            opts['ssl'][key] = getattr(ssl, val)
class _update_discovery_config(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, opts):
        '''
        Update discovery config for all instances.
    
        :param opts:
        :return:
        '''
        if opts.get('discovery') not in (None, False):
            if opts['discovery'] is True:
                opts['discovery'] = {}
            discovery_config = {'attempts': 3, 'pause': 5, 'port': 4520, 'match': 'any', 'mapping': {}, 'multimaster': False}
            for key in opts['discovery']:
                if key not in discovery_config:
                    raise salt.exceptions.SaltConfigurationError('Unknown discovery option: {0}'.format(key))
            if opts.get('__role') != 'minion':
                for key in ['attempts', 'pause', 'match']:
                    del discovery_config[key]
            opts['discovery'] = salt.utils.dictupdate.update(discovery_config, opts['discovery'], True, True)
class Api_config(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        Read in the Salt Master config file and add additional configs that
        need to be stubbed out for salt-api
        '''
        # Let's grab a copy of salt-api's required defaults
        opts = DEFAULT_API_OPTS.copy()
    
        # Let's override them with salt's master opts
        opts.update(client_config(path, defaults=DEFAULT_MASTER_OPTS.copy()))
    
        # Let's set the pidfile and log_file values in opts to api settings
        opts.update({
            'pidfile': opts.get('api_pidfile', DEFAULT_API_OPTS['api_pidfile']),
            'log_file': opts.get('api_logfile', DEFAULT_API_OPTS['api_logfile']),
        })
    
        prepend_root_dir(opts, [
            'api_pidfile',
            'api_logfile',
            'log_file',
            'pidfile'
        ])
        return opts
class Spm_config(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        Read in the salt master config file and add additional configs that
        need to be stubbed out for spm
    
        .. versionadded:: 2015.8.0
        '''
        # Let's grab a copy of salt's master default opts
        defaults = DEFAULT_MASTER_OPTS.copy()
        # Let's override them with spm's required defaults
        defaults.update(DEFAULT_SPM_OPTS)
    
        overrides = load_config(path, 'SPM_CONFIG', DEFAULT_SPM_OPTS['spm_conf_file'])
        default_include = overrides.get('spm_default_include',
                                        defaults['spm_default_include'])
        include = overrides.get('include', [])
    
        overrides.update(include_config(default_include, path, verbose=False))
        overrides.update(include_config(include, path, verbose=True))
        defaults = apply_master_config(overrides, defaults)
        defaults = apply_spm_config(overrides, defaults)
        return client_config(path, env_var='SPM_CONFIG', defaults=defaults)
class _render_template(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, config_file):
        '''
        Render config template, substituting grains where found.
        '''
        dirname, filename = os.path.split(config_file)
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(dirname))
        template = env.get_template(filename)
        return template.render(__grains__)
class _do_search(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, conf):
        '''
        Builds connection and search arguments, performs the LDAP search and
        formats the results as a dictionary appropriate for pillar use.
        '''
        # Build LDAP connection args
        connargs = {}
        for name in ['server', 'port', 'tls', 'binddn', 'bindpw', 'anonymous']:
            connargs[name] = _config(name, conf)
        if connargs['binddn'] and connargs['bindpw']:
            connargs['anonymous'] = False
        # Build search args
        try:
            _filter = conf['filter']
        except KeyError:
            raise SaltInvocationError('missing filter')
        _dn = _config('dn', conf)
        scope = _config('scope', conf)
        _lists = _config('lists', conf) or []
        _attrs = _config('attrs', conf) or []
        _dict_key_attr = _config('dict_key_attr', conf, 'dn')
        attrs = _lists + _attrs + [_dict_key_attr]
        if not attrs:
            attrs = None
        # Perform the search
        try:
            result = __salt__['ldap.search'](_filter, _dn, scope, attrs,
                                             **connargs)['results']
        except IndexError:  # we got no results for this search
            log.debug('LDAP search returned no results for filter %s', _filter)
            result = {}
        except Exception:
            log.critical(
                'Failed to retrieve pillar data from LDAP:\n', exc_info=True
            )
            return {}
        return result
class Start(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Start Riak
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' riak.start
        '''
        ret = {'comment': '', 'success': False}
    
        cmd = __execute_cmd('riak', 'start')
    
        if cmd['retcode'] != 0:
            ret['comment'] = cmd['stderr']
        else:
            ret['comment'] = cmd['stdout']
            ret['success'] = True
    
        return ret
class Stop(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Stop Riak
    
        .. versionchanged:: 2015.8.0
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' riak.stop
        '''
        ret = {'comment': '', 'success': False}
    
        cmd = __execute_cmd('riak', 'stop')
    
        if cmd['retcode'] != 0:
            ret['comment'] = cmd['stderr']
        else:
            ret['comment'] = cmd['stdout']
            ret['success'] = True
    
        return ret
class Cluster_commit(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Commit Cluster Changes
    
        .. versionchanged:: 2015.8.0
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' riak.cluster_commit
        '''
        ret = {'comment': '', 'success': False}
    
        cmd = __execute_cmd('riak-admin', 'cluster commit')
    
        if cmd['retcode'] != 0:
            ret['comment'] = cmd['stdout']
        else:
            ret['comment'] = cmd['stdout']
            ret['success'] = True
    
        return ret
class Member_status(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Get cluster member status
    
        .. versionchanged:: 2015.8.0
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' riak.member_status
        '''
        ret = {'membership': {},
               'summary': {'Valid': 0,
                           'Leaving': 0,
                           'Exiting': 0,
                           'Joining': 0,
                           'Down': 0,
                           }}
    
        out = __execute_cmd('riak-admin', 'member-status')['stdout'].splitlines()
    
        for line in out:
            if line.startswith(('=', '-', 'Status')):
                continue
            if '/' in line:
                # We're in the summary line
                for item in line.split('/'):
                    key, val = item.split(':')
                    ret['summary'][key.strip()] = val.strip()
    
            if len(line.split()) == 4:
                # We're on a node status line
                (status, ring, pending, node) = line.split()
    
                ret['membership'][node] = {
                    'Status': status,
                    'Ring': ring,
                    'Pending': pending
                }
    
        return ret
class Status(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Current node status
    
        .. versionadded:: 2015.8.0
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' riak.status
        '''
        ret = {}
    
        cmd = __execute_cmd('riak-admin', 'status')
    
        for i in cmd['stdout'].splitlines():
            if ':' in i:
                (name, val) = i.split(':', 1)
                ret[name.strip()] = val.strip()
    
        return ret
class Is_admin(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        Is the passed user a member of the Administrators group
    
        Args:
            name (str): The name to check
    
        Returns:
            bool: True if user is a member of the Administrators group, False
            otherwise
        '''
        groups = get_user_groups(name, True)
    
        for group in groups:
            if group in ('S-1-5-32-544', 'S-1-5-18'):
                return True
    
        return False
class Get_sid_from_name(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, name):
        '''
        This is a tool for getting a sid from a name. The name can be any object.
        Usually a user or a group
    
        Args:
            name (str): The name of the user or group for which to get the sid
    
        Returns:
            str: The corresponding SID
        '''
        # If None is passed, use the Universal Well-known SID "Null SID"
        if name is None:
            name = 'NULL SID'
    
        try:
            sid = win32security.LookupAccountName(None, name)[0]
        except pywintypes.error as exc:
            raise CommandExecutionError(
                'User {0} not found: {1}'.format(name, exc))
    
        return win32security.ConvertSidToStringSid(sid)
class Get_current_user(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, with_domain=True):
        '''
        Gets the user executing the process
    
        Args:
    
            with_domain (bool):
                ``True`` will prepend the user name with the machine name or domain
                separated by a backslash
    
        Returns:
            str: The user name
        '''
        try:
            user_name = win32api.GetUserNameEx(win32api.NameSamCompatible)
            if user_name[-1] == '$':
                # Make the system account easier to identify.
                # Fetch sid so as to handle other language than english
                test_user = win32api.GetUserName()
                if test_user == 'SYSTEM':
                    user_name = 'SYSTEM'
                elif get_sid_from_name(test_user) == 'S-1-5-18':
                    user_name = 'SYSTEM'
            elif not with_domain:
                user_name = win32api.GetUserName()
        except pywintypes.error as exc:
            raise CommandExecutionError(
                'Failed to get current user: {0}'.format(exc))
    
        if not user_name:
            return False
    
        return user_name
class Get_sam_name(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, username):
        r'''
        Gets the SAM name for a user. It basically prefixes a username without a
        backslash with the computer name. If the user does not exist, a SAM
        compatible name will be returned using the local hostname as the domain.
    
        i.e. salt.utils.get_same_name('Administrator') would return 'DOMAIN.COM\Administrator'
    
        .. note:: Long computer names are truncated to 15 characters
        '''
        try:
            sid_obj = win32security.LookupAccountName(None, username)[0]
        except pywintypes.error:
            return '\\'.join([platform.node()[:15].upper(), username])
        username, domain, _ = win32security.LookupAccountSid(None, sid_obj)
        return '\\'.join([domain, username])
class Escape_for_cmd_exe(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, arg):
        '''
        Escape an argument string to be suitable to be passed to
        cmd.exe on Windows
    
        This method takes an argument that is expected to already be properly
        escaped for the receiving program to be properly parsed. This argument
        will be further escaped to pass the interpolation performed by cmd.exe
        unchanged.
    
        Any meta-characters will be escaped, removing the ability to e.g. use
        redirects or variables.
    
        Args:
            arg (str): a single command line argument to escape for cmd.exe
    
        Returns:
            str: an escaped string suitable to be passed as a program argument to cmd.exe
        '''
        meta_chars = '()%!^"<>&|'
        meta_re = re.compile('(' + '|'.join(re.escape(char) for char in list(meta_chars)) + ')')
        meta_map = {char: "^{0}".format(char) for char in meta_chars}
    
        def escape_meta_chars(m):
            char = m.group(1)
            return meta_map[char]
    
        return meta_re.sub(escape_meta_chars, arg)
class Broadcast_setting_change(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, message='Environment'):
        '''
        Send a WM_SETTINGCHANGE Broadcast to all Windows
    
        Args:
    
            message (str):
                A string value representing the portion of the system that has been
                updated and needs to be refreshed. Default is ``Environment``. These
                are some common values:
    
                - "Environment" : to effect a change in the environment variables
                - "intl" : to effect a change in locale settings
                - "Policy" : to effect a change in Group Policy Settings
                - a leaf node in the registry
                - the name of a section in the ``Win.ini`` file
    
                See lParam within msdn docs for
                `WM_SETTINGCHANGE <https://msdn.microsoft.com/en-us/library/ms725497%28VS.85%29.aspx>`_
                for more information on Broadcasting Messages.
    
                See GWL_WNDPROC within msdn docs for
                `SetWindowLong <https://msdn.microsoft.com/en-us/library/windows/desktop/ms633591(v=vs.85).aspx>`_
                for information on how to retrieve those messages.
    
        .. note::
            This will only affect new processes that aren't launched by services. To
            apply changes to the path or registry to services, the host must be
            restarted. The ``salt-minion``, if running as a service, will not see
            changes to the environment until the system is restarted. Services
            inherit their environment from ``services.exe`` which does not respond
            to messaging events. See
            `MSDN Documentation <https://support.microsoft.com/en-us/help/821761/changes-that-you-make-to-environment-variables-do-not-affect-services>`_
            for more information.
    
        CLI Example:
    
        ... code-block:: python
    
            import salt.utils.win_functions
            salt.utils.win_functions.broadcast_setting_change('Environment')
        '''
        # Listen for messages sent by this would involve working with the
        # SetWindowLong function. This can be accessed via win32gui or through
        # ctypes. You can find examples on how to do this by searching for
        # `Accessing WGL_WNDPROC` on the internet. Here are some examples of how
        # this might work:
        #
        # # using win32gui
        # import win32con
        # import win32gui
        # old_function = win32gui.SetWindowLong(window_handle, win32con.GWL_WNDPROC, new_function)
        #
        # # using ctypes
        # import ctypes
        # import win32con
        # from ctypes import c_long, c_int
        # user32 = ctypes.WinDLL('user32', use_last_error=True)
        # WndProcType = ctypes.WINFUNCTYPE(c_int, c_long, c_int, c_int)
        # new_function = WndProcType
        # old_function = user32.SetWindowLongW(window_handle, win32con.GWL_WNDPROC, new_function)
        broadcast_message = ctypes.create_unicode_buffer(message)
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        result = user32.SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                                            broadcast_message, SMTO_ABORTIFHUNG,
                                            5000, 0)
        return result == 1
class Guid_to_squid(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, guid):
        '''
        Converts a GUID   to a compressed guid (SQUID)
    
        Each Guid has 5 parts separated by '-'. For the first three each one will be
        totally reversed, and for the remaining two each one will be reversed by
        every other character. Then the final compressed Guid will be constructed by
        concatenating all the reversed parts without '-'.
    
        .. Example::
    
            Input:                  2BE0FA87-5B36-43CF-95C8-C68D6673FB94
            Reversed:               78AF0EB2-63B5-FC34-598C-6CD86637BF49
            Final Compressed Guid:  78AF0EB263B5FC34598C6CD86637BF49
    
        Args:
    
            guid (str): A valid GUID
    
        Returns:
            str: A valid compressed GUID (SQUID)
        '''
        guid_pattern = re.compile(r'^\{(\w{8})-(\w{4})-(\w{4})-(\w\w)(\w\w)-(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)\}$')
        guid_match = guid_pattern.match(guid)
        squid = ''
        if guid_match is not None:
            for index in range(1, 12):
                squid += guid_match.group(index)[::-1]
        return squid
class Squid_to_guid(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, squid):
        '''
        Converts a compressed GUID (SQUID) back into a GUID
    
        Args:
    
            squid (str): A valid compressed GUID
    
        Returns:
            str: A valid GUID
        '''
        squid_pattern = re.compile(r'^(\w{8})(\w{4})(\w{4})(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)$')
        squid_match = squid_pattern.match(squid)
        guid = ''
        if squid_match is not None:
            guid = '{' + \
                   squid_match.group(1)[::-1]+'-' + \
                   squid_match.group(2)[::-1]+'-' + \
                   squid_match.group(3)[::-1]+'-' + \
                   squid_match.group(4)[::-1]+squid_match.group(5)[::-1] + '-'
            for index in range(6, 12):
                guid += squid_match.group(index)[::-1]
            guid += '}'
        return guid
class System_info(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, data):
        '''
        Helper method to return parsed system_info
        from the 'show version' command.
        '''
        if not data:
            return {}
        info = {
            'software': _parse_software(data),
            'hardware': _parse_hardware(data),
            'plugins': _parse_plugins(data),
        }
        return {'nxos': info}
class Get_modules(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Get a list of the PowerShell modules which are potentially available to be
        imported. The intent is to mimic the functionality of ``Get-Module
        -ListAvailable | Select-Object -Expand Name``, without the delay of loading
        PowerShell to do so.
    
        Returns:
            list: A list of modules available to Powershell
    
        Example:
    
        .. code-block:: python
    
            import salt.utils.powershell
            modules = salt.utils.powershell.get_modules()
        '''
        ret = list()
        valid_extensions = ('.psd1', '.psm1', '.cdxml', '.xaml', '.dll')
        # need to create an info function to get PS information including version
        # __salt__ is not available from salt.utils... need to create a salt.util
        # for the registry to avoid loading powershell to get the version
        # not sure how to get the powershell version in linux outside of powershell
        # if running powershell to get version need to use subprocess.Popen
        # That information will be loaded here
        # ps_version = info()['version_raw']
        root_paths = []
    
        home_dir = os.environ.get('HOME', os.environ.get('HOMEPATH'))
        system_dir = '{0}\\System32'.format(os.environ.get('WINDIR', 'C:\\Windows'))
        program_files = os.environ.get('ProgramFiles', 'C:\\Program Files')
        default_paths = [
            '{0}/.local/share/powershell/Modules'.format(home_dir),
            # Once version is available, these can be enabled
            # '/opt/microsoft/powershell/{0}/Modules'.format(ps_version),
            # '/usr/local/microsoft/powershell/{0}/Modules'.format(ps_version),
            '/usr/local/share/powershell/Modules',
            '{0}\\WindowsPowerShell\\v1.0\\Modules\\'.format(system_dir),
            '{0}\\WindowsPowerShell\\Modules'.format(program_files)]
        default_paths = ';'.join(default_paths)
    
        ps_module_path = os.environ.get('PSModulePath', default_paths)
    
        # Check if defaults exist, add them if they do
        ps_module_path = ps_module_path.split(';')
        for item in ps_module_path:
            if os.path.exists(item):
                root_paths.append(item)
    
        # Did we find any, if not log the error and return
        if not root_paths:
            log.error('Default paths not found')
            return ret
    
        for root_path in root_paths:
    
            # only recurse directories
            if not os.path.isdir(root_path):
                continue
    
            # get a list of all files in the root_path
            for root_dir, sub_dirs, file_names in salt.utils.path.os_walk(root_path):
                for file_name in file_names:
                    base_name, file_extension = os.path.splitext(file_name)
    
                    # If a module file or module manifest is present, check if
                    # the base name matches the directory name.
    
                    if file_extension.lower() in valid_extensions:
                        dir_name = os.path.basename(os.path.normpath(root_dir))
    
                        # Stop recursion once we find a match, and use
                        # the capitalization from the directory name.
                        if dir_name not in ret and \
                                base_name.lower() == dir_name.lower():
                            del sub_dirs[:]
                            ret.append(dir_name)
    
        return ret
class Generate_cert(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, domain):
        '''
        Generate an icinga2 client certificate and key.
    
        Returns::
            icinga2 pki new-cert --cn domain.tld --key /etc/icinga2/pki/domain.tld.key --cert /etc/icinga2/pki/domain.tld.crt
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' icinga2.generate_cert domain.tld
    
        '''
        result = __salt__['cmd.run_all'](["icinga2", "pki", "new-cert", "--cn", domain, "--key", "{0}{1}.key".format(get_certs_path(), domain), "--cert", "{0}{1}.crt".format(get_certs_path(), domain)], python_shell=False)
        return result
class _handle_salt_host_resource(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, resource):
        '''
        Handles salt_host resources.
        See https://github.com/dmacvicar/terraform-provider-salt
    
        Returns roster attributes for the resource or None
        '''
        ret = {}
        attrs = resource.get('primary', {}).get('attributes', {})
        ret[MINION_ID] = attrs.get(MINION_ID)
        valid_attrs = set(attrs.keys()).intersection(TF_ROSTER_ATTRS.keys())
        for attr in valid_attrs:
            ret[attr] = _cast_output_to_type(attrs.get(attr), TF_ROSTER_ATTRS.get(attr))
        return ret
class _add_ssh_key(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, ret):
        '''
        Setups the salt-ssh minion to be accessed with salt-ssh default key
        '''
        priv = None
        if __opts__.get('ssh_use_home_key') and os.path.isfile(os.path.expanduser('~/.ssh/id_rsa')):
            priv = os.path.expanduser('~/.ssh/id_rsa')
        else:
            priv = __opts__.get(
                'ssh_priv',
                os.path.abspath(os.path.join(
                    __opts__['pki_dir'],
                    'ssh',
                    'salt-ssh.rsa'
                ))
            )
        if priv and os.path.isfile(priv):
            ret['priv'] = priv
class _parse_state_file(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, state_file_path='terraform.tfstate'):
        '''
        Parses the terraform state file passing different resource types to the right handler
        '''
        ret = {}
        with salt.utils.files.fopen(state_file_path, 'r') as fh_:
            tfstate = salt.utils.json.load(fh_)
    
        modules = tfstate.get('modules')
        if not modules:
            log.error('Malformed tfstate file. No modules found')
            return ret
    
        for module in modules:
            resources = module.get('resources', [])
            for resource_name, resource in salt.ext.six.iteritems(resources):
                roster_entry = None
                if resource['type'] == 'salt_host':
                    roster_entry = _handle_salt_host_resource(resource)
    
                if not roster_entry:
                    continue
    
                minion_id = roster_entry.get(MINION_ID, resource.get('id'))
                if not minion_id:
                    continue
    
                if MINION_ID in roster_entry:
                    del roster_entry[MINION_ID]
                _add_ssh_key(roster_entry)
                ret[minion_id] = roster_entry
        return ret
class Prep_ip_port(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, opts):
        '''
        parse host:port values from opts['master'] and return valid:
            master: ip address or hostname as a string
            master_port: (optional) master returner port as integer
    
        e.g.:
          - master: 'localhost:1234' -> {'master': 'localhost', 'master_port': 1234}
          - master: '127.0.0.1:1234' -> {'master': '127.0.0.1', 'master_port' :1234}
          - master: '[::1]:1234' -> {'master': '::1', 'master_port': 1234}
          - master: 'fe80::a00:27ff:fedc:ba98' -> {'master': 'fe80::a00:27ff:fedc:ba98'}
        '''
        ret = {}
        # Use given master IP if "ip_only" is set or if master_ip is an ipv6 address without
        # a port specified. The is_ipv6 check returns False if brackets are used in the IP
        # definition such as master: '[::1]:1234'.
        if opts['master_uri_format'] == 'ip_only':
            ret['master'] = ipaddress.ip_address(opts['master'])
        else:
            host, port = parse_host_port(opts['master'])
            ret = {'master': host}
            if port:
                ret.update({'master_port': port})
    
        return ret
class Eval_master_func(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, opts):
        '''
        Evaluate master function if master type is 'func'
        and save it result in opts['master']
        '''
        if '__master_func_evaluated' not in opts:
            # split module and function and try loading the module
            mod_fun = opts['master']
            mod, fun = mod_fun.split('.')
            try:
                master_mod = salt.loader.raw_mod(opts, mod, fun)
                if not master_mod:
                    raise KeyError
                # we take whatever the module returns as master address
                opts['master'] = master_mod[mod_fun]()
                # Check for valid types
                if not isinstance(opts['master'], (six.string_types, list)):
                    raise TypeError
                opts['__master_func_evaluated'] = True
            except KeyError:
                log.error('Failed to load module %s', mod_fun)
                sys.exit(salt.defaults.exitcodes.EX_GENERIC)
            except TypeError:
                log.error('%s returned from %s is not a string', opts['master'], mod_fun)
                sys.exit(salt.defaults.exitcodes.EX_GENERIC)
            log.info('Evaluated master from module: %s', mod_fun)
class _return_retry_timer(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Based on the minion configuration, either return a randomized timer or
            just return the value of the return_retry_timer.
            '''
            msg = 'Minion return retry timer set to %s seconds'
            if self.opts.get('return_retry_timer_max'):
                try:
                    random_retry = randint(self.opts['return_retry_timer'], self.opts['return_retry_timer_max'])
                    retry_msg = msg % random_retry
                    log.debug('%s (randomized)', msg % random_retry)
                    return random_retry
                except ValueError:
                    # Catch wiseguys using negative integers here
                    log.error(
                        'Invalid value (return_retry_timer: %s or '
                        'return_retry_timer_max: %s). Both must be positive '
                        'integers.',
                        self.opts['return_retry_timer'],
                        self.opts['return_retry_timer_max'],
                    )
                    log.debug(msg, DEFAULT_MINION_OPTS['return_retry_timer'])
                    return DEFAULT_MINION_OPTS['return_retry_timer']
            else:
                log.debug(msg, self.opts.get('return_retry_timer'))
                return self.opts.get('return_retry_timer')
class _prep_mod_opts(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Returns a copy of the opts with key bits stripped out
            '''
            mod_opts = {}
            for key, val in six.iteritems(self.opts):
                if key == 'logger':
                    continue
                mod_opts[key] = val
            return mod_opts
class Ctx(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Return a single context manager for the minion's data
            '''
            if six.PY2:
                return contextlib.nested(
                    self.functions.context_dict.clone(),
                    self.returners.context_dict.clone(),
                    self.executors.context_dict.clone(),
                )
            else:
                exitstack = contextlib.ExitStack()
                exitstack.enter_context(self.functions.context_dict.clone())
                exitstack.enter_context(self.returners.context_dict.clone())
                exitstack.enter_context(self.executors.context_dict.clone())
                return exitstack
class _parse_version_string(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, version_conditions_string):
        '''
        Returns a list of two-tuples containing (operator, version).
        '''
        result = []
        version_conditions_string = version_conditions_string.strip()
        if not version_conditions_string:
            return result
        for version_condition in version_conditions_string.split(','):
            operator_and_version = _get_comparison_spec(version_condition)
            result.append(operator_and_version)
        return result
class _nested_output(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, obj):
        '''
        Serialize obj and format for output
        '''
        nested.__opts__ = __opts__
        ret = nested.output(obj).rstrip()
        return ret
class Mod_init(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, low):
        '''
        Set a flag to tell the install functions to refresh the package database.
        This ensures that the package database is refreshed only once during
        a state run significantly improving the speed of package management
        during a state run.
    
        It sets a flag for a number of reasons, primarily due to timeline logic.
        When originally setting up the mod_init for pkg a number of corner cases
        arose with different package managers and how they refresh package data.
    
        It also runs the "ex_mod_init" from the package manager module that is
        currently loaded. The "ex_mod_init" is expected to work as a normal
        "mod_init" function.
    
        .. seealso::
           :py:func:`salt.modules.ebuild.ex_mod_init`
    
        '''
        ret = True
        if 'pkg.ex_mod_init' in __salt__:
            ret = __salt__['pkg.ex_mod_init'](low)
    
        if low['fun'] == 'installed' or low['fun'] == 'latest':
            salt.utils.pkg.write_rtag(__opts__)
            return ret
        return False
class _call_system_profiler(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, datatype):
        '''
        Call out to system_profiler.  Return a dictionary
        of the stuff we are interested in.
        '''
    
        p = subprocess.Popen(
            [PROFILER_BINARY, '-detailLevel', 'full',
             '-xml', datatype], stdout=subprocess.PIPE)
        (sysprofresults, sysprof_stderr) = p.communicate(input=None)
    
        if six.PY2:
            plist = plistlib.readPlistFromString(sysprofresults)
        else:
            plist = plistlib.readPlistFromBytes(sysprofresults)
    
        try:
            apps = plist[0]['_items']
        except (IndexError, KeyError):
            apps = []
    
        return apps
class Receipts(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Return the results of a call to
        ``system_profiler -xml -detail full SPInstallHistoryDataType``
        as a dictionary.  Top-level keys of the dictionary
        are the names of each set of install receipts, since
        there can be multiple receipts with the same name.
        Contents of each key are a list of dictionaries.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' systemprofiler.receipts
        '''
    
        apps = _call_system_profiler('SPInstallHistoryDataType')
    
        appdict = {}
    
        for a in apps:
            details = dict(a)
            details.pop('_name')
            if 'install_date' in details:
                details['install_date'] = details['install_date'].strftime('%Y-%m-%d %H:%M:%S')
            if 'info' in details:
                try:
                    details['info'] = '{0}: {1}'.format(details['info'][0],
                                                        details['info'][1].strftime('%Y-%m-%d %H:%M:%S'))
                except (IndexError, AttributeError):
                    pass
    
            if a['_name'] not in appdict:
                appdict[a['_name']] = []
    
            appdict[a['_name']].append(details)
    
        return appdict
class Item(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *args):
        '''
        .. versionadded:: 0.16.2
    
        Return one or more pillar entries
    
        CLI Examples:
    
        .. code-block:: bash
    
            salt '*' pillar.item foo
            salt '*' pillar.item foo bar baz
        '''
        ret = {}
        for arg in args:
            try:
                ret[arg] = __pillar__[arg]
            except KeyError:
                pass
        return ret
class Raw(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, key=None):
        '''
        Return the raw pillar data that is available in the module. This will
        show the pillar as it is loaded as the __pillar__ dict.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' pillar.raw
    
        With the optional key argument, you can select a subtree of the
        pillar raw data.::
    
            salt '*' pillar.raw key='roles'
        '''
        if key:
            ret = __pillar__.get(key, {})
        else:
            ret = __pillar__
    
        return ret
class _get_client(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, profile):
        '''
        Return the GitHub client, cached into __context__ for performance
        '''
        token = _get_config_value(profile, 'token')
        key = 'github.{0}:{1}'.format(
            token,
            _get_config_value(profile, 'org_name')
        )
    
        if key not in __context__:
            __context__[key] = github.Github(
                token,
                per_page=100
            )
        return __context__[key]
class List_private_repos(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, profile='github'):
        '''
        List private repositories within the organization. Dependent upon the access
        rights of the profile token.
    
        .. versionadded:: 2016.11.0
    
        profile
            The name of the profile configuration to use. Defaults to ``github``.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt myminion github.list_private_repos
            salt myminion github.list_private_repos profile='my-github-profile'
        '''
        repos = []
        for repo in _get_repos(profile):
            if repo.private is True:
                repos.append(repo.name)
        return repos
class List_public_repos(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, profile='github'):
        '''
        List public repositories within the organization.
    
        .. versionadded:: 2016.11.0
    
        profile
            The name of the profile configuration to use. Defaults to ``github``.
    
        CLI Example:
    
        .. code-block:: bash
    
            salt myminion github.list_public_repos
            salt myminion github.list_public_repos profile='my-github-profile'
        '''
        repos = []
        for repo in _get_repos(profile):
            if repo.private is False:
                repos.append(repo.name)
        return repos
class _format_pr(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, pr_):
        '''
        Helper function to format API return information into a more manageable
        and useful dictionary for pull request information.
    
        pr_
            The pull request to format.
        '''
        ret = {'id': pr_.get('id'),
               'pr_number': pr_.get('number'),
               'state': pr_.get('state'),
               'title': pr_.get('title'),
               'user': pr_.get('user').get('login'),
               'html_url': pr_.get('html_url'),
               'base_branch': pr_.get('base').get('ref')}
    
        return ret
class _format_issue(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, issue):
        '''
        Helper function to format API return information into a more manageable
        and useful dictionary for issue information.
    
        issue
            The issue to format.
        '''
        ret = {'id': issue.get('id'),
               'issue_number': issue.get('number'),
               'state': issue.get('state'),
               'title': issue.get('title'),
               'user': issue.get('user').get('login'),
               'html_url': issue.get('html_url')}
    
        assignee = issue.get('assignee')
        if assignee:
            assignee = assignee.get('login')
    
        labels = issue.get('labels')
        label_names = []
        for label in labels:
            label_names.append(label.get('name'))
    
        milestone = issue.get('milestone')
        if milestone:
            milestone = milestone.get('title')
    
        ret['assignee'] = assignee
        ret['labels'] = label_names
        ret['milestone'] = milestone
    
        return ret
class _get_mounts(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, fs_type=None):
        '''
        List mounted filesystems.
        '''
        mounts = {}
        with salt.utils.files.fopen('/proc/mounts') as fhr:
            for line in fhr.readlines():
                line = salt.utils.stringutils.to_unicode(line)
                device, mntpnt, fstype, options, fs_freq, fs_passno = line.strip().split(" ")
                if fs_type and fstype != fs_type:
                    continue
                if mounts.get(device) is None:
                    mounts[device] = []
    
                data = {
                    'mount_point': mntpnt,
                    'options': options.split(",")
                }
                if not fs_type:
                    data['type'] = fstype
                mounts[device].append(data)
        return mounts
class _blkid(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, fs_type=None):
        '''
        Return available media devices.
    
        :param fs_type: Filter only devices that are formatted by that file system.
        '''
        flt = lambda data: [el for el in data if el.strip()]
        data = dict()
        for dev_meta in flt(os.popen("blkid -o full").read().split(os.linesep)):  # No __salt__ around at this point.
            dev_meta = dev_meta.strip()
            if not dev_meta:
                continue
            device = dev_meta.split(" ")
            dev_name = device.pop(0)[:-1]
            data[dev_name] = dict()
            for k_set in device:
                ks_key, ks_value = [elm.replace('"', '') for elm in k_set.split("=")]
                data[dev_name][ks_key.lower()] = ks_value
    
        if fs_type:
            mounts = _get_mounts(fs_type)
            for device in six.iterkeys(mounts):
                if data.get(device):
                    data[device]['mounts'] = mounts[device]
    
        return data
class _is_device(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        Return True if path is a physical device.
        '''
        out = __salt__['cmd.run_all']('file -i {0}'.format(path))
        _verify_run(out)
    
        # Always [device, mime, charset]. See (file --help)
        return re.split(r'\s+', out['stdout'])[1][:-1] == 'inode/blockdevice'
class Returner(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, ret):
        '''
        Send an mattermost message with the data
        '''
    
        _options = _get_options(ret)
    
        api_url = _options.get('api_url')
        channel = _options.get('channel')
        username = _options.get('username')
        hook = _options.get('hook')
    
        if not hook:
            log.error('mattermost.hook not defined in salt config')
            return
    
        returns = ret.get('return')
    
        message = ('id: {0}\r\n'
                   'function: {1}\r\n'
                   'function args: {2}\r\n'
                   'jid: {3}\r\n'
                   'return: {4}\r\n').format(
                        ret.get('id'),
                        ret.get('fun'),
                        ret.get('fun_args'),
                        ret.get('jid'),
                        returns)
    
        mattermost = post_message(channel,
                                  message,
                                  username,
                                  api_url,
                                  hook)
        return mattermost
class Event_return(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, events):
        '''
        Send the events to a mattermost room.
    
        :param events:      List of events
        :return:            Boolean if messages were sent successfully.
        '''
        _options = _get_options()
    
        api_url = _options.get('api_url')
        channel = _options.get('channel')
        username = _options.get('username')
        hook = _options.get('hook')
    
        is_ok = True
        for event in events:
            log.debug('Event: %s', event)
            log.debug('Event data: %s', event['data'])
            message = 'tag: {0}\r\n'.format(event['tag'])
            for key, value in six.iteritems(event['data']):
                message += '{0}: {1}\r\n'.format(key, value)
            result = post_message(channel,
                                  message,
                                  username,
                                  api_url,
                                  hook)
            if not result:
                is_ok = False
    
        return is_ok
class Setup_temp_logger(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, log_level='error'):
        '''
        Setup the temporary console logger
        '''
        if is_temp_logging_configured():
            logging.getLogger(__name__).warning(
                'Temporary logging is already configured'
            )
            return
    
        if log_level is None:
            log_level = 'warning'
    
        level = LOG_LEVELS.get(log_level.lower(), logging.ERROR)
    
        handler = None
        for handler in logging.root.handlers:
            if handler in (LOGGING_NULL_HANDLER, LOGGING_STORE_HANDLER):
                continue
    
            if not hasattr(handler, 'stream'):
                # Not a stream handler, continue
                continue
    
            if handler.stream is sys.stderr:
                # There's already a logging handler outputting to sys.stderr
                break
        else:
            handler = LOGGING_TEMP_HANDLER
        handler.setLevel(level)
    
        # Set the default temporary console formatter config
        formatter = logging.Formatter(
            '[%(levelname)-8s] %(message)s', datefmt='%H:%M:%S'
        )
        handler.setFormatter(formatter)
        logging.root.addHandler(handler)
    
        # Sync the null logging handler messages with the temporary handler
        if LOGGING_NULL_HANDLER is not None:
            LOGGING_NULL_HANDLER.sync_with_handlers([handler])
        else:
            logging.getLogger(__name__).debug(
                'LOGGING_NULL_HANDLER is already None, can\'t sync messages '
                'with it'
            )
    
        # Remove the temporary null logging handler
        __remove_null_logging_handler()
    
        global __TEMP_LOGGING_CONFIGURED
        __TEMP_LOGGING_CONFIGURED = True
class Setup_extended_logging(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, opts):
        '''
        Setup any additional logging handlers, internal or external
        '''
        if is_extended_logging_configured() is True:
            # Don't re-configure external loggers
            return
    
        # Explicit late import of salt's loader
        import salt.loader
    
        # Let's keep a reference to the current logging handlers
        initial_handlers = logging.root.handlers[:]
    
        # Load any additional logging handlers
        providers = salt.loader.log_handlers(opts)
    
        # Let's keep track of the new logging handlers so we can sync the stored
        # log records with them
        additional_handlers = []
    
        for name, get_handlers_func in six.iteritems(providers):
            logging.getLogger(__name__).info('Processing `log_handlers.%s`', name)
            # Keep a reference to the logging handlers count before getting the
            # possible additional ones.
            initial_handlers_count = len(logging.root.handlers)
    
            handlers = get_handlers_func()
            if isinstance(handlers, types.GeneratorType):
                handlers = list(handlers)
            elif handlers is False or handlers == [False]:
                # A false return value means not configuring any logging handler on
                # purpose
                logging.getLogger(__name__).info(
                    'The `log_handlers.%s.setup_handlers()` function returned '
                    '`False` which means no logging handler was configured on '
                    'purpose. Continuing...', name
                )
                continue
            else:
                # Make sure we have an iterable
                handlers = [handlers]
    
            for handler in handlers:
                if not handler and \
                        len(logging.root.handlers) == initial_handlers_count:
                    logging.getLogger(__name__).info(
                        'The `log_handlers.%s`, did not return any handlers '
                        'and the global handlers count did not increase. This '
                        'could be a sign of `log_handlers.%s` not working as '
                        'supposed', name, name
                    )
                    continue
    
                logging.getLogger(__name__).debug(
                    'Adding the \'%s\' provided logging handler: \'%s\'',
                    name, handler
                )
                additional_handlers.append(handler)
                logging.root.addHandler(handler)
    
        for handler in logging.root.handlers:
            if handler in initial_handlers:
                continue
            additional_handlers.append(handler)
    
        # Sync the null logging handler messages with the temporary handler
        if LOGGING_STORE_HANDLER is not None:
            LOGGING_STORE_HANDLER.sync_with_handlers(additional_handlers)
        else:
            logging.getLogger(__name__).debug(
                'LOGGING_STORE_HANDLER is already None, can\'t sync messages '
                'with it'
            )
    
        # Remove the temporary queue logging handler
        __remove_queue_logging_handler()
    
        # Remove the temporary null logging handler (if it exists)
        __remove_null_logging_handler()
    
        global __EXTERNAL_LOGGERS_CONFIGURED
        __EXTERNAL_LOGGERS_CONFIGURED = True
class Set_multiprocessing_logging_level_by_opts(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, opts):
        '''
        This will set the multiprocessing logging level to the lowest
        logging level of all the types of logging that are configured.
        '''
        global __MP_LOGGING_LEVEL
    
        log_levels = [
            LOG_LEVELS.get(opts.get('log_level', '').lower(), logging.ERROR),
            LOG_LEVELS.get(opts.get('log_level_logfile', '').lower(), logging.ERROR)
        ]
        for level in six.itervalues(opts.get('log_granular_levels', {})):
            log_levels.append(
                LOG_LEVELS.get(level.lower(), logging.ERROR)
            )
    
        __MP_LOGGING_LEVEL = min(log_levels)
class Setup_multiprocessing_logging(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, queue=None):
        '''
        This code should be called from within a running multiprocessing
        process instance.
        '''
        from salt.utils.platform import is_windows
    
        global __MP_LOGGING_CONFIGURED
        global __MP_LOGGING_QUEUE_HANDLER
    
        if __MP_IN_MAINPROCESS is True and not is_windows():
            # We're in the MainProcess, return! No multiprocessing logging setup shall happen
            # Windows is the exception where we want to set up multiprocessing
            # logging in the MainProcess.
            return
    
        try:
            logging._acquireLock()  # pylint: disable=protected-access
    
            if __MP_LOGGING_CONFIGURED is True:
                return
    
            # Let's set it to true as fast as possible
            __MP_LOGGING_CONFIGURED = True
    
            if __MP_LOGGING_QUEUE_HANDLER is not None:
                return
    
            # The temp null and temp queue logging handlers will store messages.
            # Since noone will process them, memory usage will grow. If they
            # exist, remove them.
            __remove_null_logging_handler()
            __remove_queue_logging_handler()
    
            # Let's add a queue handler to the logging root handlers
            __MP_LOGGING_QUEUE_HANDLER = SaltLogQueueHandler(queue or get_multiprocessing_logging_queue())
            logging.root.addHandler(__MP_LOGGING_QUEUE_HANDLER)
            # Set the logging root level to the lowest needed level to get all
            # desired messages.
            log_level = get_multiprocessing_logging_level()
            logging.root.setLevel(log_level)
            logging.getLogger(__name__).debug(
                'Multiprocessing queue logging configured for the process running '
                'under PID: %s at log level %s', os.getpid(), log_level
            )
            # The above logging call will create, in some situations, a futex wait
            # lock condition, probably due to the multiprocessing Queue's internal
            # lock and semaphore mechanisms.
            # A small sleep will allow us not to hit that futex wait lock condition.
            time.sleep(0.0001)
        finally:
            logging._releaseLock()
class Conf(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        '''
        Parse GRUB conf file
    
        CLI Example:
    
        .. code-block:: bash
    
            salt '*' grub.conf
        '''
        stanza = ''
        stanzas = []
        in_stanza = False
        ret = {}
        pos = 0
        try:
            with salt.utils.files.fopen(_detect_conf(), 'r') as _fp:
                for line in _fp:
                    line = salt.utils.stringutils.to_unicode(line)
                    if line.startswith('#'):
                        continue
                    if line.startswith('\n'):
                        in_stanza = False
                        if 'title' in stanza:
                            stanza += 'order {0}'.format(pos)
                            pos += 1
                            stanzas.append(stanza)
                        stanza = ''
                        continue
                    if line.strip().startswith('title'):
                        if in_stanza:
                            stanza += 'order {0}'.format(pos)
                            pos += 1
                            stanzas.append(stanza)
                            stanza = ''
                        else:
                            in_stanza = True
                    if in_stanza:
                        stanza += line
                    if not in_stanza:
                        key, value = _parse_line(line)
                        ret[key] = value
                if in_stanza:
                    if not line.endswith('\n'):
                        line += '\n'
                    stanza += line
                    stanza += 'order {0}'.format(pos)
                    pos += 1
                    stanzas.append(stanza)
        except (IOError, OSError) as exc:
            msg = "Could not read grub config: {0}"
            raise CommandExecutionError(msg.format(exc))
    
        ret['stanzas'] = []
        for stanza in stanzas:
            mydict = {}
            for line in stanza.strip().splitlines():
                key, value = _parse_line(line)
                mydict[key] = value
            ret['stanzas'].append(mydict)
        return ret
class _parse_upgrade_data(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, data):
        '''
        Helper method to parse upgrade data from the NX-OS device.
        '''
        upgrade_result = {}
        upgrade_result['upgrade_data'] = None
        upgrade_result['succeeded'] = False
        upgrade_result['upgrade_required'] = False
        upgrade_result['upgrade_non_disruptive'] = False
        upgrade_result['upgrade_in_progress'] = False
        upgrade_result['installing'] = False
        upgrade_result['module_data'] = {}
        upgrade_result['error_data'] = None
        upgrade_result['backend_processing_error'] = False
        upgrade_result['invalid_command'] = False
    
        # Error handling
        if isinstance(data, string_types) and re.search('Code: 500', data):
            log.info('Detected backend processing error')
            upgrade_result['error_data'] = data
            upgrade_result['backend_processing_error'] = True
            return upgrade_result
    
        if isinstance(data, dict):
            if 'code' in data and data['code'] == '400':
                log.info('Detected client error')
                upgrade_result['error_data'] = data['cli_error']
    
                if re.search('install.*may be in progress', data['cli_error']):
                    log.info('Detected install in progress...')
                    upgrade_result['installing'] = True
    
                if re.search('Invalid command', data['cli_error']):
                    log.info('Detected invalid command...')
                    upgrade_result['invalid_command'] = True
            else:
                # If we get here then it's likely we lost access to the device
                # but the upgrade succeeded.  We lost the actual upgrade data so
                # set the flag such that impact data is used instead.
                log.info('Probable backend processing error')
                upgrade_result['backend_processing_error'] = True
            return upgrade_result
    
        # Get upgrade data for further parsing
        # Case 1: Command terminal dont-ask returns empty {} that we don't need.
        if isinstance(data, list) and len(data) == 2:
            data = data[1]
        # Case 2: Command terminal dont-ask does not get included.
        if isinstance(data, list) and len(data) == 1:
            data = data[0]
    
        log.info('Parsing NX-OS upgrade data')
        upgrade_result['upgrade_data'] = data
        for line in data.split('\n'):
    
            log.info('Processing line: (%s)', line)
    
            # Check to see if upgrade is disruptive or non-disruptive
            if re.search(r'non-disruptive', line):
                log.info('Found non-disruptive line')
                upgrade_result['upgrade_non_disruptive'] = True
    
            # Example:
            # Module  Image  Running-Version(pri:alt)  New-Version  Upg-Required
            # 1       nxos   7.0(3)I7(5a)              7.0(3)I7(5a)        no
            # 1       bios   v07.65(09/04/2018)        v07.64(05/16/2018)  no
            mo = re.search(r'(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(yes|no)', line)
            if mo:
                log.info('Matched Module Running/New Version Upg-Req Line')
                bk = 'module_data'  # base key
                g1 = mo.group(1)
                g2 = mo.group(2)
                g3 = mo.group(3)
                g4 = mo.group(4)
                g5 = mo.group(5)
                mk = 'module {0}:image {1}'.format(g1, g2)  # module key
                upgrade_result[bk][mk] = {}
                upgrade_result[bk][mk]['running_version'] = g3
                upgrade_result[bk][mk]['new_version'] = g4
                if g5 == 'yes':
                    upgrade_result['upgrade_required'] = True
                    upgrade_result[bk][mk]['upgrade_required'] = True
                continue
    
            # The following lines indicate a successfull upgrade.
            if re.search(r'Install has been successful', line):
                log.info('Install successful line')
                upgrade_result['succeeded'] = True
                continue
    
            if re.search(r'Finishing the upgrade, switch will reboot in', line):
                log.info('Finishing upgrade line')
                upgrade_result['upgrade_in_progress'] = True
                continue
    
            if re.search(r'Switch will be reloaded for disruptive upgrade', line):
                log.info('Switch will be reloaded line')
                upgrade_result['upgrade_in_progress'] = True
                continue
    
            if re.search(r'Switching over onto standby', line):
                log.info('Switching over onto standby line')
                upgrade_result['upgrade_in_progress'] = True
                continue
    
        return upgrade_result
class __get_docker_file_path(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        Determines the filepath to use
    
        :param path:
        :return:
        '''
        if os.path.isfile(path):
            return path
        for dc_filename in DEFAULT_DC_FILENAMES:
            file_path = os.path.join(path, dc_filename)
            if os.path.isfile(file_path):
                return file_path
class __read_docker_compose_file(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, file_path):
        '''
        Read the compose file if it exists in the directory
    
        :param file_path:
        :return:
        '''
        if not os.path.isfile(file_path):
            return __standardize_result(False,
                                        'Path {} is not present'.format(file_path),
                                        None, None)
        try:
            with salt.utils.files.fopen(file_path, 'r') as fl:
                file_name = os.path.basename(file_path)
                result = {file_name: ''}
                for line in fl:
                    result[file_name] += salt.utils.stringutils.to_unicode(line)
        except EnvironmentError:
            return __standardize_result(False,
                                        'Could not read {0}'.format(file_path),
                                        None, None)
        return __standardize_result(True,
                                    'Reading content of {0}'.format(file_path),
                                    result, None)
class __load_project(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        Load a docker-compose project from path
    
        :param path:
        :return:
        '''
        file_path = __get_docker_file_path(path)
        if file_path is None:
            msg = 'Could not find docker-compose file at {0}'.format(path)
            return __standardize_result(False,
                                        msg,
                                        None, None)
        return __load_project_from_file_path(file_path)
class __load_project_from_file_path(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, file_path):
        '''
        Load a docker-compose project from file path
    
        :param path:
        :return:
        '''
        try:
            project = get_project(project_dir=os.path.dirname(file_path),
                                  config_path=[os.path.basename(file_path)])
        except Exception as inst:
            return __handle_except(inst)
        return project
class Get(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        Get the content of the docker-compose file into a directory
    
        path
            Path where the docker-compose file is stored on the server
    
        CLI Example:
    
        .. code-block:: bash
    
            salt myminion dockercompose.get /path/where/docker-compose/stored
        '''
        file_path = __get_docker_file_path(path)
        if file_path is None:
            return __standardize_result(False,
                                        'Path {} is not present'.format(path),
                                        None, None)
        salt_result = __read_docker_compose_file(file_path)
        if not salt_result['status']:
            return salt_result
        project = __load_project(path)
        if isinstance(project, dict):
            salt_result['return']['valid'] = False
        else:
            salt_result['return']['valid'] = True
        return salt_result
class Ps(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        '''
        List all running containers and report some information about them
    
        path
            Path where the docker-compose file is stored on the server
    
        CLI Example:
    
        .. code-block:: bash
    
            salt myminion dockercompose.ps /path/where/docker-compose/stored
        '''
    
        project = __load_project(path)
        result = {}
        if isinstance(project, dict):
            return project
        else:
            if USE_FILTERCLASS:
                containers = sorted(
                    project.containers(None, stopped=True) +
                    project.containers(None, OneOffFilter.only),
                    key=attrgetter('name'))
            else:
                containers = sorted(
                    project.containers(None, stopped=True) +
                    project.containers(None, one_off=True),
                    key=attrgetter('name'))
            for container in containers:
                command = container.human_readable_command
                if len(command) > 30:
                    command = '{0} ...'.format(command[:26])
                result[container.name] = {
                    'id': container.id,
                    'name': container.name,
                    'command': command,
                    'state': container.human_readable_state,
                    'ports': container.human_readable_ports,
                }
        return __standardize_result(True, 'Listing docker-compose containers', result, None)
class Split_low_tag(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, tag):
        '''
        Take a low tag and split it back into the low dict that it came from
        '''
        state, id_, name, fun = tag.split('_|-')
    
        return {'state': state,
                '__id__': id_,
                'name': name,
                'fun': fun}
class Get_accumulator_dir(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, cachedir):
        '''
        Return the directory that accumulator data is stored in, creating it if it
        doesn't exist.
        '''
        fn_ = os.path.join(cachedir, 'accumulator')
        if not os.path.isdir(fn_):
            # accumulator_dir is not present, create it
            os.makedirs(fn_)
        return fn_
class Trim_req(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, req):
        '''
        Trim any function off of a requisite
        '''
        reqfirst = next(iter(req))
        if '.' in reqfirst:
            return {reqfirst.split('.')[0]: req[reqfirst]}
        return req
class Format_log(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, ret):
        '''
        Format the state into a log message
        '''
        msg = ''
        if isinstance(ret, dict):
            # Looks like the ret may be a valid state return
            if 'changes' in ret:
                # Yep, looks like a valid state return
                chg = ret['changes']
                if not chg:
                    if ret['comment']:
                        msg = ret['comment']
                    else:
                        msg = 'No changes made for {0[name]}'.format(ret)
                elif isinstance(chg, dict):
                    if 'diff' in chg:
                        if isinstance(chg['diff'], six.string_types):
                            msg = 'File changed:\n{0}'.format(chg['diff'])
                    if all([isinstance(x, dict) for x in six.itervalues(chg)]):
                        if all([('old' in x and 'new' in x)
                                for x in six.itervalues(chg)]):
                            msg = 'Made the following changes:\n'
                            for pkg in chg:
                                old = chg[pkg]['old']
                                if not old and old not in (False, None):
                                    old = 'absent'
                                new = chg[pkg]['new']
                                if not new and new not in (False, None):
                                    new = 'absent'
                                # This must be able to handle unicode as some package names contain
                                # non-ascii characters like "Fran�ais" or "Espa�ol". See Issue #33605.
                                msg += '\'{0}\' changed from \'{1}\' to \'{2}\'\n'.format(pkg, old, new)
                if not msg:
                    msg = six.text_type(ret['changes'])
                if ret['result'] is True or ret['result'] is None:
                    log.info(msg)
                else:
                    log.error(msg)
        else:
            # catch unhandled data
            log.info(six.text_type(ret))
class _gather_pillar(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Whenever a state run starts, gather the pillar data fresh
            '''
            if self._pillar_override:
                if self._pillar_enc:
                    try:
                        self._pillar_override = salt.utils.crypt.decrypt(
                            self._pillar_override,
                            self._pillar_enc,
                            translate_newlines=True,
                            renderers=getattr(self, 'rend', None),
                            opts=self.opts,
                            valid_rend=self.opts['decrypt_pillar_renderers'])
                    except Exception as exc:
                        log.error('Failed to decrypt pillar override: %s', exc)
    
                if isinstance(self._pillar_override, six.string_types):
                    # This can happen if an entire pillar dictionary was passed as
                    # a single encrypted string. The override will have been
                    # decrypted above, and should now be a stringified dictionary.
                    # Use the YAML loader to convert that to a Python dictionary.
                    try:
                        self._pillar_override = yamlloader.load(
                            self._pillar_override,
                            Loader=yamlloader.SaltYamlSafeLoader)
                    except Exception as exc:
                        log.error('Failed to load CLI pillar override')
                        log.exception(exc)
    
                if not isinstance(self._pillar_override, dict):
                    log.error('Pillar override was not passed as a dictionary')
                    self._pillar_override = None
    
            pillar = salt.pillar.get_pillar(
                    self.opts,
                    self.opts['grains'],
                    self.opts['id'],
                    self.opts['saltenv'],
                    pillar_override=self._pillar_override,
                    pillarenv=self.opts.get('pillarenv'))
            return pillar.compile_pillar()
class _get_envs(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Pull the file server environments out of the master options
            '''
            envs = ['base']
            if 'file_roots' in self.opts:
                envs.extend([x for x in list(self.opts['file_roots'])
                             if x not in envs])
            env_order = self.opts.get('env_order', [])
            # Remove duplicates while preserving the order
            members = set()
            env_order = [env for env in env_order if not (env in members or members.add(env))]
            client_envs = self.client.envs()
            if env_order and client_envs:
                return [env for env in env_order if env in client_envs]
    
            elif env_order:
                return env_order
            else:
                envs.extend([env for env in client_envs if env not in envs])
                return envs
class Get_tops(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Gather the top files
            '''
            tops = DefaultOrderedDict(list)
            include = DefaultOrderedDict(list)
            done = DefaultOrderedDict(list)
            found = 0  # did we find any contents in the top files?
            # Gather initial top files
            merging_strategy = self.opts['top_file_merging_strategy']
            if merging_strategy == 'same' and not self.opts['saltenv']:
                if not self.opts['default_top']:
                    raise SaltRenderError(
                        'top_file_merging_strategy set to \'same\', but no '
                        'default_top configuration option was set'
                    )
    
            if self.opts['saltenv']:
                contents = self.client.cache_file(
                    self.opts['state_top'],
                    self.opts['saltenv']
                )
                if contents:
                    found = 1
                    tops[self.opts['saltenv']] = [
                        compile_template(
                            contents,
                            self.state.rend,
                            self.state.opts['renderer'],
                            self.state.opts['renderer_blacklist'],
                            self.state.opts['renderer_whitelist'],
                            saltenv=self.opts['saltenv']
                        )
                    ]
                else:
                    tops[self.opts['saltenv']] = [{}]
    
            else:
                found = 0
                state_top_saltenv = self.opts.get('state_top_saltenv', False)
                if state_top_saltenv \
                        and not isinstance(state_top_saltenv, six.string_types):
                    state_top_saltenv = six.text_type(state_top_saltenv)
    
                for saltenv in [state_top_saltenv] if state_top_saltenv \
                        else self._get_envs():
                    contents = self.client.cache_file(
                        self.opts['state_top'],
                        saltenv
                    )
                    if contents:
                        found = found + 1
                        tops[saltenv].append(
                            compile_template(
                                contents,
                                self.state.rend,
                                self.state.opts['renderer'],
                                self.state.opts['renderer_blacklist'],
                                self.state.opts['renderer_whitelist'],
                                saltenv=saltenv
                            )
                        )
                    else:
                        tops[saltenv].append({})
                        log.debug('No contents loaded for saltenv \'%s\'', saltenv)
    
                if found > 1 and merging_strategy == 'merge' and not self.opts.get('env_order', None):
                    log.warning(
                        'top_file_merging_strategy is set to \'%s\' and '
                        'multiple top files were found. Merging order is not '
                        'deterministic, it may be desirable to either set '
                        'top_file_merging_strategy to \'same\' or use the '
                        '\'env_order\' configuration parameter to specify the '
                        'merging order.', merging_strategy
                    )
    
            if found == 0:
                log.debug(
                    'No contents found in top file. If this is not expected, '
                    'verify that the \'file_roots\' specified in \'etc/master\' '
                    'are accessible. The \'file_roots\' configuration is: %s',
                    repr(self.state.opts['file_roots'])
                )
    
            # Search initial top files for includes
            for saltenv, ctops in six.iteritems(tops):
                for ctop in ctops:
                    if 'include' not in ctop:
                        continue
                    for sls in ctop['include']:
                        include[saltenv].append(sls)
                    ctop.pop('include')
            # Go through the includes and pull out the extra tops and add them
            while include:
                pops = []
                for saltenv, states in six.iteritems(include):
                    pops.append(saltenv)
                    if not states:
                        continue
                    for sls_match in states:
                        for sls in fnmatch.filter(self.avail[saltenv], sls_match):
                            if sls in done[saltenv]:
                                continue
                            tops[saltenv].append(
                                compile_template(
                                    self.client.get_state(
                                        sls,
                                        saltenv
                                    ).get('dest', False),
                                    self.state.rend,
                                    self.state.opts['renderer'],
                                    self.state.opts['renderer_blacklist'],
                                    self.state.opts['renderer_whitelist'],
                                    saltenv
                                )
                            )
                            done[saltenv].append(sls)
                for saltenv in pops:
                    if saltenv in include:
                        include.pop(saltenv)
            return tops
class Get_top(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Returns the high data derived from the top file
            '''
            try:
                tops = self.get_tops()
            except SaltRenderError as err:
                log.error('Unable to render top file: %s', err.error)
                return {}
            return self.merge_tops(tops)
class Compile_highstate(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Return just the highstate or the errors
            '''
            err = []
            top = self.get_top()
            err += self.verify_tops(top)
            matches = self.top_matches(top)
            high, errors = self.render_highstate(matches)
            err += errors
    
            if err:
                return err
    
            return high
class Compile_low_chunks(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Compile the highstate but don't run it, return the low chunks to
            see exactly what the highstate will execute
            '''
            top = self.get_top()
            matches = self.top_matches(top)
            high, errors = self.render_highstate(matches)
    
            # If there is extension data reconcile it
            high, ext_errors = self.state.reconcile_extend(high)
            errors += ext_errors
    
            # Verify that the high data is structurally sound
            errors += self.state.verify_high(high)
            high, req_in_errors = self.state.requisite_in(high)
            errors += req_in_errors
            high = self.state.apply_exclude(high)
    
            if errors:
                return errors
    
            # Compile and verify the raw chunks
            chunks = self.state.compile_high_data(high)
    
            return chunks
class Compile_state_usage(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Return all used and unused states for the minion based on the top match data
            '''
            err = []
            top = self.get_top()
            err += self.verify_tops(top)
    
            if err:
                return err
    
            matches = self.top_matches(top)
            state_usage = {}
    
            for saltenv, states in self.avail.items():
                env_usage = {
                    'used': [],
                    'unused': [],
                    'count_all': 0,
                    'count_used': 0,
                    'count_unused': 0
                }
    
                env_matches = matches.get(saltenv)
    
                for state in states:
                    env_usage['count_all'] += 1
                    if state in env_matches:
                        env_usage['count_used'] += 1
                        env_usage['used'].append(state)
                    else:
                        env_usage['count_unused'] += 1
                        env_usage['unused'].append(state)
    
                state_usage[saltenv] = env_usage
    
            return state_usage
class Compile_master(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''
            Return the state data from the master
            '''
            load = {'grains': self.grains,
                    'opts': self.opts,
                    'cmd': '_master_state'}
            try:
                return self.channel.send(load, tries=3, timeout=72000)
            except SaltReqTimeoutError:
                return {}
