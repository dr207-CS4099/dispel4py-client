# from dispel4py.core import GenericPE
# from dispel4py.base import IterativePE, ConsumerPE, ProducerPE
# class Pub_connect(ProducerPE):
#     def __init__(self):
#         ProducerPE.__init__(self)
#     def _process(self):
#         '''
#         Create and connect this thread's zmq socket. If a publisher socket
#         already exists "pub_close" is called before creating and connecting a
#         new socket.
#         '''
#         if self.pub_sock:
#             self.pub_close()
#         ctx = zmq.Context.instance()
#         self._sock_data.sock = ctx.socket(zmq.PUSH)
#         self.pub_sock.setsockopt(zmq.LINGER, -1)
#         if self.opts.get('ipc_mode', '') == 'tcp':
#             pull_uri = 'tcp://127.0.0.1:{0}'.format(
#                 self.opts.get('tcp_master_publish_pull', 4514)
#                 )
#         else:
#             pull_uri = 'ipc://{0}'.format(
#                 os.path.join(self.opts['sock_dir'], 'publish_pull.ipc')
#                 )
#         log.debug("Connecting to pub server: %s", pull_uri)
#         self.pub_sock.connect(pull_uri)
#         return self._sock_data.sock
    

# class Removed(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#             '''
#             Ensure that the named snap package is not installed
        
#             name
#                 The snap package
#             '''
        
#             ret = {'name': name,
#                    'changes': {},
#                    'pchanges': {},
#                    'result': None,
#                    'comment': ''}
        
#             old = __salt__['snap.versions_installed'](name)
#             if not old:
#                 ret['comment'] = 'Package {0} is not installed'.format(name)
#                 ret['result'] = True
#                 return ret
        
#             if __opts__['test']:
#                 ret['comment'] = 'Package {0} would have been removed'.format(name)
#                 ret['result'] = None
#                 ret['pchanges']['old'] = old[0]['version']
#                 ret['pchanges']['new'] = None
#                 return ret
        
#             remove = __salt__['snap.remove'](name)
#             ret['comment'] = 'Package {0} removed'.format(name)
#             ret['result'] = True
#             ret['changes']['old'] = old[0]['version']
#             ret['changes']['new'] = None
#             return ret
# class _get_queue(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, config):
#         '''
#             Check the context for the notifier and construct it if not present
#             '''
        
#             if 'watchdog.observer' not in __context__:
#                 queue = collections.deque()
#                 observer = Observer()
#                 for path in config.get('directories', {}):
#                     path_params = config.get('directories').get(path)
#                     masks = path_params.get('mask', DEFAULT_MASK)
#                     event_handler = Handler(queue, masks)
#                     observer.schedule(event_handler, path)
        
#                 observer.start()
        
#                 __context__['watchdog.observer'] = observer
#                 __context__['watchdog.queue'] = queue
        
#             return __context__['watchdog.queue']
# class Beacon(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, config):
#         '''
#             Watch the configured directories
        
#             Example Config
        
#             .. code-block:: yaml
        
#                 beacons:
#                   watchdog:
#                     - directories:
#                         /path/to/dir:
#                           mask:
#                             - create
#                             - modify
#                             - delete
#                             - move
        
#             The mask list can contain the following events (the default mask is create,
#             modify delete, and move):
#             * create  - File or directory is created in watched directory
#             * modify  - The watched directory is modified
#             * delete  - File or directory is deleted from watched directory
#             * move    - File or directory is moved or renamed in the watched directory
#             '''
        
#             _config = {}
#             list(map(_config.update, config))
        
#             queue = _get_queue(_config)
        
#             ret = []
#             while queue:
#                 ret.append(to_salt_event(queue.popleft()))
        
#             return ret
# class Bounce_cluster(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Bounce all Traffic Server nodes in the cluster. Bouncing Traffic Server
#             shuts down and immediately restarts Traffic Server, node-by-node.
        
#             .. code-block:: yaml
        
#                 bounce_ats_cluster:
#                   trafficserver.bounce_cluster
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'result': None,
#                    'comment': ''}
        
#             if __opts__['test']:
#                 ret['comment'] = 'Bouncing cluster'
#                 return ret
        
#             __salt__['trafficserver.bounce_cluster']()
        
#             ret['result'] = True
#             ret['comment'] = 'Bounced cluster'
#             return ret
# class Clear_cluster(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Clears accumulated statistics on all nodes in the cluster.
        
#             .. code-block:: yaml
        
#                 clear_ats_cluster:
#                   trafficserver.clear_cluster
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'result': None,
#                    'comment': ''}
        
#             if __opts__['test']:
#                 ret['comment'] = 'Clearing cluster statistics'
#                 return ret
        
#             __salt__['trafficserver.clear_cluster']()
        
#             ret['result'] = True
#             ret['comment'] = 'Cleared cluster statistics'
#             return ret
# class Clear_node(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Clears accumulated statistics on the local node.
        
#             .. code-block:: yaml
        
#                 clear_ats_node:
#                   trafficserver.clear_node
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'result': None,
#                    'comment': ''}
        
#             if __opts__['test']:
#                 ret['comment'] = 'Clearing local node statistics'
#                 return ret
        
#             __salt__['trafficserver.clear_node']()
        
#             ret['result'] = True
#             ret['comment'] = 'Cleared local node statistics'
#             return ret
# class Restart_cluster(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Restart the traffic_manager process and the traffic_server process on all
#             the nodes in a cluster.
        
#             .. code-block:: bash
        
#                 restart_ats_cluster:
#                   trafficserver.restart_cluster
        
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'result': None,
#                    'comment': ''}
        
#             if __opts__['test']:
#                 ret['comment'] = 'Restarting cluster'
#                 return ret
        
#             __salt__['trafficserver.restart_cluster']()
        
#             ret['result'] = True
#             ret['comment'] = 'Restarted cluster'
#             return ret
# class Shutdown(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Shut down Traffic Server on the local node.
        
#             .. code-block:: yaml
        
#                 shutdown_ats:
#                   trafficserver.shutdown
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'result': None,
#                    'comment': ''}
        
#             if __opts__['test']:
#                 ret['comment'] = 'Shutting down local node'
#                 return ret
        
#             __salt__['trafficserver.shutdown']()
        
#             ret['result'] = True
#             ret['comment'] = 'Shutdown local node'
#             return ret
# class Startup(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Start Traffic Server on the local node.
        
#             .. code-block:: yaml
        
#                 startup_ats:
#                   trafficserver.startup
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'result': None,
#                    'comment': ''}
        
#             if __opts__['test']:
#                 ret['comment'] = 'Starting up local node'
#                 return ret
        
#             __salt__['trafficserver.startup']()
        
#             ret['result'] = True
#             ret['comment'] = 'Starting up local node'
#             return ret
# class Refresh(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Initiate a Traffic Server configuration file reread. Use this command to
#             update the running configuration after any configuration file modification.
        
#             The timestamp of the last reconfiguration event (in seconds since epoch) is
#             published in the proxy.node.config.reconfigure_time metric.
        
#             .. code-block:: yaml
        
#                 refresh_ats:
#                   trafficserver.refresh
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'result': None,
#                    'comment': ''}
        
#             if __opts__['test']:
#                 ret['comment'] = 'Refreshing local node configuration'
#                 return ret
        
#             __salt__['trafficserver.refresh']()
        
#             ret['result'] = True
#             ret['comment'] = 'Refreshed local node configuration'
#             return ret
# class Zero_cluster(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Reset performance statistics to zero across the cluster.
        
#             .. code-block:: yaml
        
#                 zero_ats_cluster:
#                   trafficserver.zero_cluster
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'result': None,
#                    'comment': ''}
        
#             if __opts__['test']:
#                 ret['comment'] = 'Zeroing cluster statistics'
#                 return ret
        
#             __salt__['trafficserver.zero_cluster']()
        
#             ret['result'] = True
#             ret['comment'] = 'Zeroed cluster statistics'
#             return ret
# class Zero_node(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Reset performance statistics to zero on the local node.
        
#             .. code-block:: yaml
        
#                 zero_ats_node:
#                   trafficserver.zero_node
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'result': None,
#                    'comment': ''}
        
#             if __opts__['test']:
#                 ret['comment'] = 'Zeroing local node statistics'
#                 return ret
        
#             __salt__['trafficserver.zero_node']()
        
#             ret['result'] = True
#             ret['comment'] = 'Zeroed local node statistics'
#             return ret
# class Avail_locations(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, call=None):
#         '''
#             Return a dict of all available VM locations on the cloud provider with
#             relevant data
#             '''
#             if call == 'action':
#                 raise SaltCloudSystemExit(
#                     'The avail_locations function must be called with '
#                     '-f or --function, or with the --list-locations option'
#                 )
        
#             params = {'Action': 'DescribeRegions'}
#             items = query(params=params)
        
#             ret = {}
#             for region in items['Regions']['Region']:
#                 ret[region['RegionId']] = {}
#                 for item in region:
#                     ret[region['RegionId']][item] = six.text_type(region[item])
        
#             return ret
# class Avail_sizes(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, call=None):
#         '''
#             Return a list of the image sizes that are on the provider
#             '''
#             if call == 'action':
#                 raise SaltCloudSystemExit(
#                     'The avail_sizes function must be called with '
#                     '-f or --function, or with the --list-sizes option'
#                 )
        
#             params = {'Action': 'DescribeInstanceTypes'}
#             items = query(params=params)
        
#             ret = {}
#             for image in items['InstanceTypes']['InstanceType']:
#                 ret[image['InstanceTypeId']] = {}
#                 for item in image:
#                     ret[image['InstanceTypeId']][item] = six.text_type(image[item])
        
#             return ret
# class List_availability_zones(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, call=None):
#         '''
#             List all availability zones in the current region
#             '''
#             ret = {}
        
#             params = {'Action': 'DescribeZones',
#                       'RegionId': get_location()}
#             items = query(params)
        
#             for zone in items['Zones']['Zone']:
#                 ret[zone['ZoneId']] = {}
#                 for item in zone:
#                     ret[zone['ZoneId']][item] = six.text_type(zone[item])
        
#             return ret
# class List_nodes_min(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, call=None):
#         '''
#             Return a list of the VMs that are on the provider. Only a list of VM names,
#             and their state, is returned. This is the minimum amount of information
#             needed to check for existing VMs.
#             '''
#             if call == 'action':
#                 raise SaltCloudSystemExit(
#                     'The list_nodes_min function must be called with -f or --function.'
#                 )
        
#             ret = {}
#             location = get_location()
#             params = {
#                 'Action': 'DescribeInstanceStatus',
#                 'RegionId': location,
#             }
#             nodes = query(params)
        
#             log.debug(
#                 'Total %s instance found in Region %s',
#                 nodes['TotalCount'], location
#             )
#             if 'Code' in nodes or nodes['TotalCount'] == 0:
#                 return ret
        
#             for node in nodes['InstanceStatuses']['InstanceStatus']:
#                 ret[node['InstanceId']] = {}
#                 for item in node:
#                     ret[node['InstanceId']][item] = node[item]
        
#             return ret
# class List_nodes(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, call=None):
#         '''
#             Return a list of the VMs that are on the provider
#             '''
#             if call == 'action':
#                 raise SaltCloudSystemExit(
#                     'The list_nodes function must be called with -f or --function.'
#                 )
        
#             nodes = list_nodes_full()
#             ret = {}
#             for instanceId in nodes:
#                 node = nodes[instanceId]
#                 ret[node['name']] = {
#                     'id': node['id'],
#                     'name': node['name'],
#                     'public_ips': node['public_ips'],
#                     'private_ips': node['private_ips'],
#                     'size': node['size'],
#                     'state': six.text_type(node['state']),
#                 }
#             return ret
# class List_nodes_full(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, call=None):
#         '''
#             Return a list of the VMs that are on the provider
#             '''
#             if call == 'action':
#                 raise SaltCloudSystemExit(
#                     'The list_nodes_full function must be called with -f '
#                     'or --function.'
#                 )
        
#             ret = {}
#             location = get_location()
#             params = {
#                 'Action': 'DescribeInstanceStatus',
#                 'RegionId': location,
#                 'PageSize': '50'
#             }
#             result = query(params=params)
        
#             log.debug(
#                 'Total %s instance found in Region %s',
#                 result['TotalCount'], location
#             )
#             if 'Code' in result or result['TotalCount'] == 0:
#                 return ret
        
#             # aliyun max 100 top instance in api
#             result_instancestatus = result['InstanceStatuses']['InstanceStatus']
#             if result['TotalCount'] > 50:
#                 params['PageNumber'] = '2'
#                 result = query(params=params)
#                 result_instancestatus.update(result['InstanceStatuses']['InstanceStatus'])
        
#             for node in result_instancestatus:
        
#                 instanceId = node.get('InstanceId', '')
        
#                 params = {
#                     'Action': 'DescribeInstanceAttribute',
#                     'InstanceId': instanceId
#                 }
#                 items = query(params=params)
#                 if 'Code' in items:
#                     log.warning('Query instance:%s attribute failed', instanceId)
#                     continue
        
#                 name = items['InstanceName']
#                 ret[name] = {
#                     'id': items['InstanceId'],
#                     'name': name,
#                     'image': items['ImageId'],
#                     'size': 'TODO',
#                     'state': items['Status']
#                 }
#                 for item in items:
#                     value = items[item]
#                     if value is not None:
#                         value = six.text_type(value)
#                     if item == "PublicIpAddress":
#                         ret[name]['public_ips'] = items[item]['IpAddress']
#                     if item == "InnerIpAddress" and 'private_ips' not in ret[name]:
#                         ret[name]['private_ips'] = items[item]['IpAddress']
#                     if item == 'VpcAttributes':
#                         vpc_ips = items[item]['PrivateIpAddress']['IpAddress']
#                         if vpc_ips:
#                             ret[name]['private_ips'] = vpc_ips
#                     ret[name][item] = value
        
#             provider = __active_provider_name__ or 'aliyun'
#             if ':' in provider:
#                 comps = provider.split(':')
#                 provider = comps[0]
        
#             __opts__['update_cachedir'] = True
#             __utils__['cloud.cache_node_list'](ret, provider, __opts__)
        
#             return ret
# class List_securitygroup(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, call=None):
#         '''
#             Return a list of security group
#             '''
#             if call == 'action':
#                 raise SaltCloudSystemExit(
#                     'The list_nodes function must be called with -f or --function.'
#                 )
        
#             params = {
#                 'Action': 'DescribeSecurityGroups',
#                 'RegionId': get_location(),
#                 'PageSize': '50',
#             }
        
#             result = query(params)
#             if 'Code' in result:
#                 return {}
        
#             ret = {}
#             for sg in result['SecurityGroups']['SecurityGroup']:
#                 ret[sg['SecurityGroupId']] = {}
#                 for item in sg:
#                     ret[sg['SecurityGroupId']][item] = sg[item]
        
#             return ret
# class Get_image(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, vm_):
#         '''
#             Return the image object to use
#             '''
#             images = avail_images()
#             vm_image = six.text_type(config.get_cloud_config_value(
#                 'image', vm_, __opts__, search_global=False
#             ))
        
#             if not vm_image:
#                 raise SaltCloudNotFound('No image specified for this VM.')
        
#             if vm_image and six.text_type(vm_image) in images:
#                 return images[vm_image]['ImageId']
#             raise SaltCloudNotFound(
#                 'The specified image, \'{0}\', could not be found.'.format(vm_image)
#             )
# class Get_securitygroup(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, vm_):
#         '''
#             Return the security group
#             '''
#             sgs = list_securitygroup()
#             securitygroup = config.get_cloud_config_value(
#                 'securitygroup', vm_, __opts__, search_global=False
#             )
        
#             if not securitygroup:
#                 raise SaltCloudNotFound('No securitygroup ID specified for this VM.')
        
#             if securitygroup and six.text_type(securitygroup) in sgs:
#                 return sgs[securitygroup]['SecurityGroupId']
#             raise SaltCloudNotFound(
#                 'The specified security group, \'{0}\', could not be found.'.format(
#                     securitygroup)
#             )
# class Get_size(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, vm_):
#         '''
#             Return the VM's size. Used by create_node().
#             '''
#             sizes = avail_sizes()
#             vm_size = six.text_type(config.get_cloud_config_value(
#                 'size', vm_, __opts__, search_global=False
#             ))
        
#             if not vm_size:
#                 raise SaltCloudNotFound('No size specified for this VM.')
        
#             if vm_size and six.text_type(vm_size) in sizes:
#                 return sizes[vm_size]['InstanceTypeId']
        
#             raise SaltCloudNotFound(
#                 'The specified size, \'{0}\', could not be found.'.format(vm_size)
#             )
# class __get_location(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, vm_):
#         '''
#             Return the VM's location
#             '''
#             locations = avail_locations()
#             vm_location = six.text_type(config.get_cloud_config_value(
#                 'location', vm_, __opts__, search_global=False
#             ))
        
#             if not vm_location:
#                 raise SaltCloudNotFound('No location specified for this VM.')
        
#             if vm_location and six.text_type(vm_location) in locations:
#                 return locations[vm_location]['RegionId']
#             raise SaltCloudNotFound(
#                 'The specified location, \'{0}\', could not be found.'.format(
#                     vm_location
#                 )
#             )
# class Create_node(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, kwargs):
#         '''
#             Convenience function to make the rest api call for node creation.
#             '''
#             if not isinstance(kwargs, dict):
#                 kwargs = {}
        
#             # Required parameters
#             params = {
#                 'Action': 'CreateInstance',
#                 'InstanceType': kwargs.get('size_id', ''),
#                 'RegionId': kwargs.get('region_id', DEFAULT_LOCATION),
#                 'ImageId': kwargs.get('image_id', ''),
#                 'SecurityGroupId': kwargs.get('securitygroup_id', ''),
#                 'InstanceName': kwargs.get('name', ''),
#             }
        
#             # Optional parameters'
#             optional = [
#                 'InstanceName', 'InternetChargeType',
#                 'InternetMaxBandwidthIn', 'InternetMaxBandwidthOut',
#                 'HostName', 'Password', 'SystemDisk.Category', 'VSwitchId'
#                 # 'DataDisk.n.Size', 'DataDisk.n.Category', 'DataDisk.n.SnapshotId'
#             ]
        
#             for item in optional:
#                 if item in kwargs:
#                     params.update({item: kwargs[item]})
        
#             # invoke web call
#             result = query(params)
#             return result['InstanceId']
# class Create(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, vm_):
#         '''
#             Create a single VM from a data dict
#             '''
#             try:
#                 # Check for required profile parameters before sending any API calls.
#                 if vm_['profile'] and config.is_profile_configured(__opts__,
#                                                                    __active_provider_name__ or 'aliyun',
#                                                                    vm_['profile'],
#                                                                    vm_=vm_) is False:
#                     return False
#             except AttributeError:
#                 pass
        
#             __utils__['cloud.fire_event'](
#                 'event',
#                 'starting create',
#                 'salt/cloud/{0}/creating'.format(vm_['name']),
#                 args=__utils__['cloud.filter_event']('creating', vm_, ['name', 'profile', 'provider', 'driver']),
#                 sock_dir=__opts__['sock_dir'],
#                 transport=__opts__['transport']
#             )
        
#             log.info('Creating Cloud VM %s', vm_['name'])
#             kwargs = {
#                 'name': vm_['name'],
#                 'size_id': get_size(vm_),
#                 'image_id': get_image(vm_),
#                 'region_id': __get_location(vm_),
#                 'securitygroup_id': get_securitygroup(vm_),
#             }
#             if 'vswitch_id' in vm_:
#                 kwargs['VSwitchId'] = vm_['vswitch_id']
#             if 'internet_chargetype' in vm_:
#                 kwargs['InternetChargeType'] = vm_['internet_chargetype']
#             if 'internet_maxbandwidthin' in vm_:
#                 kwargs['InternetMaxBandwidthIn'] = six.text_type(vm_['internet_maxbandwidthin'])
#             if 'internet_maxbandwidthout' in vm_:
#                 kwargs['InternetMaxBandwidthOut'] = six.text_type(vm_['internet_maxbandwidthOut'])
#             if 'hostname' in vm_:
#                 kwargs['HostName'] = vm_['hostname']
#             if 'password' in vm_:
#                 kwargs['Password'] = vm_['password']
#             if 'instance_name' in vm_:
#                 kwargs['InstanceName'] = vm_['instance_name']
#             if 'systemdisk_category' in vm_:
#                 kwargs['SystemDisk.Category'] = vm_['systemdisk_category']
        
#             __utils__['cloud.fire_event'](
#                 'event',
#                 'requesting instance',
#                 'salt/cloud/{0}/requesting'.format(vm_['name']),
#                 args=__utils__['cloud.filter_event']('requesting', kwargs, list(kwargs)),
#                 sock_dir=__opts__['sock_dir'],
#                 transport=__opts__['transport']
#             )
        
#             try:
#                 ret = create_node(kwargs)
#             except Exception as exc:
#                 log.error(
#                     'Error creating %s on Aliyun ECS\n\n'
#                     'The following exception was thrown when trying to '
#                     'run the initial deployment: %s',
#                     vm_['name'], six.text_type(exc),
#                     # Show the traceback if the debug logging level is enabled
#                     exc_info_on_loglevel=logging.DEBUG
#                 )
#                 return False
#             # repair ip address error and start vm
#             time.sleep(8)
#             params = {'Action': 'StartInstance',
#                       'InstanceId': ret}
#             query(params)
        
#             def __query_node_data(vm_name):
#                 data = show_instance(vm_name, call='action')
#                 if not data:
#                     # Trigger an error in the wait_for_ip function
#                     return False
#                 if data.get('PublicIpAddress', None) is not None:
#                     return data
        
#             try:
#                 data = salt.utils.cloud.wait_for_ip(
#                     __query_node_data,
#                     update_args=(vm_['name'],),
#                     timeout=config.get_cloud_config_value(
#                         'wait_for_ip_timeout', vm_, __opts__, default=10 * 60),
#                     interval=config.get_cloud_config_value(
#                         'wait_for_ip_interval', vm_, __opts__, default=10),
#                 )
#             except (SaltCloudExecutionTimeout, SaltCloudExecutionFailure) as exc:
#                 try:
#                     # It might be already up, let's destroy it!
#                     destroy(vm_['name'])
#                 except SaltCloudSystemExit:
#                     pass
#                 finally:
#                     raise SaltCloudSystemExit(six.text_type(exc))
        
#             if data['public_ips']:
#                 ssh_ip = data['public_ips'][0]
#             elif data['private_ips']:
#                 ssh_ip = data['private_ips'][0]
#             else:
#                 log.info('No available ip:cant connect to salt')
#                 return False
#             log.debug('VM %s is now running', ssh_ip)
#             vm_['ssh_host'] = ssh_ip
        
#             # The instance is booted and accessible, let's Salt it!
#             ret = __utils__['cloud.bootstrap'](vm_, __opts__)
#             ret.update(data)
        
#             log.info('Created Cloud VM \'%s\'', vm_['name'])
#             log.debug(
#                 '\'%s\' VM creation details:\n%s',
#                 vm_['name'], pprint.pformat(data)
#             )
        
#             __utils__['cloud.fire_event'](
#                 'event',
#                 'created instance',
#                 'salt/cloud/{0}/created'.format(vm_['name']),
#                 args=__utils__['cloud.filter_event']('created', vm_, ['name', 'profile', 'provider', 'driver']),
#                 sock_dir=__opts__['sock_dir'],
#                 transport=__opts__['transport']
#             )
        
#             return ret
# class Query(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, params=None):
#         '''
#             Make a web call to aliyun ECS REST API
#             '''
#             path = 'https://ecs-cn-hangzhou.aliyuncs.com'
        
#             access_key_id = config.get_cloud_config_value(
#                 'id', get_configured_provider(), __opts__, search_global=False
#             )
#             access_key_secret = config.get_cloud_config_value(
#                 'key', get_configured_provider(), __opts__, search_global=False
#             )
        
#             timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        
#             # public interface parameters
#             parameters = {
#                 'Format': 'JSON',
#                 'Version': DEFAULT_ALIYUN_API_VERSION,
#                 'AccessKeyId': access_key_id,
#                 'SignatureVersion': '1.0',
#                 'SignatureMethod': 'HMAC-SHA1',
#                 'SignatureNonce': six.text_type(uuid.uuid1()),
#                 'TimeStamp': timestamp,
#             }
        
#             # include action or function parameters
#             if params:
#                 parameters.update(params)
        
#             # Calculate the string for Signature
#             signature = _compute_signature(parameters, access_key_secret)
#             parameters['Signature'] = signature
        
#             request = requests.get(path, params=parameters, verify=True)
#             if request.status_code != 200:
#                 raise SaltCloudSystemExit(
#                     'An error occurred while querying aliyun ECS. HTTP Code: {0}  '
#                     'Error: \'{1}\''.format(
#                         request.status_code,
#                         request.text
#                     )
#                 )
        
#             log.debug(request.url)
        
#             content = request.text
        
#             result = salt.utils.json.loads(content)
#             if 'Code' in result:
#                 raise SaltCloudSystemExit(
#                     pprint.pformat(result.get('Message', {}))
#                 )
#             return result
# class _write_adminfile(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, kwargs):
#         '''
#             Create a temporary adminfile based on the keyword arguments passed to
#             pkg.install.
#             '''
#             # Set the adminfile default variables
#             email = kwargs.get('email', '')
#             instance = kwargs.get('instance', 'quit')
#             partial = kwargs.get('partial', 'nocheck')
#             runlevel = kwargs.get('runlevel', 'nocheck')
#             idepend = kwargs.get('idepend', 'nocheck')
#             rdepend = kwargs.get('rdepend', 'nocheck')
#             space = kwargs.get('space', 'nocheck')
#             setuid = kwargs.get('setuid', 'nocheck')
#             conflict = kwargs.get('conflict', 'nocheck')
#             action = kwargs.get('action', 'nocheck')
#             basedir = kwargs.get('basedir', 'default')
        
#             # Make tempfile to hold the adminfile contents.
#             adminfile = salt.utils.files.mkstemp(prefix="salt-")
        
#             def _write_line(fp_, line):
#                 fp_.write(salt.utils.stringutils.to_str(line))
        
#             with salt.utils.files.fopen(adminfile, 'w') as fp_:
#                 _write_line(fp_, 'email={0}\n'.format(email))
#                 _write_line(fp_, 'instance={0}\n'.format(instance))
#                 _write_line(fp_, 'partial={0}\n'.format(partial))
#                 _write_line(fp_, 'runlevel={0}\n'.format(runlevel))
#                 _write_line(fp_, 'idepend={0}\n'.format(idepend))
#                 _write_line(fp_, 'rdepend={0}\n'.format(rdepend))
#                 _write_line(fp_, 'space={0}\n'.format(space))
#                 _write_line(fp_, 'setuid={0}\n'.format(setuid))
#                 _write_line(fp_, 'conflict={0}\n'.format(conflict))
#                 _write_line(fp_, 'action={0}\n'.format(action))
#                 _write_line(fp_, 'basedir={0}\n'.format(basedir))
        
#             return adminfile
# class Iter_transport_opts(ConsumerPE):
#     def __init__(self):
#         ConsumerPE.__init__(self)
#     def _process(self, opts):
#         '''
#             Yield transport, opts for all master configured transports
#             '''
#             transports = set()
        
#             for transport, opts_overrides in six.iteritems(opts.get('transport_opts', {})):
#                 t_opts = dict(opts)
#                 t_opts.update(opts_overrides)
#                 t_opts['transport'] = transport
#                 transports.add(transport)
#                 yield transport, t_opts
        
#             if opts['transport'] not in transports:
#                 yield opts['transport'], opts
# class Event(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, name):
#         '''
#             Chekcs for a specific event match and returns result True if the match
#             happens
        
#             USAGE:
        
#             .. code-block:: yaml
        
#                 salt/foo/*/bar:
#                   check.event
        
#                 run_remote_ex:
#                   local.cmd:
#                     - tgt: '*'
#                     - func: test.ping
#                     - require:
#                       - check: salt/foo/*/bar
#             '''
#             ret = {'name': name,
#                    'changes': {},
#                    'comment': '',
#                    'result': False}
        
#             for event in __events__:
#                 if salt.utils.stringutils.expr_match(event['tag'], name):
#                     ret['result'] = True
        
#             return ret
# class Map_clonemode(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, vm_info):
#         """
#             Convert the virtualbox config file values for clone_mode into the integers the API requires
#             """
#             mode_map = {
#               'state': 0,
#               'child': 1,
#               'all':   2
#             }
        
#             if not vm_info:
#                 return DEFAULT_CLONE_MODE
        
#             if 'clonemode' not in vm_info:
#                 return DEFAULT_CLONE_MODE
        
#             if vm_info['clonemode'] in mode_map:
#                 return mode_map[vm_info['clonemode']]
#             else:
#                 raise SaltCloudSystemExit(
#                     "Illegal clonemode for virtualbox profile.  Legal values are: {}".format(','.join(mode_map.keys()))
#                 )
# class Create(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, vm_info):
#         '''
#             Creates a virtual machine from the given VM information
        
#             This is what is used to request a virtual machine to be created by the
#             cloud provider, wait for it to become available, and then (optionally) log
#             in and install Salt on it.
        
#             Events fired:
        
#             This function fires the event ``salt/cloud/vm_name/creating``, with the
#             payload containing the names of the VM, profile, and provider.
        
#             @param vm_info
        
#             .. code-block:: text
        
#                 {
#                     name: <str>
#                     profile: <dict>
#                     driver: <provider>:<profile>
#                     clonefrom: <vm_name>
#                     clonemode: <mode> (default: state, choices: state, child, all)
#                 }
        
#             @type vm_info dict
#             @return dict of resulting vm. !!!Passwords can and should be included!!!
#             '''
#             try:
#                 # Check for required profile parameters before sending any API calls.
#                 if vm_info['profile'] and config.is_profile_configured(
#                     __opts__,
#                         __active_provider_name__ or 'virtualbox',
#                     vm_info['profile']
#                 ) is False:
#                     return False
#             except AttributeError:
#                 pass
        
#             vm_name = vm_info["name"]
#             deploy = config.get_cloud_config_value(
#                 'deploy', vm_info, __opts__, search_global=False, default=True
#             )
#             wait_for_ip_timeout = config.get_cloud_config_value(
#                 'wait_for_ip_timeout', vm_info, __opts__, default=60
#             )
#             boot_timeout = config.get_cloud_config_value(
#                 'boot_timeout', vm_info, __opts__, default=60 * 1000
#             )
#             power = config.get_cloud_config_value(
#                 'power_on', vm_info, __opts__, default=False
#             )
#             key_filename = config.get_cloud_config_value(
#                 'private_key', vm_info, __opts__, search_global=False, default=None
#             )
#             clone_mode = map_clonemode(vm_info)
#             wait_for_pattern = vm_info['waitforpattern'] if 'waitforpattern' in vm_info.keys() else None
#             interface_index = vm_info['interfaceindex'] if 'interfaceindex' in vm_info.keys() else 0
        
#             log.debug("Going to fire event: starting create")
#             __utils__['cloud.fire_event'](
#                 'event',
#                 'starting create',
#                 'salt/cloud/{0}/creating'.format(vm_info['name']),
#                 args=__utils__['cloud.filter_event']('creating', vm_info, ['name', 'profile', 'provider', 'driver']),
#                 sock_dir=__opts__['sock_dir'],
#                 transport=__opts__['transport']
#             )
        
#             # to create the virtual machine.
#             request_kwargs = {
#                 'name': vm_info['name'],
#                 'clone_from': vm_info['clonefrom'],
#                 'clone_mode': clone_mode
#             }
        
#             __utils__['cloud.fire_event'](
#                 'event',
#                 'requesting instance',
#                 'salt/cloud/{0}/requesting'.format(vm_info['name']),
#                 args=__utils__['cloud.filter_event']('requesting', request_kwargs, list(request_kwargs)),
#                 sock_dir=__opts__['sock_dir'],
#                 transport=__opts__['transport']
#             )
#             vm_result = vb_clone_vm(**request_kwargs)
        
#             # Booting and deploying if needed
#             if power:
#                 vb_start_vm(vm_name, timeout=boot_timeout)
#                 ips = vb_wait_for_network_address(wait_for_ip_timeout, machine_name=vm_name, wait_for_pattern=wait_for_pattern)
        
#                 if ips:
#                     ip = ips[interface_index]
#                     log.info("[ %s ] IPv4 is: %s", vm_name, ip)
#                     # ssh or smb using ip and install salt only if deploy is True
#                     if deploy:
#                         vm_info['key_filename'] = key_filename
#                         vm_info['ssh_host'] = ip
        
#                         res = __utils__['cloud.bootstrap'](vm_info, __opts__)
#                         vm_result.update(res)
        
#             __utils__['cloud.fire_event'](
#                 'event',
#                 'created machine',
#                 'salt/cloud/{0}/created'.format(vm_info['name']),
#                 args=__utils__['cloud.filter_event']('created', vm_result, list(vm_result)),
#                 sock_dir=__opts__['sock_dir'],
#                 transport=__opts__['transport']
#             )
        
#             # Passwords should be included in this object!!
#             return vm_result
# class Install(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, runas=None):
#         '''
#             Install RVM system-wide
        
#             runas
#                 The user under which to run the rvm installer script. If not specified,
#                 then it be run as the user under which Salt is running.
        
#             CLI Example:
        
#             .. code-block:: bash
        
#                 salt '*' rvm.install
#             '''
#             # RVM dependencies on Ubuntu 10.04:
#             #   bash coreutils gzip bzip2 gawk sed curl git-core subversion
#             installer = 'https://raw.githubusercontent.com/rvm/rvm/master/binscripts/rvm-installer'
#             ret = __salt__['cmd.run_all'](
#                 # the RVM installer automatically does a multi-user install when it is
#                 # invoked with root privileges
#                 'curl -Ls {installer} | bash -s stable'.format(installer=installer),
#                 runas=runas,
#                 python_shell=True
#             )
#             if ret['retcode'] > 0:
#                 msg = 'Error encountered while downloading the RVM installer'
#                 if ret['stderr']:
#                     msg += '. stderr follows:\n\n' + ret['stderr']
#                 raise CommandExecutionError(msg)
#             return True
# class List_(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, runas=None):
#         '''
#             List all rvm-installed rubies
        
#             runas
#                 The user under which to run rvm. If not specified, then rvm will be run
#                 as the user under which Salt is running.
        
#             CLI Example:
        
#             .. code-block:: bash
        
#                 salt '*' rvm.list
#             '''
#             rubies = []
#             output = _rvm(['list'], runas=runas)
#             if output:
#                 regex = re.compile(r'^[= ]([*> ]) ([^- ]+)-([^ ]+) \[ (.*) \]')
#                 for line in output.splitlines():
#                     match = regex.match(line)
#                     if match:
#                         rubies.append([
#                             match.group(2), match.group(3), match.group(1) == '*'
#                         ])
#             return rubies
# class Gemset_list_all(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, runas=None):
#         '''
#             List all gemsets for all installed rubies.
        
#             Note that you must have set a default ruby before this can work.
        
#             runas
#                 The user under which to run rvm. If not specified, then rvm will be run
#                 as the user under which Salt is running.
        
#             CLI Example:
        
#             .. code-block:: bash
        
#                 salt '*' rvm.gemset_list_all
#             '''
#             gemsets = {}
#             current_ruby = None
#             output = _rvm_do('default', ['rvm', 'gemset', 'list_all'], runas=runas)
#             if output:
#                 gems_regex = re.compile('^   ([^ ]+)')
#                 gemset_regex = re.compile('^gemsets for ([^ ]+)')
#                 for line in output.splitlines():
#                     match = gemset_regex.match(line)
#                     if match:
#                         current_ruby = match.group(1)
#                         gemsets[current_ruby] = []
#                     match = gems_regex.match(line)
#                     if match:
#                         gemsets[current_ruby].append(match.group(1))
#             return gemsets
# class Interfaces(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, root):
#         '''
#             Generate a dictionary with all available interfaces relative to root.
#             Symlinks are not followed.
        
#             CLI example:
#              .. code-block:: bash
        
#                 salt '*' sysfs.interfaces block/bcache0/bcache
        
#             Output example:
#              .. code-block:: json
        
#                {
#                   "r": [
#                     "state",
#                     "partial_stripes_expensive",
#                     "writeback_rate_debug",
#                     "stripe_size",
#                     "dirty_data",
#                     "stats_total/cache_hits",
#                     "stats_total/cache_bypass_misses",
#                     "stats_total/bypassed",
#                     "stats_total/cache_readaheads",
#                     "stats_total/cache_hit_ratio",
#                     "stats_total/cache_miss_collisions",
#                     "stats_total/cache_misses",
#                     "stats_total/cache_bypass_hits",
#                   ],
#                   "rw": [
#                     "writeback_rate",
#                     "writeback_rate_update_seconds",
#                     "cache_mode",
#                     "writeback_delay",
#                     "label",
#                     "writeback_running",
#                     "writeback_metadata",
#                     "running",
#                     "writeback_rate_p_term_inverse",
#                     "sequential_cutoff",
#                     "writeback_percent",
#                     "writeback_rate_d_term",
#                     "readahead"
#                   ],
#                   "w": [
#                     "stop",
#                     "clear_stats",
#                     "attach",
#                     "detach"
#                   ]
#                }
        
#             .. note::
#               * 'r' interfaces are read-only
#               * 'w' interfaces are write-only (e.g. actions)
#               * 'rw' are interfaces that can both be read or written
#             '''
        
#             root = target(root)
#             if root is False or not os.path.isdir(root):
#                 log.error('SysFS %s not a dir', root)
#                 return False
        
#             readwrites = []
#             reads = []
#             writes = []
        
#             for path, _, files in salt.utils.path.os_walk(root, followlinks=False):
#                 for afile in files:
#                     canpath = os.path.join(path, afile)
        
#                     if not os.path.isfile(canpath):
#                         continue
        
#                     stat_mode = os.stat(canpath).st_mode
#                     is_r = bool(stat.S_IRUSR & stat_mode)
#                     is_w = bool(stat.S_IWUSR & stat_mode)
        
#                     relpath = os.path.relpath(canpath, root)
#                     if is_w:
#                         if is_r:
#                             readwrites.append(relpath)
#                         else:
#                             writes.append(relpath)
#                     elif is_r:
#                         reads.append(relpath)
#                     else:
#                         log.warning('Unable to find any interfaces in %s', canpath)
        
#             return {
#                 'r': reads,
#                 'w': writes,
#                 'rw': readwrites
#             }
# class _get_librato(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, ret=None):
#         '''
#             Return a Librato connection object.
#             '''
#             _options = _get_options(ret)
        
#             conn = librato.connect(
#                 _options.get('email'),
#                 _options.get('api_token'),
#                 sanitizer=librato.sanitize_metric_name,
#                 hostname=_options.get('api_url'))
#             log.info("Connected to librato.")
#             return conn
# class Returner(ConsumerPE):
#     def __init__(self):
#         ConsumerPE.__init__(self)
#     def _process(self, ret):
#         '''
#             Parse the return data and return metrics to Librato.
#             '''
#             librato_conn = _get_librato(ret)
        
#             q = librato_conn.new_queue()
        
#             if ret['fun'] == 'state.highstate':
#                 log.debug('Found returned Highstate data.')
#                 # Calculate the runtimes and number of failed states.
#                 stats = _calculate_runtimes(ret['return'])
#                 log.debug('Batching Metric retcode with %s', ret['retcode'])
#                 q.add('saltstack.highstate.retcode',
#                       ret['retcode'], tags={'Name': ret['id']})
        
#                 log.debug(
#                     'Batching Metric num_failed_jobs with %s',
#                     stats['num_failed_states']
#                 )
#                 q.add('saltstack.highstate.failed_states',
#                       stats['num_failed_states'], tags={'Name': ret['id']})
        
#                 log.debug(
#                     'Batching Metric num_passed_states with %s',
#                     stats['num_passed_states']
#                 )
#                 q.add('saltstack.highstate.passed_states',
#                       stats['num_passed_states'], tags={'Name': ret['id']})
        
#                 log.debug('Batching Metric runtime with %s', stats['runtime'])
#                 q.add('saltstack.highstate.runtime',
#                       stats['runtime'], tags={'Name': ret['id']})
        
#                 log.debug(
#                     'Batching Metric runtime with %s',
#                     stats['num_failed_states'] + stats['num_passed_states']
#                 )
#                 q.add('saltstack.highstate.total_states', stats[
#                       'num_failed_states'] + stats['num_passed_states'], tags={'Name': ret['id']})
        
#             log.info('Sending metrics to Librato.')
#             q.submit()
# class _get_bgp_runner_opts(ProducerPE):
#     def __init__(self):
#         ProducerPE.__init__(self)
#     def _process(self):
#         '''
#             Return the bgp runner options.
#             '''
#             runner_opts = __opts__.get('runners', {}).get('bgp', {})
#             return {
#                 'tgt': runner_opts.get('tgt', _DEFAULT_TARGET),
#                 'tgt_type': runner_opts.get('tgt_type', _DEFAULT_EXPR_FORM),
#                 'display': runner_opts.get('display', _DEFAULT_DISPLAY),
#                 'return_fields': _DEFAULT_INCLUDED_FIELDS + runner_opts.get('return_fields', _DEFAULT_RETURN_FIELDS),
#                 'outputter': runner_opts.get('outputter', _DEFAULT_OUTPUTTER),
#             }
# class Neighbors(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, *asns,**kwargs):
#         '''
#             Search for BGP neighbors details in the mines of the ``bgp.neighbors`` function.
        
#             Arguments:
        
#             asns
#                 A list of AS numbers to search for.
#                 The runner will return only the neighbors of these AS numbers.
        
#             device
#                 Filter by device name (minion ID).
        
#             ip
#                 Search BGP neighbor using the IP address.
#                 In multi-VRF environments, the same IP address could be used by
#                 more than one neighbors, in different routing tables.
        
#             network
#                 Search neighbors within a certain IP network.
        
#             title
#                 Custom title.
        
#             display: ``True``
#                 Display on the screen or return structured object? Default: ``True`` (return on the CLI).
        
#             outputter: ``table``
#                 Specify the outputter name when displaying on the CLI. Default: :mod:`table <salt.output.table_out>`.
        
#             In addition, any field from the output of the ``neighbors`` function
#             from the :mod:`NAPALM BGP module <salt.modules.napalm_bgp.neighbors>` can be used as a filter.
        
#             CLI Example:
        
#             .. code-block:: bash
        
#                 salt-run bgp.neighbors 13335 15169
#                 salt-run bgp.neighbors 13335 ip=172.17.19.1
#                 salt-run bgp.neighbors multipath=True
#                 salt-run bgp.neighbors up=False export_policy=my-export-policy multihop=False
#                 salt-run bgp.neighbors network=192.168.0.0/16
        
#             Output example:
        
#             .. code-block:: text
        
#                 BGP Neighbors for 13335, 15169
#                 ________________________________________________________________________________________________________________________________________________________________
#                 |    Device    | AS Number |         Neighbor Address        | State|#Active/Received/Accepted/Damped |         Policy IN         |         Policy OUT         |
#                 ________________________________________________________________________________________________________________________________________________________________
#                 | edge01.bjm01 |   13335   |          172.17.109.11          |        Established 0/398/398/0         |       import-policy       |        export-policy       |
#                 ________________________________________________________________________________________________________________________________________________________________
#                 | edge01.bjm01 |   13335   |          172.17.109.12          |       Established 397/398/398/0        |       import-policy       |        export-policy       |
#                 ________________________________________________________________________________________________________________________________________________________________
#                 | edge01.flw01 |   13335   |          192.168.172.11         |        Established 1/398/398/0         |       import-policy       |        export-policy       |
#                 ________________________________________________________________________________________________________________________________________________________________
#                 | edge01.oua01 |   13335   |          172.17.109.17          |          Established 0/0/0/0           |       import-policy       |        export-policy       |
#                 ________________________________________________________________________________________________________________________________________________________________
#                 | edge01.bjm01 |   15169   |             2001::1             |       Established 102/102/102/0        |       import-policy       |        export-policy       |
#                 ________________________________________________________________________________________________________________________________________________________________
#                 | edge01.bjm01 |   15169   |             2001::2             |       Established 102/102/102/0        |       import-policy       |        export-policy       |
#                 ________________________________________________________________________________________________________________________________________________________________
#                 | edge01.tbg01 |   13335   |          192.168.172.17         |          Established 0/1/1/0           |       import-policy       |        export-policy       |
#                 ________________________________________________________________________________________________________________________________________________________________
#             '''
#             opts = _get_bgp_runner_opts()
#             title = kwargs.pop('title', None)
#             display = kwargs.pop('display', opts['display'])
#             outputter = kwargs.pop('outputter', opts['outputter'])
        
#             # cleaning up the kwargs
#             # __pub args not used in this runner (yet)
#             kwargs_copy = {}
#             kwargs_copy.update(kwargs)
#             for karg, _ in six.iteritems(kwargs_copy):
#                 if karg.startswith('__pub'):
#                     kwargs.pop(karg)
#             if not asns and not kwargs:
#                 if display:
#                     print('Please specify at least an AS Number or an output filter')
#                 return []
#             device = kwargs.pop('device', None)
#             neighbor_ip = kwargs.pop('ip', None)
#             ipnet = kwargs.pop('network', None)
#             ipnet_obj = IPNetwork(ipnet) if ipnet else None
#             # any other key passed on the CLI can be used as a filter
        
#             rows = []
#             # building the labels
#             labels = {}
#             for field in opts['return_fields']:
#                 if field in _DEFAULT_LABELS_MAPPING:
#                     labels[field] = _DEFAULT_LABELS_MAPPING[field]
#                 else:
#                     # transform from 'previous_connection_state' to 'Previous Connection State'
#                     labels[field] = ' '.join(map(lambda word: word.title(), field.split('_')))
#             display_fields = list(set(opts['return_fields']) - set(_DEFAULT_INCLUDED_FIELDS))
#             get_bgp_neighbors_all = _get_mine(opts=opts)
        
#             if not title:
#                 title_parts = []
#                 if asns:
#                     title_parts.append('BGP Neighbors for {asns}'.format(
#                         asns=', '.join([six.text_type(asn) for asn in asns])
#                     ))
#                 if neighbor_ip:
#                     title_parts.append('Selecting neighbors having the remote IP address: {ipaddr}'.format(ipaddr=neighbor_ip))
#                 if ipnet:
#                     title_parts.append('Selecting neighbors within the IP network: {ipnet}'.format(ipnet=ipnet))
#                 if kwargs:
#                     title_parts.append('Searching for BGP neighbors having the attributes: {attrmap}'.format(
#                         attrmap=', '.join(map(lambda key: '{key}={value}'.format(key=key, value=kwargs[key]), kwargs))
#                     ))
#                 title = '\n'.join(title_parts)
#             for minion, get_bgp_neighbors_minion in six.iteritems(get_bgp_neighbors_all):  # pylint: disable=too-many-nested-blocks
#                 if not get_bgp_neighbors_minion.get('result'):
#                     continue  # ignore empty or failed mines
#                 if device and minion != device:
#                     # when requested to display only the neighbors on a certain device
#                     continue
#                 get_bgp_neighbors_minion_out = get_bgp_neighbors_minion.get('out', {})
#                 for vrf, vrf_bgp_neighbors in six.iteritems(get_bgp_neighbors_minion_out):  # pylint: disable=unused-variable
#                     for asn, get_bgp_neighbors_minion_asn in six.iteritems(vrf_bgp_neighbors):
#                         if asns and asn not in asns:
#                             # if filtering by AS number(s),
#                             # will ignore if this AS number key not in that list
#                             # and continue the search
#                             continue
#                         for neighbor in get_bgp_neighbors_minion_asn:
#                             if kwargs and not _compare_match(kwargs, neighbor):
#                                 # requested filtering by neighbors stats
#                                 # but this one does not correspond
#                                 continue
#                             if neighbor_ip and neighbor_ip != neighbor.get('remote_address'):
#                                 # requested filtering by neighbors IP addr
#                                 continue
#                             if ipnet_obj and neighbor.get('remote_address'):
#                                 neighbor_ip_obj = IPAddress(neighbor.get('remote_address'))
#                                 if neighbor_ip_obj not in ipnet_obj:
#                                     # Neighbor not in this network
#                                     continue
#                             row = {
#                                 'device': minion,
#                                 'neighbor_address': neighbor.get('remote_address'),
#                                 'as_number': asn
#                             }
#                             if 'vrf' in display_fields:
#                                 row['vrf'] = vrf
#                             if 'connection_stats' in display_fields:
#                                 connection_stats = '{state} {active}/{received}/{accepted}/{damped}'.format(
#                                     state=neighbor.get('connection_state', -1),
#                                     active=neighbor.get('active_prefix_count', -1),
#                                     received=neighbor.get('received_prefix_count', -1),
#                                     accepted=neighbor.get('accepted_prefix_count', -1),
#                                     damped=neighbor.get('suppressed_prefix_count', -1),
#                                 )
#                                 row['connection_stats'] = connection_stats
#                             if 'interface_description' in display_fields or 'interface_name' in display_fields:
#                                 net_find = __salt__['net.interfaces'](device=minion,
#                                                                       ipnet=neighbor.get('remote_address'),
#                                                                       display=False)
#                                 if net_find:
#                                     if 'interface_description' in display_fields:
#                                         row['interface_description'] = net_find[0]['interface_description']
#                                     if 'interface_name' in display_fields:
#                                         row['interface_name'] = net_find[0]['interface']
#                                 else:
#                                     # if unable to find anything, leave blank
#                                     if 'interface_description' in display_fields:
#                                         row['interface_description'] = ''
#                                     if 'interface_name' in display_fields:
#                                         row['interface_name'] = ''
#                             for field in display_fields:
#                                 if field in neighbor:
#                                     row[field] = neighbor[field]
#                             rows.append(row)
#             return _display_runner(rows, labels, title, display=display, outputter=outputter)
# class Returner(ConsumerPE):
#     def __init__(self):
#         ConsumerPE.__init__(self)
#     def _process(self, ret):
#         '''
#             Return data to a mongodb server
#             '''
#             conn, mdb = _get_conn(ret)
        
#             if isinstance(ret['return'], dict):
#                 back = _remove_dots(ret['return'])
#             else:
#                 back = ret['return']
        
#             if isinstance(ret, dict):
#                 full_ret = _remove_dots(ret)
#             else:
#                 full_ret = ret
        
#             log.debug(back)
#             sdata = {'minion': ret['id'], 'jid': ret['jid'], 'return': back, 'fun': ret['fun'], 'full_ret': full_ret}
#             if 'out' in ret:
#                 sdata['out'] = ret['out']
        
#             # save returns in the saltReturns collection in the json format:
#             # { 'minion': <minion_name>, 'jid': <job_id>, 'return': <return info with dots removed>,
#             #   'fun': <function>, 'full_ret': <unformatted return with dots removed>}
#             #
#             # again we run into the issue with deprecated code from previous versions
        
#             if PYMONGO_VERSION > _LooseVersion('2.3'):
#                 #using .copy() to ensure that the original data is not changed, raising issue with pymongo team
#                 mdb.saltReturns.insert_one(sdata.copy())
#             else:
#                 mdb.saltReturns.insert(sdata.copy())
# class _safe_copy(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, dat):
#         ''' mongodb doesn't allow '.' in keys, but does allow unicode equivs.
#                 Apparently the docs suggest using escaped unicode full-width
#                 encodings.  *sigh*
        
#                     \\  -->  \\\            $  -->  \\\\u0024
#                     .  -->  \\\\u002e
        
#                 Personally, I prefer URL encodings,
        
#                 \\  -->  %5c
#                 $  -->  %24
#                 .  -->  %2e
        
        
#                 Which means also escaping '%':
        
#                 % -> %25
#             '''''' mongodb doesn't allow '.' in keys, but does allow unicode equivs.
#                 Apparently the docs suggest using escaped unicode full-width
#                 encodings.  *sigh*
        
#                     \\  -->  \\\\
#                     $  -->  \\\\u0024
#                     .  -->  \\\\u002e
        
#                 Personally, I prefer URL encodings,
        
#                 \\  -->  %5c
#                 $  -->  %24
#                 .  -->  %2e
        
        
#                 Which means also escaping '%':
        
#                 % -> %25
#             '''
        
#             if isinstance(dat, dict):
#                 ret = {}
#                 for k in dat:
#                     r = k.replace('%', '%25').replace('\\', '%5c').replace('$', '%24').replace('.', '%2e')
#                     if r != k:
#                         log.debug('converting dict key from %s to %s for mongodb', k, r)
#                     ret[r] = _safe_copy(dat[k])
#                 return ret
        
#             if isinstance(dat, (list, tuple)):
#                 return [_safe_copy(i) for i in dat]
        
#             return dat
# class Get_load(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, jid):
#         '''
#             Return the load associated with a given job id
#             '''
#             conn, mdb = _get_conn(ret=None)
#             return mdb.jobs.find_one({'jid': jid}, {'_id': 0})
# class Get_minions(ProducerPE):
#     def __init__(self):
#         ProducerPE.__init__(self)
#     def _process(self):
#         '''
#             Return a list of minions
#             '''
#             conn, mdb = _get_conn(ret=None)
#             ret = []
#             name = mdb.saltReturns.distinct('minion')
#             ret.append(name)
#             return ret
# class Get_jids(ProducerPE):
#     def __init__(self):
#         ProducerPE.__init__(self)
#     def _process(self):
#         '''
#             Return a list of job ids
#             '''
#             conn, mdb = _get_conn(ret=None)
#             map = "function() { emit(this.jid, this); }"
#             reduce = "function (key, values) { return values[0]; }"
#             result = mdb.jobs.inline_map_reduce(map, reduce)
#             ret = {}
#             for r in result:
#                 jid = r['_id']
#                 ret[jid] = salt.utils.jid.format_jid_instance(jid, r['value'])
#             return ret
# class Event_return(ConsumerPE):
#     def __init__(self):
#         ConsumerPE.__init__(self)
#     def _process(self, events):
#         '''
#             Return events to Mongodb server
#             '''
#             conn, mdb = _get_conn(ret=None)
        
#             if isinstance(events, list):
#                 events = events[0]
        
#             if isinstance(events, dict):
#                 log.debug(events)
        
#                 if PYMONGO_VERSION > _LooseVersion('2.3'):
#                     mdb.events.insert_one(events.copy())
#                 else:
#                     mdb.events.insert(events.copy())
# class Lowstate_file_refs(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, chunks):
#         '''
#             Create a list of file ref objects to reconcile
#             '''
#             refs = {}
#             for chunk in chunks:
#                 saltenv = 'base'
#                 crefs = []
#                 for state in chunk:
#                     if state == '__env__':
#                         saltenv = chunk[state]
#                     elif state == 'saltenv':
#                         saltenv = chunk[state]
#                     elif state.startswith('__'):
#                         continue
#                     crefs.extend(salt_refs(chunk[state]))
#                 if crefs:
#                     if saltenv not in refs:
#                         refs[saltenv] = []
#                     refs[saltenv].append(crefs)
#             return refs
# class Salt_refs(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, data):
#         '''
#             Pull salt file references out of the states
#             '''
#             proto = 'salt://'
#             ret = []
#             if isinstance(data, six.string_types):
#                 if data.startswith(proto):
#                     return [data]
#             if isinstance(data, list):
#                 for comp in data:
#                     if isinstance(comp, six.string_types):
#                         if comp.startswith(proto):
#                             ret.append(comp)
#             return ret
# class Mod_data(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, fsclient):
#         '''
#             Generate the module arguments for the shim data
#             '''
#             # TODO, change out for a fileserver backend
#             sync_refs = [
#                     'modules',
#                     'states',
#                     'grains',
#                     'renderers',
#                     'returners',
#                     ]
#             ret = {}
#             envs = fsclient.envs()
#             ver_base = ''
#             for env in envs:
#                 files = fsclient.file_list(env)
#                 for ref in sync_refs:
#                     mods_data = {}
#                     pref = '_{0}'.format(ref)
#                     for fn_ in sorted(files):
#                         if fn_.startswith(pref):
#                             if fn_.endswith(('.py', '.so', '.pyx')):
#                                 full = salt.utils.url.create(fn_)
#                                 mod_path = fsclient.cache_file(full, env)
#                                 if not os.path.isfile(mod_path):
#                                     continue
#                                 mods_data[os.path.basename(fn_)] = mod_path
#                                 chunk = salt.utils.hashutils.get_hash(mod_path)
#                                 ver_base += chunk
#                     if mods_data:
#                         if ref in ret:
#                             ret[ref].update(mods_data)
#                         else:
#                             ret[ref] = mods_data
#             if not ret:
#                 return {}
        
#             if six.PY3:
#                 ver_base = salt.utils.stringutils.to_bytes(ver_base)
        
#             ver = hashlib.sha1(ver_base).hexdigest()
#             ext_tar_path = os.path.join(
#                     fsclient.opts['cachedir'],
#                     'ext_mods.{0}.tgz'.format(ver))
#             mods = {'version': ver,
#                     'file': ext_tar_path}
#             if os.path.isfile(ext_tar_path):
#                 return mods
#             tfp = tarfile.open(ext_tar_path, 'w:gz')
#             verfile = os.path.join(fsclient.opts['cachedir'], 'ext_mods.ver')
#             with salt.utils.files.fopen(verfile, 'w+') as fp_:
#                 fp_.write(ver)
#             tfp.add(verfile, 'ext_version')
#             for ref in ret:
#                 for fn_ in ret[ref]:
#                     tfp.add(ret[ref][fn_], os.path.join(ref, fn_))
#             tfp.close()
#             return mods
# class Ssh_version(ProducerPE):
#     def __init__(self):
#         ProducerPE.__init__(self)
#     def _process(self):
#         '''
#             Returns the version of the installed ssh command
#             '''
#             # This function needs more granular checks and to be validated against
#             # older versions of ssh
#             ret = subprocess.Popen(
#                     ['ssh', '-V'],
#                     stdout=subprocess.PIPE,
#                     stderr=subprocess.PIPE).communicate()
#             try:
#                 version_parts = ret[1].split(b',')[0].split(b'_')[1]
#                 parts = []
#                 for part in version_parts:
#                     try:
#                         parts.append(int(part))
#                     except ValueError:
#                         return tuple(parts)
#                 return tuple(parts)
#             except IndexError:
#                 return (2, 0)
# class _convert_args(IterativePE):
#     def __init__(self):
#         IterativePE.__init__(self)
#     def _process(self, args):
#         '''
#             Take a list of args, and convert any dicts inside the list to keyword
#             args in the form of `key=value`, ready to be passed to salt-ssh
#             '''
#             converted = []
#             for arg in args:
#                 if isinstance(arg, dict):
#                     for key in list(arg.keys()):
#                         if key == '__kwarg__':
#                             continue
#                         converted.append('{0}={1}'.format(key, arg[key]))
#                 else:
#                     converted.append(arg)
#             return converted
