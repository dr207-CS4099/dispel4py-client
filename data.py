from dispel4py.core import GenericPE
from dispel4py.base import IterativePE, ConsumerPE, ProducerPE
class Jsonify_parameters_8749(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, params):
        """
        When sent in an authorized REST request, only strings and integers can be
        transmitted accurately. Other types of data need to be encoded into JSON.
        """
        result = {}
        for param, value in params.items():
            if isinstance(value, (int, str)):
                result[param] = value
            else:
                result[param] = json.dumps(value)
        return result
class To_fmt_17902(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
     fmt.indentable
class To_matrix_3601(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return a Numpy.array for the U3 gate."""
            theta, phi, lam = self.params
            return numpy.array(
                [[
                    numpy.cos(theta / 2),
                    -numpy.exp(1j * lam) * numpy.sin(theta / 2)
                ],
                 [
                     numpy.exp(1j * phi) * numpy.sin(theta / 2),
                     numpy.exp(1j * (phi + lam)) * numpy.cos(theta / 2)
                 ]],
                dtype=complex)
class Get_first_name_last_name_8431(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            :rtype: str
            """
            names = []
            if self._get_first_names():
                names += self._get_first_names()
            if self._get_additional_names():
                names += self._get_additional_names()
            if self._get_last_names():
                names += self._get_last_names()
            if names:
                return helpers.list_to_string(names, " ")
            else:
                return self.get_full_name()
class Pseudo_tempname_15468(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return a pseudo-tempname base in the install directory.
            This code is intentionally naive; if a malicious party can write to
            the target directory you're already in deep doodoo.
            """
            try:
                pid = os.getpid()
            except:
                pid = random.randint(0, maxsize)
            return os.path.join(self.install_dir, "test-easy-install-%s" % pid)
class Get_system_users_19624(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Return currently connected users as a list of namedtuples."""
        retlist = []
        rawlist = _psutil_mswindows.get_system_users()
        for item in rawlist:
            user, hostname, tstamp = item
            nt = nt_user(user, None, hostname, tstamp)
            retlist.append(nt)
        return retlist
class Verilogtypeofsig_9397(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, signalItem):
        """
        Check if is register or wire
        """
        driver_cnt = len(signalItem.drivers)
        if signalItem._const or driver_cnt > 1 or\
           arr_any(signalItem.drivers, _isEventDependentDriver):
            return SIGNAL_TYPE.REG
        else:
            if driver_cnt == 1:
                d = signalItem.drivers[0]
                if not isinstance(d, (Assignment, PortItem)):
                    return SIGNAL_TYPE.REG
    
            return SIGNAL_TYPE.WIRE
class Institutes_11085(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Display a list of all user institutes."""
        institute_objs = user_institutes(store, current_user)
        institutes = []
        for ins_obj in institute_objs:
            sanger_recipients = []
            for user_mail in ins_obj.get('sanger_recipients',[]):
                user_obj = store.user(user_mail)
                if not user_obj:
                    continue
                sanger_recipients.append(user_obj['name'])
            institutes.append(
                {
                    'display_name': ins_obj['display_name'],
                    'internal_id': ins_obj['_id'],
                    'coverage_cutoff': ins_obj.get('coverage_cutoff', 'None'),
                    'sanger_recipients': sanger_recipients,
                    'frequency_cutoff': ins_obj.get('frequency_cutoff', 'None'),
                    'phenotype_groups': ins_obj.get('phenotype_groups', PHENOTYPE_GROUPS)
                }
            )
    
        data = dict(institutes=institutes)
        return render_template(
            'overview/institutes.html', **data)
class Failure_message_13515(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ str: A message describing the query failure. """
            return (
                "Expected node to have styles {expected}. "
                "Actual styles were {actual}").format(
                    expected=desc(self.expected_styles),
                    actual=desc(self.actual_styles))
class _maxiter_default_15839(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Trait initialiser.
            """
            mode = self.mode
            if mode == "KK":
                return 100 * len(self.nodes)
            elif mode == "major":
                return 200
            else:
                return 600
class Bip32_serialize_14892(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, rawtuple):
        """
        Derived from code from pybitcointools (https://github.com/vbuterin/pybitcointools)
        by Vitalik Buterin
        """
        vbytes, depth, fingerprint, i, chaincode, key = rawtuple
        i = encode(i, 256, 4)
        chaincode = encode(hash_to_int(chaincode), 256, 32)
        keydata = b'\x00'  +key[:-1] if vbytes in PRIVATE else key
        bindata = vbytes + from_int_to_byte(depth % 256) + fingerprint + i + chaincode + keydata
        return changebase(bindata + bin_dbl_sha256(bindata)[:4], 256, 58)
class Swap_memory_19619(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Swap system memory as a (total, used, free, sin, sout) tuple."""
        mem = _psutil_mswindows.get_virtual_mem()
        total = mem[2]
        free = mem[3]
        used = total - free
        percent = usage_percent(used, total, _round=1)
        return nt_swapmeminfo(total, used, free, percent, 0, 0)
class Gameplayfinder_17090(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, **kwargs):
        """ Docstring will be filled in by __init__.py """
    
        querystring = _kwargs_to_qs(**kwargs)
        url = '{}?{}'.format(GPF_URL, querystring)
        # if verbose, print url
        if kwargs.get('verbose', False):
            print(url)
        html = utils.get_html(url)
        doc = pq(html)
    
        # parse
        table = doc('table#all_plays')
        plays = utils.parse_table(table)
    
        # parse score column
        if 'score' in plays.columns:
            oScore, dScore = zip(*plays.score.apply(lambda s: s.split('-')))
            plays['teamScore'] = oScore
            plays['oppScore'] = dScore
        # add parsed pbp info
        if 'description' in plays.columns:
            plays = pbp.expand_details(plays, detailCol='description')
    
        return plays
class Main_16861(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, argv):
        """main program loop"""
    
        global output_dir
    
        try:
            opts, args = getopt.getopt( sys.argv[1:], \
                                        "hb",         \
                                        ["help", "backup"] )
        except getopt.GetoptError:
            usage()
            sys.exit( 2 )
    
        if args == []:
            usage()
            sys.exit( 1 )
    
        # process options
        #
        output_dir = None
        do_backup  = None
    
        for opt in opts:
            if opt[0] in ( "-h", "--help" ):
                usage()
                sys.exit( 0 )
    
            if opt[0] in ( "-b", "--backup" ):
                do_backup = 1
    
        # create context and processor
        source_processor = SourceProcessor()
    
        # retrieve the list of files to process
        file_list = make_file_list( args )
        for filename in file_list:
            source_processor.parse_file( filename )
    
            for block in source_processor.blocks:
                beautify_block( block )
    
            new_name = filename + ".new"
            ok       = None
    
            try:
                file = open( new_name, "wt" )
                for block in source_processor.blocks:
                    for line in block.lines:
                        file.write( line )
                        file.write( "\n" )
                file.close()
            except:
                ok = 0
class Prepare_outdir_6042(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """create temp directory."""
            self._outdir = self.outdir
            if self._outdir is None:
                self._tmpdir = TemporaryDirectory()
                self.outdir = self._tmpdir.name
            elif isinstance(self.outdir, str):
                mkdirs(self.outdir)
            else:
                raise Exception("Error parsing outdir: %s"%type(self.outdir))
    
            # handle gmt type
            if isinstance(self.gene_sets, str):
                _gset = os.path.split(self.gene_sets)[-1].lower().rstrip(".gmt")
            elif isinstance(self.gene_sets, dict):
                _gset = "blank_name"
            else:
                raise Exception("Error parsing gene_sets parameter for gene sets")
    
            logfile = os.path.join(self.outdir, "gseapy.%s.%s.log" % (self.module, _gset))
            return logfile
class Safe_start_ingest_11815(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, event):
        '''Start a capture process but make sure to catch any errors during this
        process, log them but otherwise ignore them.
        '''
        try:
            ingest(event)
        except Exception:
            logger.error('Something went wrong during the upload')
            logger.error(traceback.format_exc())
            # Update state if something went wrong
            recording_state(event.uid, 'upload_error')
            update_event_status(event, Status.FAILED_UPLOADING)
            set_service_status_immediate(Service.INGEST, ServiceStatus.IDLE)
class Add_parameters_12068(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, traj):
            """Adds all neuron group parameters to `traj`."""
            assert(isinstance(traj,Trajectory))
    
            scale = traj.simulation.scale
    
    
            traj.v_standard_parameter = Brian2Parameter
    
            model_eqs = '''dV/dt= 1.0/tau_POST * (mu - V) + I_syn : 1
                           mu : 1
                           I_syn =  - I_syn_i + I_syn_e : Hz
                        '''
    
            conn_eqs = '''I_syn_PRE = x_PRE/(tau2_PRE-tau1_PRE) : Hz
                          dx_PRE/dt = -(normalization_PRE*y_PRE+x_PRE)*invtau1_PRE : 1
                          dy_PRE/dt = -y_PRE*invtau2_PRE : 1
                       '''
    
            traj.f_add_parameter('model.eqs', model_eqs,
                               comment='The differential equation for the neuron model')
    
            traj.f_add_parameter('model.synaptic.eqs', conn_eqs,
                               comment='The differential equation for the synapses. '
                                       'PRE will be replaced by `i` or `e` depending '
                                       'on the source population')
    
            traj.f_add_parameter('model.synaptic.tau1', 1*ms, comment = 'The decay time')
            traj.f_add_parameter('model.synaptic.tau2_e', 3*ms, comment = 'The rise time, excitatory')
            traj.f_add_parameter('model.synaptic.tau2_i', 2*ms, comment = 'The rise time, inhibitory')
    
            traj.f_add_parameter('model.V_th', 'V >= 1.0', comment = "Threshold value")
            traj.f_add_parameter('model.reset_func', 'V=0.0',
                                 comment = "String representation of reset function")
            traj.f_add_parameter('model.refractory', 5*ms, comment = "Absolute refractory period")
    
            traj.f_add_parameter('model.N_e', int(2000*scale), comment = "Amount of excitatory neurons")
            traj.f_add_parameter('model.N_i', int(500*scale), comment = "Amount of inhibitory neurons")
    
            traj.f_add_parameter('model.tau_e', 15*ms, comment = "Membrane time constant, excitatory")
            traj.f_add_parameter('model.tau_i', 10*ms, comment = "Membrane time constant, inhibitory")
    
            traj.f_add_parameter('model.mu_e_min', 1.1, comment = "Lower bound for bias, excitatory")
            traj.f_add_parameter('model.mu_e_max', 1.2, comment = "Upper bound for bias, excitatory")
    
            traj.f_add_parameter('model.mu_i_min', 1.0, comment = "Lower bound for bias, inhibitory")
            traj.f_add_parameter('model.mu_i_max', 1.05, comment = "Upper bound for bias, inhibitory")

class _viewport_default_15845(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Trait initialiser """
    
            viewport = Viewport(component=self.canvas, enable_zoom=True)
            viewport.tools.append(ViewportPanTool(viewport))
            return viewport
class Pip_version_check_15782(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, session):
        """Check for an update for pip.
    
        Limit the frequency of checks to once per week. State is stored either in
        the active virtualenv or in the user's USER_CACHE_DIR keyed off the prefix
        of the pip script path.
        """
        import pip  # imported here to prevent circular imports
        pypi_version = None
    
        try:
            state = load_selfcheck_statefile()
    
            current_time = datetime.datetime.utcnow()
            # Determine if we need to refresh the state
            if "last_check" in state.state and "pypi_version" in state.state:
                last_check = datetime.datetime.strptime(
                    state.state["last_check"],
                    SELFCHECK_DATE_FMT
                )
                if total_seconds(current_time - last_check) < 7 * 24 * 60 * 60:
                    pypi_version = state.state["pypi_version"]
    
            # Refresh the version if we need to or just see if we need to warn
            if pypi_version is None:
                resp = session.get(
                    PyPI.pip_json_url,
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                pypi_version = [
                    v for v in sorted(
                        list(resp.json()["releases"]),
                        key=packaging_version.parse,
                    )
                    if not packaging_version.parse(v).is_prerelease
                ][-1]
    
                # save that we've performed a check
                state.save(pypi_version, current_time)
    
            pip_version = packaging_version.parse(pip.__version__)
            remote_version = packaging_version.parse(pypi_version)
    
            # Determine if our pypi_version is older
            if (pip_version < remote_version and
                    pip_version.base_version != remote_version.base_version):
                # Advise "python -m pip" on Windows to avoid issues
                # with overwriting pip.exe.
                if WINDOWS:
                    pip_cmd = "python -m pip"
                else:
                    pip_cmd = "pip"
                logger.warning(
                    "You are using pip version %s, however version %s is "
                    "available.\nYou should consider upgrading via the "
                    "'%s install --upgrade pip' command." % (pip.__version__,
                                                             pypi_version,
                                                             pip_cmd)
                )
    
        except Exception:
            logger.debug(
                "There was an error checking the latest version of pip",
                exc_info=True,
            )
class Get_vid_from_url_0(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, url):
            """Extracts video ID from URL.
            """
            return match1(url, r'youtu\.be/([^?/]+)') or \
              match1(url, r'youtube\.com/embed/([^/?]+)') or \
              match1(url, r'youtube\.com/v/([^/?]+)') or \
              match1(url, r'youtube\.com/watch/([^/?]+)') or \
              parse_query_param(url, 'v') or \
              parse_query_param(parse_query_param(url, 'u'), 'v')
class Register_5312(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, linter):
        """required method to auto register this checker """
        linter.register_checker(TypeChecker(linter))
        linter.register_checker(IterableChecker(linter))
class Conjugate_3627(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return the conjugate of the QuantumChannel."""
            kraus_l, kraus_r = self._data
            kraus_l = [k.conj() for k in kraus_l]
            if kraus_r is not None:
                kraus_r = [k.conj() for k in kraus_r]
            return Kraus((kraus_l, kraus_r), self.input_dims(), self.output_dims())
class _get_titles_8433(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            :rtype: list(list(str))
            """
            titles = []
            for child in self.vcard.getChildren():
                if child.name == "TITLE":
                    titles.append(child.value)
            return sorted(titles)
class _populate_commands_8581(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Create an instance of each of the debugger
            commands. Commands are found by importing files in the
            directory 'command'. Some files are excluded via an array set
            in __init__.  For each of the remaining files, we import them
            and scan for class names inside those files and for each class
            name, we will create an instance of that class. The set of
            DebuggerCommand class instances form set of possible debugger
            commands."""
            from trepan.processor import command as Mcommand
            if hasattr(Mcommand, '__modules__'):
                return self.populate_commands_easy_install(Mcommand)
            else:
                return self.populate_commands_pip(Mcommand)
class List_overlay_names_15995(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return list of overlay names."""
    
            overlay_names = []
            for blob in self._blobservice.list_blobs(
                self.uuid,
                prefix=self.overlays_key_prefix
            ):
                overlay_file = blob.name.rsplit('/', 1)[-1]
                overlay_name, ext = overlay_file.split('.')
                overlay_names.append(overlay_name)
    
            return overlay_names
class Pid_exists_4297(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, pid):
        """Check whether pid exists in the current process table."""
        if pid < 0:
            return False
        try:
            os.kill(pid, 0)
        except OSError as exc:
            logging.debug("No process[%s]: %s", exc.errno, exc)
            return exc.errno == errno.EPERM
        else:
            p = psutil.Process(pid)
            return p.status != psutil.STATUS_ZOMBIE
class Get_disk_usage_19620(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        """Return disk usage associated with path."""
        try:
            total, free = _psutil_mswindows.get_disk_usage(path)
        except WindowsError:
            err = sys.exc_info()[1]
            if not os.path.exists(path):
                raise OSError(errno.ENOENT, "No such file or directory: '%s'" % path)
            raise
        used = total - free
        percent = usage_percent(used, total, _round=1)
        return nt_diskinfo(total, used, free, percent)
class Load_ipython_extension_20303(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, ip):
        """Load the extension in IPython."""
        global _loaded
        if not _loaded:
            plugin = StoreMagic(shell=ip, config=ip.config)
            ip.plugin_manager.register_plugin('storemagic', plugin)
            _loaded = True
class Transpose_3628(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return the transpose of the QuantumChannel."""
            kraus_l, kraus_r = self._data
            kraus_l = [k.T for k in kraus_l]
            if kraus_r is not None:
                kraus_r = [k.T for k in kraus_r]
            return Kraus((kraus_l, kraus_r),
                         input_dims=self.output_dims(),
                         output_dims=self.input_dims())
class Makeservice_14822(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, opt):
        """Make a service
    
        :params opt: dictionary-like object with 'freq', 'config' and 'messages'
        :returns: twisted.application.internet.TimerService that at opt['freq']
                  checks for stale processes in opt['config'], and sends
                  restart messages through opt['messages']
        """
        restarter, path = parseConfig(opt)
        now = time.time()
        checker = functools.partial(check, path, now)
        beatcheck = tainternet.TimerService(opt['freq'], run, restarter,
                                            checker, time.time)
        beatcheck.setName('beatcheck')
        return heart.wrapHeart(beatcheck)
class Internal_name_17949(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Return the unique internal name
            """
            unq = super().internal_name()
            if self.tret is not None:
                unq += "_" + self.tret
            return unq
class Parsecommandlinearguments_11513(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
      """
      Set up command line parsing.
      """
      parser = argparse.ArgumentParser(description="Plot predicted Gaia sky averaged proper motion errors as a function of V")
      parser.add_argument("-p", action="store_true", dest="pdfOutput", help="Make PDF plot")
      parser.add_argument("-b", action="store_true", dest="pngOutput", help="Make PNG plot")
      parser.add_argument("-g", action="store_true", dest="gmagAbscissa", help="Plot performance vs G instead of V")
      args=vars(parser.parse_args())
      return args
class Dist_in_usersite_15407(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, dist):
        """
        Return True if given Distribution is installed in user site.
        """
        norm_path = normalize_path(dist_location(dist))
        return norm_path.startswith(normalize_path(user_site))
class Virtual_memory_19618(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """System virtual memory as a namedtuple."""
        mem = _psutil_mswindows.get_virtual_mem()
        totphys, availphys, totpagef, availpagef, totvirt, freevirt = mem
        #
        total = totphys
        avail = availphys
        free = availphys
        used = total - avail
        percent = usage_percent((total - avail), total, _round=1)
        return nt_virtmem_info(total, avail, percent, used, free)
class Migrate_window_13383(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, bg):
        "Take a pythoncard background resource and convert to a gui2py window"
        ret = {}
        for k, v in bg.items():
            if k == 'type':
                v = WIN_MAP[v]._meta.name
            elif k == 'menubar':
                menus = v['menus']
                v = [migrate_control(menu) for menu in menus]
            elif k == 'components':
                v = [migrate_control(comp) for comp in v]
            else:
                k = SPEC_MAP['Widget'].get(k, k)
            ret[k] = v
        return ret
class To_dict_10780(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            convert the fields of the object into a dictionnary
            """
            # all the attibutes defined by PKCS#11
            all_attributes = PyKCS11.CKA.keys()
    
            # only use the integer values and not the strings like 'CKM_RSA_PKCS'
            all_attributes = [attr for attr in all_attributes if
                              isinstance(attr, int)]
    
            # all the attributes of the object
            attributes = self.session.getAttributeValue(self, all_attributes)
    
            dico = dict()
            for key, attr in zip(all_attributes, attributes):
                if attr is None:
                    continue
                if key == CKA_CLASS:
                    dico[PyKCS11.CKA[key]] = PyKCS11.CKO[attr]
                elif key == CKA_CERTIFICATE_TYPE:
                    dico[PyKCS11.CKA[key]] = PyKCS11.CKC[attr]
                elif key == CKA_KEY_TYPE:
                    dico[PyKCS11.CKA[key]] = PyKCS11.CKK[attr]
                else:
                    dico[PyKCS11.CKA[key]] = attr
            return dico
class Count_id_10031(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, w0):
        """
        0 -> no terms idd
        1 -> most term idd are shared in root morphem
        2 -> most term idd are shared in flexing morphem
        3 -> most term idd are shared root <-> flexing (crossed)
        :param w0:
        :param w1:
        :return:
        """
    
        def f(w1):
            count = [set(w0.root).intersection(w1.root),
                     set(w0.flexing).intersection(w1.flexing),
                     set(w0.root).intersection(w1.flexing) | set(w1.root).intersection(w0.flexing)]
    
            if any(count):
                return max((1,2,3), key=lambda i: len(count[i - 1]))
            else:
                return 0
    
        return f
class Get_plastic_table_18324(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
         """
         Calculates the plastic data
         """
         E = self.young_modulus
         sy = self.yield_stress
         n = self.hardening_exponent
         eps_max = self.max_strain
         Np = self.strain_data_points
         ey = sy/E
         s = 10.**np.linspace(0., np.log10(eps_max/ey), Np)
         strain = ey * s
         stress = sy * s**n
         plastic_strain = strain - stress / E 
         return pd.DataFrame({"strain": strain, 
                              "stress": stress, 
                              "plastic_strain": plastic_strain})
class Get_system_per_cpu_times_20344(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Return system CPU times as a named tuple"""
        ret = []
        for cpu_t in _psutil_osx.get_system_per_cpu_times():
            user, nice, system, idle = cpu_t
            item = _cputimes_ntuple(user, nice, system, idle)
            ret.append(item)
        return ret
class Supplementary_files_14392(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """The supplementary files of this notebook"""
            if self._supplementary_files is not None:
                return self._supplementary_files
            return getattr(self.nb.metadata, 'supplementary_files', None)
class Get_config_926(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Returns the config of the layer.
    
        A layer config is a Python dictionary (serializable) containing the
        configuration of a layer. The same layer can be reinstantiated later
        (without its trained weights) from this configuration.
    
        Returns:
          config: A Python dictionary of class keyword arguments and their
            serialized values.
        """
        config = {
            'filters': self.filters,
            'kernel_size': self.kernel_size,
            'strides': self.strides,
            'padding': self.padding,
            'data_format': self.data_format,
            'dilation_rate': self.dilation_rate,
            'activation': (tf.keras.activations.serialize(self.activation)
                           if self.activation else None),
            'activity_regularizer':
                tf.keras.initializers.serialize(self.activity_regularizer),
        }
        function_keys = [
            'kernel_posterior_fn',
            'kernel_posterior_tensor_fn',
            'kernel_prior_fn',
            'kernel_divergence_fn',
            'bias_posterior_fn',
            'bias_posterior_tensor_fn',
            'bias_prior_fn',
            'bias_divergence_fn',
        ]
        for function_key in function_keys:
          function = getattr(self, function_key)
          if function is None:
            function_name = None
            function_type = None
          else:
            function_name, function_type = tfp_layers_util.serialize_function(
                function)
          config[function_key] = function_name
          config[function_key + '_type'] = function_type
        base_config = super(_ConvVariational, self).get_config()
        return dict(list(base_config.items()) + list(config.items()))
class Print_location_8569(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, proc_obj):
        """Show where we are. GUI's and front-end interfaces often
        use this to update displays. So it is helpful to make sure
        we give at least some place that's located in a file.
        """
        i_stack = proc_obj.curindex
        if i_stack is None or proc_obj.stack is None:
            return False
        core_obj = proc_obj.core
        dbgr_obj = proc_obj.debugger
        intf_obj = dbgr_obj.intf[-1]
    
        # Evaluation routines like "exec" don't show useful location
        # info. In these cases, we will use the position before that in
        # the stack.  Hence the looping below which in practices loops
        # once and sometimes twice.
        remapped_file = None
        source_text = None
        while i_stack >= 0:
            frame_lineno = proc_obj.stack[i_stack]
            i_stack -= 1
            frame, lineno = frame_lineno
    
    #         # Next check to see that local variable breadcrumb exists and
    #         # has the magic dynamic value.
    #         # If so, it's us and we don't normally show this.a
    #         if 'breadcrumb' in frame.f_locals:
    #             if self.run == frame.f_locals['breadcrumb']:
    #                 break
    
            filename = Mstack.frame2file(core_obj, frame, canonic=False)
            if '<string>' == filename and dbgr_obj.eval_string:
                remapped_file = filename
                filename = pyficache.unmap_file(filename)
                if '<string>' == filename:
                    remapped = cmdfns.source_tempfile_remap('eval_string',
                                                            dbgr_obj.eval_string)
                    pyficache.remap_file(filename, remapped)
                    filename = remapped
                    lineno = pyficache.unmap_file_line(filename, lineno)
                    pass
                pass
            elif '<string>' == filename:
                source_text = deparse_fn(frame.f_code)
                filename = "<string: '%s'>" % source_text
                pass
            else:
                m = re.search('^<frozen (.*)>', filename)
                if m and m.group(1) in pyficache.file2file_remap:
                    remapped_file = pyficache.file2file_remap[m.group(1)]
                    pass
                elif filename in pyficache.file2file_remap:
                    remapped_file = pyficache.unmap_file(filename)
                    # FIXME: a remapped_file shouldn't be the same as its unmapped version
                    if remapped_file == filename:
                        remapped_file = None
                        pass
                    pass
                elif m and m.group(1) in sys.modules:
                    remapped_file = m.group(1)
                    pyficache.remap_file(filename, remapped_file)
                pass
    
            opts = {
                'reload_on_change' : proc_obj.settings('reload'),
                'output'           : proc_obj.settings('highlight')
                }
    
            if 'style' in proc_obj.debugger.settings:
                opts['style'] = proc_obj.settings('style')
    
            pyficache.update_cache(filename)
            line = pyficache.getline(filename, lineno, opts)
            if not line:
                if (not source_text and
                    filename.startswith("<string: ") and proc_obj.curframe.f_code):
                    # Deparse the code object into a temp file and remap the line from code
                    # into the corresponding line of the tempfile
                    co = proc_obj.curframe.f_code
                    temp_filename, name_for_code = deparse_and_cache(co, proc_obj.errmsg)
                    lineno = 1
                    # _, lineno = pyficache.unmap_file_line(temp_filename, lineno, True)
                    if temp_filename:
                        filename = temp_filename
                    pass
    
                else:
                    # FIXME:
                    if source_text:
                        lines = source_text.split("\n")
                        temp_name='string-'
                    else:
                        # try with good ol linecache and consider fixing pyficache
                        lines = linecache.getlines(filename)
                        temp_name = filename
                    if lines:
                        # FIXME: DRY code with version in cmdproc.py print_location
                        prefix = os.path.basename(temp_name).split('.')[0]
                        fd = tempfile.NamedTemporaryFile(suffix='.py',
                                                         prefix=prefix,
                                                         delete=False)
                        with fd:
                            fd.write(''.join(lines))
                            remapped_file = fd.name
                            pyficache.remap_file(remapped_file, filename)
                        fd.close()
                        pass
                line = linecache.getline(filename, lineno,
                                         proc_obj.curframe.f_globals)
                if not line:
                    m = re.search('^<frozen (.*)>', filename)
                    if m and m.group(1):
                        remapped_file = m.group(1)
                        try_module = sys.modules.get(remapped_file)
                        if (try_module and inspect.ismodule(try_module) and
                            hasattr(try_module, '__file__')):
                            remapped_file = sys.modules[remapped_file].__file__
                            pyficache.remap_file(filename, remapped_file)
                            line = linecache.getline(remapped_file, lineno,
                                                     proc_obj.curframe.f_globals)
                        else:
                            remapped_file = m.group(1)
                            code = proc_obj.curframe.f_code
                            filename, line = cmdfns.deparse_getline(code, remapped_file,
                                                                    lineno, opts)
                        pass
                pass
    
            try:
                match, reason = Mstack.check_path_with_frame(frame, filename)
                if not match:
                    if filename not in warned_file_mismatches:
                        proc_obj.errmsg(reason)
                        warned_file_mismatches.add(filename)
            except:
                pass
    
            fn_name = frame.f_code.co_name
            last_i  = frame.f_lasti
            print_source_location_info(intf_obj.msg, filename, lineno, fn_name,
                                       remapped_file = remapped_file,
                                       f_lasti = last_i)
            if line and len(line.strip()) != 0:
                if proc_obj.event:
                    print_source_line(intf_obj.msg, lineno, line,
                                      proc_obj.event2short[proc_obj.event])
                pass
            if '<string>' != filename: break
            pass
    
        if proc_obj.event in ['return', 'exception']:
            val = proc_obj.event_arg
            intf_obj.msg('R=> %s' % proc_obj._saferepr(val))
            pass
        return True
class Makeplot_11542(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, args):
      """
      Make the plot with parallax horizons. The plot shows V-band magnitude vs distance for a number of
      spectral types and over the range 5.7<G<20. In addition a set of crudely drawn contours show the points
      where 0.1, 1, and 10 per cent relative parallax accracy are reached.
    
      Parameters
      ----------
      
      args - Command line arguments.
      """
      distances = 10.0**np.linspace(1,6,10001)
    
      spts=['B0V', 'A0V', 'F0V', 'G0V', 'K0V', 'K4V', 'K1III']
      twokmsRV = []
      twokmsV = []
      vabsTwokms = []
      fivekmsRV = []
      fivekmsV = []
      vabsFivekms = []
      tenkmsRV = []
      tenkmsV = []
      vabsTenkms = []
    
      fig=plt.figure(figsize=(11,7.8))
      deltaHue = 240.0/(len(spts)-1)
      hues = (240.0-np.arange(len(spts))*deltaHue)/360.0
      hsv=np.zeros((1,1,3))
      hsv[0,0,1]=1.0
      hsv[0,0,2]=0.9
      for hue,spt in zip(hues, spts):
        hsv[0,0,0]=hue
        vmags = vabsFromSpt(spt)+5.0*np.log10(distances)-5.0
        vmini=vminiFromSpt(spt)
        grvsmags = vmags - vminGrvsFromVmini(vmini)
        rvError = vradErrorSkyAvg(vmags, spt)
        observed = (grvsmags>=5.7) & (grvsmags<=16.1)
        rvError = rvError[observed]
        # Identify the points where the relative parallax accuracy is 0.1, 1, or 10 per cent.
        if (rvError.min()<=2.0):
          index = len(rvError[rvError<=2.0])-1
          twokmsRV.append(distances[observed][index])
          twokmsV.append(vmags[observed][index])
          vabsTwokms.append(vabsFromSpt(spt))
        if (rvError.min()<=5.0):
          index = len(rvError[rvError<=5.0])-1
          fivekmsRV.append(distances[observed][index])
          fivekmsV.append(vmags[observed][index])
          vabsFivekms.append(vabsFromSpt(spt))
        if (rvError.min()<=10.0):
          index = len(rvError[rvError<=10.0])-1
          tenkmsRV.append(distances[observed][index])
          tenkmsV.append(vmags[observed][index])
          vabsTenkms.append(vabsFromSpt(spt))
        plt.semilogx(distances[observed], vmags[observed], '-', label=spt, color=hsv_to_rgb(hsv)[0,0,:])
        plt.text(distances[observed][-1], vmags[observed][-1], spt, horizontalalignment='center',
            verticalalignment='bottom', fontsize=14)
    
      # Draw the "contours" of constant radial velocity accuracy.
      twokmsRV = np.array(twokmsRV)
      twokmsV = np.array(twokmsV)
      indices = np.argsort(vabsTwokms)
      plt.semilogx(twokmsRV[indices],twokmsV[indices],'k--')
      plt.text(twokmsRV[indices][-1]*0.8,twokmsV[indices][-1],"$2$ km s$^{-1}$", ha='right', size=16,
          bbox=dict(boxstyle="round, pad=0.3", ec=(0.0, 0.0, 0.0), fc=(1.0, 1.0, 1.0),))
    
      fivekmsRV = np.array(fivekmsRV)
      fivekmsV = np.array(fivekmsV)
      indices = np.argsort(vabsFivekms)
      plt.semilogx(fivekmsRV[indices],fivekmsV[indices],'k--')
      plt.text(fivekmsRV[indices][-1]*0.8,fivekmsV[indices][-1],"$5$ km s$^{-1}$", ha='right', size=16,
          bbox=dict(boxstyle="round, pad=0.3", ec=(0.0, 0.0, 0.0), fc=(1.0, 1.0, 1.0),))
    
      tenkmsRV = np.array(tenkmsRV)
      tenkmsV = np.array(tenkmsV)
      indices = np.argsort(vabsTenkms)
      plt.semilogx(tenkmsRV[indices],tenkmsV[indices],'k--')
      plt.text(tenkmsRV[indices][-1]*0.8,tenkmsV[indices][-1]+0.5,"$10$ km s$^{-1}$", ha='right', size=16,
          bbox=dict(boxstyle="round, pad=0.3", ec=(0.0, 0.0, 0.0), fc=(1.0, 1.0, 1.0),))
    
      plt.title('Radial velocity accuracy horizons ($A_V=0$)')
    
      plt.xlabel('Distance [pc]')
      plt.ylabel('V')
      plt.grid()
      #leg=plt.legend(loc=4, fontsize=14, labelspacing=0.5)
      plt.ylim(5,20)
      
      basename='RadialVelocityHorizons'
      if (args['pdfOutput']):
        plt.savefig(basename+'.pdf')
      elif (args['pngOutput']):
        plt.savefig(basename+'.png')
      else:
        plt.show()
class _get_all_graphs_15840(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Property getter.
            """
            top_graph = self
    
            def get_subgraphs(graph):
                assert isinstance(graph, BaseGraph)
                subgraphs = graph.subgraphs[:]
                for subgraph in graph.subgraphs:
                    subsubgraphs = get_subgraphs(subgraph)
                    subgraphs.extend(subsubgraphs)
                return subgraphs
    
            subgraphs = get_subgraphs(top_graph)
            return [top_graph] + subgraphs
class Close_19048(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Stop listing for new connections and close all open connections.
            
            :returns: Deferred that calls back once everything is closed.
            """
            
            def cancel_sends(_):
                logger.debug("Closed port. Cancelling all on-going send operations...")
                while self._ongoing_sends:
                    d = self._ongoing_sends.pop()
                    d.cancel()
    
            def close_connections(_):
                all_connections = [c for conns in self._connections.itervalues() for c in conns]
                
                logger.debug("Closing all connections (there are %s)..." % len(all_connections))
                for c in all_connections:
                    c.transport.loseConnection()
                ds = [c.wait_for_close() for c in all_connections]
                d = defer.DeferredList(ds, fireOnOneErrback=True)
                
                def allclosed(_):
                    logger.debug("All connections closed.")
                d.addCallback(allclosed)
                return d
            
            logger.debug("Closing connection pool...")
            
            d = defer.maybeDeferred(self._listeningport.stopListening)
            d.addCallback(cancel_sends)
            d.addCallback(close_connections)
            return d
class Get_memory_info_20346(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return a tuple with the process' RSS and VMS size."""
            rss, vms = _psutil_osx.get_process_memory_info(self.pid)[:2]
            return nt_meminfo(rss, vms)
class Update_w_10321(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ compute new W """
            def select_hull_points(data, n=3):
                """ select data points for pairwise projections of the first n
                dimensions """
    
                # iterate over all projections and select data points
                idx = np.array([])
    
                # iterate over some pairwise combinations of dimensions
                for i in combinations(range(n), 2):
                    # sample convex hull points in 2D projection
                    convex_hull_d = quickhull(data[i, :].T)
    
                    # get indices for convex hull data points
                    idx = np.append(idx, vq(data[i, :], convex_hull_d.T))
                    idx = np.unique(idx)
    
                return np.int32(idx)
    
            # determine convex hull data points using either PCA or random
            # projections
            method = 'randomprojection'
            if method == 'pca':
                pcamodel = PCA(self.data)
                pcamodel.factorize(show_progress=False)
                proj = pcamodel.H
            else:
                R = np.random.randn(self._base_sel, self._data_dimension)
                proj = np.dot(R, self.data)
    
            self._hull_idx = select_hull_points(proj, n=self._base_sel)
            aa_mdl = AA(self.data[:, self._hull_idx], num_bases=self._num_bases)
    
            # determine W
            aa_mdl.factorize(niter=50, compute_h=True, compute_w=True,
                             compute_err=True, show_progress=False)
    
            self.W = aa_mdl.W
            self._map_w_to_data()
class _fetchchildren_15033(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''Fetch and return new child items.'''
            children = []
            for entry in QDir.drives():
                path = os.path.normpath(entry.canonicalFilePath())
                children.append(Mount(path))
    
            return children
class Get_scope_list_17892(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
     list
class Write_inp_18323(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
         """
         Returns the material definition as a string in Abaqus INP format.
         """
         template = self.get_template()
         return template.substitute({"class": self.__class__.__name__,
                                     "label": self.label}).strip()
class To_ogc_wkt_7684(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Returns the CS as a OGC WKT formatted string.
            """
            return 'GEOGCS["%s", %s, %s, %s, AXIS["Lon", %s], AXIS["Lat", %s]]' % (self.name, self.datum.to_ogc_wkt(), self.prime_mer.to_ogc_wkt(), self.angunit.to_ogc_wkt(), self.twin_ax[0].ogc_wkt, self.twin_ax[1].ogc_wkt )
class Info_21325(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Returns a description of the trait."""
            if isinstance(self.klass, basestring):
                klass = self.klass
            else:
                klass = self.klass.__name__
            result = 'a subclass of ' + klass
            if self._allow_none:
                return result + ' or None'
            return result
class Ds2n_18623(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Calculates the derivative of the neutron separation energies:
    
            ds2n(Z,A) = s2n(Z,A) - s2n(Z,A+2)
            """
            idx = [(x[0] + 0, x[1] + 2) for x in self.df.index]
            values = self.s2n.values - self.s2n.loc[idx].values
            return Table(df=pd.Series(values, index=self.df.index, name='ds2n' + '(' + self.name + ')'))
class Bit_string_index_3972(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, text):
        """Return the index of a string of 0s and 1s."""
        n = len(text)
        k = text.count("1")
        if text.count("0") != n - k:
            raise VisualizationError("s must be a string of 0 and 1")
        ones = [pos for pos, char in enumerate(text) if char == "1"]
        return lex_index(n, k, ones)
class To_esri_wkt_7685(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Returns the CS as a ESRI WKT formatted string.
            """
            return 'GEOGCS["%s", %s, %s, %s, AXIS["Lon", %s], AXIS["Lat", %s]]' % (self.name, self.datum.to_esri_wkt(), self.prime_mer.to_esri_wkt(), self.angunit.to_esri_wkt(), self.twin_ax[0].esri_wkt, self.twin_ax[1].esri_wkt )
class _repr_html__7412(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Jupyter Notebook magic repr function.
            """
            rows, c = '', ''
            s = '<tr><td><strong>{k}</strong></td><td style="{stl}">{v}</td></tr>'
            for k, v in self.__dict__.items():
    
                if k == '_colour':
                    k = 'colour'
                    c = utils.text_colour_for_hex(v)
                    style = 'color:{}; background-color:{}'.format(c, v)
                else:
                    style = 'color:black; background-color:white'
    
                if k == 'component':
                    try:
                        v = v._repr_html_()
                    except AttributeError:
                        v = v.__repr__()
    
                rows += s.format(k=k, v=v, stl=style)
            html = '<table>{}</table>'.format(rows)
            return html
class Cwd_filt_20111(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, depth):
        """Return the last depth elements of the current working directory.
    
        $HOME is always replaced with '~'.
        If depth==0, the full path is returned."""
    
        cwd = os.getcwdu().replace(HOME,"~")
        out = os.sep.join(cwd.split(os.sep)[-depth:])
        return out or os.sep
class Fetch_ensembl_genes_10897(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, build='37'):
        """Fetch the ensembl genes
        
        Args:
            build(str): ['37', '38']
        """
        if build == '37':
            url = 'http://grch37.ensembl.org'
        else:
            url = 'http://www.ensembl.org'
        
        LOG.info("Fetching ensembl genes from %s", url)
        dataset_name = 'hsapiens_gene_ensembl'
        
        dataset = pybiomart.Dataset(name=dataset_name, host=url)
        
        attributes = [
            'chromosome_name',
            'start_position',
            'end_position',
            'ensembl_gene_id',
            'hgnc_symbol',
            'hgnc_id',
        ]
        
        filters = {
            'chromosome_name': CHROMOSOMES,
        }
        
        result = dataset.query(
            attributes = attributes,
            filters = filters,
            use_attr_names=True,
        )
        
        return result
class Inputhook_pyglet_20752(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Run the pyglet event loop by processing pending events only.
    
        This keeps processing pending events until stdin is ready.  After
        processing all pending events, a call to time.sleep is inserted.  This is
        needed, otherwise, CPU usage is at 100%.  This sleep time should be tuned
        though for best performance.
        """
        # We need to protect against a user pressing Control-C when IPython is
        # idle and this is running. We trap KeyboardInterrupt and pass.
        try:
            t = clock()
            while not stdin_ready():
                pyglet.clock.tick()
                for window in pyglet.app.windows:
                    window.switch_to()
                    window.dispatch_events()
                    window.dispatch_event('on_draw')
                    flip(window)
    
                # We need to sleep at this point to keep the idle CPU load
                # low.  However, if sleep to long, GUI response is poor.  As
                # a compromise, we watch how often GUI events are being processed
                # and switch between a short and long sleep time.  Here are some
                # stats useful in helping to tune this.
                # time    CPU load
                # 0.001   13%
                # 0.005   3%
                # 0.01    1.5%
                # 0.05    0.5%
                used_time = clock() - t
                if used_time > 5*60.0:
                    # print 'Sleep for 5 s'  # dbg
                    time.sleep(5.0)
                elif used_time > 10.0:
                    # print 'Sleep for 1 s'  # dbg
                    time.sleep(1.0)
                elif used_time > 0.1:
                    # Few GUI events coming in, so we can sleep longer
                    # print 'Sleep for 0.05 s'  # dbg
                    time.sleep(0.05)
                else:
                    # Many GUI events coming in, so sleep only very little
                    time.sleep(0.001)
        except KeyboardInterrupt:
            pass
        return 0
class Assemble_3585(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Assemble a QasmQobjInstruction"""
            instruction = QasmQobjInstruction(name=self.name)
            # Evaluate parameters
            if self.params:
                params = [
                    x.evalf() if hasattr(x, 'evalf') else x for x in self.params
                ]
                params = [
                    sympy.matrix2numpy(x, dtype=complex) if isinstance(
                        x, sympy.Matrix) else x for x in params
                ]
                instruction.params = params
            # Add placeholder for qarg and carg params
            if self.num_qubits:
                instruction.qubits = list(range(self.num_qubits))
            if self.num_clbits:
                instruction.memory = list(range(self.num_clbits))
            # Add control parameters for assembler. This is needed to convert
            # to a qobj conditional instruction at assemble time and after
            # conversion will be deleted by the assembler.
            if self.control:
                instruction._control = self.control
            return instruction
class Get_conn_126(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Returns a connection object"""
            db = self.get_connection(self.presto_conn_id)
            reqkwargs = None
            if db.password is not None:
                reqkwargs = {'auth': HTTPBasicAuth(db.login, db.password)}
            return presto.connect(
                host=db.host,
                port=db.port,
                username=db.login,
                source=db.extra_dejson.get('source', 'airflow'),
                protocol=db.extra_dejson.get('protocol', 'http'),
                catalog=db.extra_dejson.get('catalog', 'hive'),
                requests_kwargs=reqkwargs,
                schema=db.schema)

class System_19625(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, cmd):
        """Win32 version of os.system() that works with network shares.
    
        Note that this implementation returns None, as meant for use in IPython.
    
        Parameters
        ----------
        cmd : str
          A command to be executed in the system shell.
    
        Returns
        -------
        None : we explicitly do NOT return the subprocess status code, as this
        utility is meant to be used extensively in IPython, where any return value
        would trigger :func:`sys.displayhook` calls.
        """
        with AvoidUNCPath() as path:
            if path is not None:
                cmd = '"pushd %s &&"%s' % (path, cmd)
            with Win32ShellCommandController(cmd) as scc:
                scc.run()
class Get_code_144(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, dag_id):
        """Return python code of a given dag_id."""
        session = settings.Session()
        DM = models.DagModel
        dag = session.query(DM).filter(DM.dag_id == dag_id).first()
        session.close()
        # Check DAG exists.
        if dag is None:
            error_message = "Dag id {} not found".format(dag_id)
            raise DagNotFound(error_message)
    
        try:
            with wwwutils.open_maybe_zipped(dag.fileloc, 'r') as f:
                code = f.read()
                return code
        except IOError as e:
            error_message = "Error {} while reading Dag id {} Code".format(str(e), dag_id)
            raise AirflowException(error_message)
class Setup_8577(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Initialization done before entering the debugger-command
            loop. In particular we set up the call stack used for local
            variable lookup and frame/up/down commands.
    
            We return True if we should NOT enter the debugger-command
            loop."""
            self.forget()
            if self.settings('dbg_trepan'):
                self.frame = inspect.currentframe()
                pass
            if self.event in ['exception', 'c_exception']:
                exc_type, exc_value, exc_traceback = self.event_arg
            else:
                _, _, exc_traceback = (None, None, None,)  # NOQA
                pass
            if self.frame or exc_traceback:
                self.stack, self.curindex = \
                    get_stack(self.frame, exc_traceback, None, self)
                self.curframe = self.stack[self.curindex][0]
                self.thread_name = Mthread.current_thread_name()
                if exc_traceback:
                    self.list_lineno = traceback.extract_tb(exc_traceback, 1)[0][1]
                    self.list_offset = self.curframe.f_lasti
                    self.list_object = self.curframe
            else:
                self.stack = self.curframe = \
                    self.botframe = None
                pass
            if self.curframe:
                self.list_lineno = \
                    max(1, inspect.getlineno(self.curframe)
                        - int(self.settings('listsize') / 2)) - 1
                self.list_offset   = self.curframe.f_lasti
                self.list_filename = self.curframe.f_code.co_filename
                self.list_object   = self.curframe
            else:
                if not exc_traceback: self.list_lineno = None
                pass
            # if self.execRcLines()==1: return True
    
            # FIXME:  do we want to save self.list_lineno a second place
            # so that we can do 'list .' and go back to the first place we listed?
            return False
class Get_history_19740(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """get all msg_ids, ordered by time submitted."""
            query = """SELECT msg_id FROM %s ORDER by submitted ASC"""%self.table
            cursor = self._db.execute(query)
            # will be a list of length 1 tuples
            return [ tup[0] for tup in cursor.fetchall()]
class Ainv_21332(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            'Returns a Solver instance'
    
            if not hasattr(self, '_Ainv'):
                self._Ainv = self.Solver(self.A)
            return self._Ainv
class Read_14531(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *paths):
        """Build a file path from *paths* and return the contents."""
        with open(os.path.join(*paths), 'r') as filename:
            return filename.read()
class Getoutput_20050(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, cmd):
        """Return standard output of executing cmd in a shell.
    
        Accepts the same arguments as os.system().
    
        Parameters
        ----------
        cmd : str
          A command to be executed in the system shell.
    
        Returns
        -------
        stdout : str
        """
    
        out = process_handler(cmd, lambda p: p.communicate()[0], subprocess.STDOUT)
        if out is None:
            return ''
        return py3compat.bytes_to_str(out)
class Get_query_811(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Default filters for model
            """
            return (
                super().get_query()
                .filter(or_(models.DagModel.is_active,
                            models.DagModel.is_paused))
                .filter(~models.DagModel.is_subdag)
            )
