from dispel4py.core import GenericPE
from dispel4py.base import IterativePE, ConsumerPE, ProducerPE
class Get_system_per_cpu_times_83(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Return system CPU times as a named tuple"""
        ret = []
        for cpu_t in _psutil_bsd.get_system_per_cpu_times():
            user, nice, system, idle, irq = cpu_t
            item = _cputimes_ntuple(user, nice, system, idle, irq)
            ret.append(item)
        return ret
class _component_default_60(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Trait initialiser.
            """
            component = Container(fit_window=False, auto_size=True,
                bgcolor="green")#, position=list(self.pos) )
            component.tools.append( MoveTool(component) )
    #        component.tools.append( TraitsTool(component) )
            return component
class Get_ext_memory_info_81(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return a tuple with the process' RSS and VMS size."""
            rss, vms, pfaults, pageins = _psutil_osx.get_process_memory_info(self.pid)
            return self._nt_ext_mem(rss, vms,
                                    pfaults * _PAGESIZE,
                                    pageins * _PAGESIZE)
class Get_plastic_table_72(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
         """
         Calculates the plastic data
         """
         K = self.consistency
         sy = self.yield_stress
         n = self.hardening_exponent
         eps_max = self.max_strain
         Np = self.strain_data_points
         plastic_strain = np.linspace(0., eps_max, Np)
         stress = sy + K * plastic_strain**n 
         return pd.DataFrame({"stress": stress, 
                              "plastic_strain": plastic_strain})
class Get_config_4(ProducerPE):
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
            'seed': self.seed,
        }
        base_config = super(_ConvFlipout, self).get_config()
        return dict(list(base_config.items()) + list(config.items()))
class Dict_repr_html_25(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, dictionary):
        """
        Jupyter Notebook magic repr function.
        """
        rows = ''
        s = '<tr><td><strong>{k}</strong></td><td>{v}</td></tr>'
        for k, v in dictionary.items():
            rows += s.format(k=k, v=v)
        html = '<table>{}</table>'.format(rows)
        return html
class Parsecommandlinearguments_43(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
      """
      Set up command line parsing.
      """
      parser = argparse.ArgumentParser(description="Calculate parallax error for given G and (V-I)")
      parser.add_argument("gmag", help="G-band magnitude of source", type=float)
      parser.add_argument("vmini", help="(V-I) colour of source", type=float)
    
      args=vars(parser.parse_args())
      return args
class Jsonify_parameters_36(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, params):
        """
        When sent in an authorized REST request, only strings and integers can be
        transmitted accurately. Other types of data need to be encoded into JSON.
        """
        result = {}
        for param, value in params.items():
            if isinstance(value, types_not_to_encode):
                result[param] = value
            else:
                result[param] = json.dumps(value)
        return result
class Makeplot_44(ConsumerPE):
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
      av = args['extinction']
      ai = 0.479*av #Cardelli et al R=3.1
    
      spts = ['B0I', 'B1V', 'G2V', 'K4V', 'M0V', 'M6V', 'K1III', 'M0III']
      pointOnePercD = []
      pointOnePercV = []
      onePercD = []
      onePercV = []
      tenPercD = []
      tenPercV = []
      vabsPointOnePerc = []
      vabsOnePerc = []
      vabsTenPerc = []
    
      fig=plt.figure(figsize=(11,7.8))
      deltaHue = 240.0/(len(spts)-1)
      hues = (240.0-np.arange(len(spts))*deltaHue)/360.0
      hsv=np.zeros((1,1,3))
      hsv[0,0,1]=1.0
      hsv[0,0,2]=0.9
      for hue,spt in zip(hues, spts):
        hsv[0,0,0]=hue
        vmags = vabsFromSpt(spt)+5.0*np.log10(distances)-5.0+av
        vmini=vminiFromSpt(spt)+av-ai
        #gmags = gabsFromSpt(spt)+5.0*np.log10(distances)-5.0
        gmags = vmags + gminvFromVmini(vmini)
        relParErr = parallaxErrorSkyAvg(gmags,vmini)*distances/1.0e6
        observed = (gmags>=5.7) & (gmags<=20.0)
        relParErrObs = relParErr[observed]
        # Identify the points where the relative parallax accuracy is 0.1, 1, or 10 per cent.
        if (relParErrObs.min()<0.001):
          index = len(relParErrObs[relParErrObs<=0.001])-1
          pointOnePercD.append(distances[observed][index])
          pointOnePercV.append(vmags[observed][index])
          vabsPointOnePerc.append(vabsFromSpt(spt))
        if (relParErrObs.min()<0.01):
          index = len(relParErrObs[relParErrObs<=0.01])-1
          onePercD.append(distances[observed][index])
          onePercV.append(vmags[observed][index])
          vabsOnePerc.append(vabsFromSpt(spt))
        if (relParErrObs.min()<0.1):
          index = len(relParErrObs[relParErrObs<=0.1])-1
          tenPercD.append(distances[observed][index])
          tenPercV.append(vmags[observed][index])
          vabsTenPerc.append(vabsFromSpt(spt))
        plt.semilogx(distances[observed], vmags[observed], '-', label=spt, color=hsv_to_rgb(hsv)[0,0,:])
        if (spt=='B0I'):
          plt.text(distances[observed][-1]-1.0e5, vmags[observed][-1], spt, horizontalalignment='right',
              verticalalignment='bottom', fontsize=14)
        else:
          plt.text(distances[observed][-1], vmags[observed][-1], spt, horizontalalignment='center',
              verticalalignment='bottom', fontsize=14)
    
      # Draw the "contours" of constant relative parallax accuracy.
      pointOnePercD = np.array(pointOnePercD)
      pointOnePercV = np.array(pointOnePercV)
      indices = np.argsort(vabsPointOnePerc)
      plt.semilogx(pointOnePercD[indices],pointOnePercV[indices],'k--')
      plt.text(pointOnePercD[indices][-1]*1.2,pointOnePercV[indices][-1]-2.5,"$0.1$\\%", ha='right', size=16,
          bbox=dict(boxstyle="round, pad=0.3", ec=(0.0, 0.0, 0.0), fc=(1.0, 1.0, 1.0),))
    
      onePercD = np.array(onePercD)
      onePercV = np.array(onePercV)
      indices = np.argsort(vabsOnePerc)
      plt.semilogx(onePercD[indices],onePercV[indices],'k--')
      plt.text(onePercD[indices][-1]*1.2,onePercV[indices][-1]-2.5,"$1$\\%", ha='right', size=16,
          bbox=dict(boxstyle="round, pad=0.3", ec=(0.0, 0.0, 0.0), fc=(1.0, 1.0, 1.0),))
    
      tenPercD = np.array(tenPercD)
      tenPercV = np.array(tenPercV)
      indices = np.argsort(vabsTenPerc)
      plt.semilogx(tenPercD[indices],tenPercV[indices],'k--')
      plt.text(tenPercD[indices][-1]*1.5,tenPercV[indices][-1]-2.5,"$10$\\%", ha='right', size=16,
          bbox=dict(boxstyle="round, pad=0.3", ec=(0.0, 0.0, 0.0), fc=(1.0, 1.0, 1.0),))
    
      plt.title('Parallax relative accuracy horizons ($A_V={0}$)'.format(av))
    
      plt.xlabel('Distance [pc]')
      plt.ylabel('V')
      plt.grid()
      #leg=plt.legend(loc=4, fontsize=14, labelspacing=0.5)
      plt.ylim(5,26)
      
      basename='ParallaxHorizons'
      if (args['pdfOutput']):
        plt.savefig(basename+'.pdf')
      elif (args['pngOutput']):
        plt.savefig(basename+'.png')
      else:
        plt.show()
class _vp_default_61(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Trait initialiser.
            """
            vp = Viewport(component=self.component)
            vp.enable_zoom=True
    #        vp.view_position = [-10, -10]
            vp.tools.append(ViewportPanTool(vp))
            return vp
class To_dict_40(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            convert the fields of the object into a dictionnary
            """
            dico = dict()
            for field in self.fields.keys():
                if field == "flags":
                    dico[field] = self.flags2text()
                elif field == "state":
                    dico[field] = self.state2text()
                else:
                    dico[field] = eval("self." + field)
            return dico
class Get_conn_2(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Returns a connection object
            """
            db = self.get_connection(getattr(self, self.conn_name_attr))
            return self.connector.connect(
                host=db.host,
                port=db.port,
                username=db.login,
                schema=db.schema)
class To_matrix_10(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return a Numpy.array for the U3 gate."""
            lam = self.params[0]
            lam = float(lam)
            return numpy.array([[1, 0], [0, numpy.exp(1j * lam)]], dtype=complex)
class Load_ipython_extension_82(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, ip):
        """Load the extension in IPython."""
        import sympy
    
        # sympyprinting extension has been moved to SymPy as of 0.7.2, if it
        # exists there, warn the user and import it
        try:
            import sympy.interactive.ipythonprinting
        except ImportError:
            pass
        else:
            warnings.warn("The sympyprinting extension in IPython is deprecated, "
                "use sympy.interactive.ipythonprinting")
            ip.extension_manager.load_extension('sympy.interactive.ipythonprinting')
            return
    
        global _loaded
        if not _loaded:
            plaintext_formatter = ip.display_formatter.formatters['text/plain']
    
            for cls in (object, str):
                plaintext_formatter.for_type(cls, print_basic_unicode)
    
            printable_containers = [list, tuple]
    
            # set and frozen set were broken with SymPy's latex() function, but
            # was fixed in the 0.7.1-git development version. See
            # http://code.google.com/p/sympy/issues/detail?id=3062.
            if sympy.__version__ > '0.7.1':
                printable_containers += [set, frozenset]
            else:
                plaintext_formatter.for_type(cls, print_basic_unicode)
    
            plaintext_formatter.for_type_by_name(
                'sympy.core.basic', 'Basic', print_basic_unicode
            )
            plaintext_formatter.for_type_by_name(
                'sympy.matrices.matrices', 'Matrix', print_basic_unicode
            )
    
            png_formatter = ip.display_formatter.formatters['image/png']
    
            png_formatter.for_type_by_name(
                'sympy.core.basic', 'Basic', print_png
            )
            png_formatter.for_type_by_name(
                'sympy.matrices.matrices', 'Matrix', print_display_png
            )
            for cls in [dict, int, long, float] + printable_containers:
                png_formatter.for_type(cls, print_png)
    
            latex_formatter = ip.display_formatter.formatters['text/latex']
            latex_formatter.for_type_by_name(
                'sympy.core.basic', 'Basic', print_latex
            )
            latex_formatter.for_type_by_name(
                'sympy.matrices.matrices', 'Matrix', print_latex
            )
    
            for cls in printable_containers:
                # Use LaTeX only if every element is printable by latex
                latex_formatter.for_type(cls, print_latex)
    
            _loaded = True
class To_fmt_67(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """
        Return an Fmt representation for pretty-printing
        """
        params = ""
        txt = fmt.sep(" ", ['fun'])
        name = self.show_name()
        if name != "":
            txt.lsdata.append(name)
        tparams = []
        if self.tparams is not None:
            tparams = list(self.tparams)
        if self.variadic:
            tparams.append('...')
        params = '(' + ", ".join(tparams) + ')'
        txt.lsdata.append(': ' + params)
        txt.lsdata.append('-> ' + self.tret)
        return txt
class _repr_html__23(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Jupyter Notebook magic repr function.
            """
            all_keys = list(set(itertools.chain(*[d.keys for d in self])))
            rows = ''
            for decor in self:
                th, tr = decor._repr_html_row_(keys=all_keys)
                rows += '<tr>{}</tr>'.format(tr)
            header = '<tr>{}</tr>'.format(th)
            html = '<table>{}{}</table>'.format(header, rows)
            return html
class System_90(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
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
        # The controller provides interactivity with both
        # stdin and stdout
        #import _process_win32_controller
        #_process_win32_controller.system(cmd)
    
        with AvoidUNCPath() as path:
            if path is not None:
                cmd = '"pushd %s &&"%s' % (path, cmd)
            return process_handler(cmd, _system_body)
class Register_20(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, linter):
        """required method to auto register this checker"""
        linter.register_checker(BasicErrorChecker(linter))
        linter.register_checker(BasicChecker(linter))
        linter.register_checker(NameChecker(linter))
        linter.register_checker(DocStringChecker(linter))
        linter.register_checker(PassChecker(linter))
        linter.register_checker(ComparisonChecker(linter))
class Getoutput_91(IterativePE):
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
    
        with AvoidUNCPath() as path:
            if path is not None:
                cmd = '"pushd %s &&"%s' % (path, cmd)
            out = process_handler(cmd, lambda p: p.communicate()[0], STDOUT)
    
        if out is None:
            out = b''
        return py3compat.bytes_to_str(out)
class _diagram_canvas_default_56(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Trait initialiser """
    
            canvas = Canvas()
    
            for tool in self.tools:
                canvas.tools.append(tool(canvas))
    
            return canvas
class Register_19(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, linter):
        """required method to auto register this checker """
        linter.register_checker(ClassChecker(linter))
        linter.register_checker(SpecialMethodsChecker(linter))
class Internal_name_69(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Return the unique internal name
            """
            unq = 'f_' + super().internal_name()
            if self.tparams is not None:
                unq += "_" + "_".join(self.tparams)
            if self.tret is not None:
                unq += "_" + self.tret
            return unq
class List_overlay_names_70(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return list of overlay names."""
    
            bucket = self.s3resource.Bucket(self.bucket)
    
            overlay_names = []
            for obj in bucket.objects.filter(
                Prefix=self.overlays_key_prefix
            ).all():
    
                overlay_file = obj.key.rsplit('/', 1)[-1]
                overlay_name, ext = overlay_file.split('.')
                overlay_names.append(overlay_name)
    
            return overlay_names
class Register_17(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, linter):
        """required method to auto register this checker """
        linter.register_checker(StringFormatChecker(linter))
        linter.register_checker(StringConstantChecker(linter))
class Makeservice_51(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, opt):
        """Make a service
    
        :params opt: dictionary-like object with 'freq', 'config' and 'messages'
        :returns: twisted.application.internet.TimerService that at opt['freq']
                  checks for stale processes in opt['config'], and sends
                  restart messages through opt['messages']
        """
        restarter, path = beatcheck.parseConfig(opt)
        pool = client.HTTPConnectionPool(reactor)
        agent = client.Agent(reactor=reactor, pool=pool)
        settings = Settings(reactor=reactor, agent=agent)
        states = {}
        checker = functools.partial(check, settings, states, path)
        httpcheck = tainternet.TimerService(opt['freq'], run, restarter, checker)
        httpcheck.setName('httpcheck')
        return heart.wrapHeart(httpcheck)
class Get_system_users_89(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Return currently connected users as a list of namedtuples."""
        retlist = []
        rawlist = _psutil_linux.get_system_users()
        for item in rawlist:
            user, tty, hostname, tstamp, user_process = item
            # XXX the underlying C function includes entries about
            # system boot, run level and others.  We might want
            # to use them in the future.
            if not user_process:
                continue
            if hostname == ':0.0':
                hostname = 'localhost'
            nt = nt_user(user, tty or None, hostname, tstamp)
            retlist.append(nt)
        return retlist
class Info_93(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Returns a description of the trait."""
            result = 'any of ' + repr(self.values)
            if self._allow_none:
                return result + ' or None'
            return result
class _repr_html__24(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Jupyter Notebook magic repr function.
            """
            rows = ''
            s = '<tr><td><strong>{k}</strong></td><td>{v}</td></tr>'
            for k, v in self.__dict__.items():
                rows += s.format(k=k, v=v)
            html = '<table>{}</table>'.format(rows)
            return html
class Update_w_39(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ compute new W """
    
            def select_next(iterval):
                """ select the next best data sample using robust map
                or simply the max iterval ... """
    
                if self._robust_map:
                    k = np.argsort(iterval)[::-1]
                    d_sub = self.data[:,k[:self._robust_nselect]]
                    self.sub.extend(k[:self._robust_nselect])
    
                    # cluster d_sub
                    kmeans_mdl = Kmeans(d_sub, num_bases=self._robust_cluster)
                    kmeans_mdl.factorize(niter=10)
    
                    # get largest cluster
                    h = np.histogram(kmeans_mdl.assigned, range(self._robust_cluster+1))[0]
                    largest_cluster = np.argmax(h)
                    sel = pdist(kmeans_mdl.W[:, largest_cluster:largest_cluster+1], d_sub)
                    sel = k[np.argmin(sel)]
                else:
                    sel = np.argmax(iterval)
    
                return sel
    
            EPS = 10**-8
    
            if scipy.sparse.issparse(self.data):
                norm_data = np.sqrt(self.data.multiply(self.data).sum(axis=0))
                norm_data = np.array(norm_data).reshape((-1))
            else:
                norm_data = np.sqrt(np.sum(self.data**2, axis=0))
    
    
            self.select = []
    
            if self._method == 'pca' or self._method == 'aa':
                iterval = norm_data.copy()
    
            if self._method == 'nmf':
                iterval = np.sum(self.data, axis=0)/(np.sqrt(self.data.shape[0])*norm_data)
                iterval = 1.0 - iterval
    
            self.select.append(select_next(iterval))
    
    
            for l in range(1, self._num_bases):
    
                if scipy.sparse.issparse(self.data):
                    c = self.data[:, self.select[-1]:self.select[-1]+1].T * self.data
                    c = np.array(c.todense())
                else:
                    c = np.dot(self.data[:,self.select[-1]], self.data)
    
                c = c/(norm_data * norm_data[self.select[-1]])
    
                if self._method == 'pca':
                    c = 1.0 - np.abs(c)
                    c = c * norm_data
    
                elif self._method == 'aa':
                    c = (c*-1.0 + 1.0)/2.0
                    c = c * norm_data
    
                elif self._method == 'nmf':
                    c = 1.0 - np.abs(c)
    
                ### update the estimated volume
                iterval = c * iterval
    
                # detect the next best data point
                self.select.append(select_next(iterval))
    
                self._logger.info('cur_nodes: ' + str(self.select))
    
            # sort indices, otherwise h5py won't work
            self.W = self.data[:, np.sort(self.select)]
    
            # "unsort" it again to keep the correct order
            self.W = self.W[:, np.argsort(np.argsort(self.select))]
class Migrate_control_48(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, comp):
        "Take a pythoncard background resource and convert to a gui2py window"
        ret = {}
        for k, v in comp.items():
            if k == 'type':
                v = CTRL_MAP[v]._meta.name
            elif k == 'menubar':
                pass
            elif k == 'components':
                v = [migrate_control(comp) for comp in v]
            else:
                k = SPEC_MAP['Widget'].get(k, k)
                if comp['type'] in SPEC_MAP:
                    k = SPEC_MAP[comp['type']].get(k, k)
                if k == 'font':
                    v = migrate_font(v)
            ret[k] = v
        return ret
class _get_roles_29(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            :rtype: list(list(str))
            """
            roles = []
            for child in self.vcard.getChildren():
                if child.name == "ROLE":
                    roles.append(child.value)
            return sorted(roles)
class Transpose_13(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return the transpose of the QuantumChannel."""
            # Make bipartite matrix
            d_in, d_out = self.dim
            data = np.reshape(self._data, (d_in, d_out, d_in, d_out))
            # Swap input and output indicies on bipartite matrix
            data = np.transpose(data, (1, 0, 3, 2))
            # Transpose channel has input and output dimensions swapped
            data = np.reshape(data, (d_in * d_out, d_in * d_out))
            return Choi(
                data, input_dims=self.output_dims(), output_dims=self.input_dims())
class Write_inp_71(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """
        Returns the material definition as a string in Abaqus INP format.
        """
        template = self.get_template()
        plastic_table = self.get_plastic_table()
        return template.substitute({
            "class": self.__class__.__name__,
            "label": self.label,
            "young_modulus": self.young_modulus,
            "poisson_ratio": self.poisson_ratio,
            "plastic_table": (self.get_plastic_table()[["stress", "plastic_strain"]]
                              .to_csv(header = False, 
                                      index = False,
                                      sep = ",").strip())}).strip()
class To_fmt_65(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """
        Return an Fmt representation for pretty-printing
        """
        qual = "evalctx"
        lseval = []
        block = fmt.block(":\n", "", fmt.tab(lseval))
        txt = fmt.sep(" ", [qual, block])
        lseval.append(self._sig.to_fmt())
        if len(self.resolution) > 0:
            lsb = []
            for k in sorted(self.resolution.keys()):
                s = self.resolution[k]
                if s is not None:
                    lsb.append(
                        fmt.end(
                            "\n",
                            ["'%s': %s (%s)" % (k, s, s().show_name())]
                        )
                    )
                else:
                    lsb.append(fmt.end("\n", ["'%s': Unresolved" % (k)]))
            if self._translate_to is not None:
                lsb.append("use translator:")
                lsb.append(self._translate_to.to_fmt())
            if self._variadic_types is not None:
                lsb.append("variadic types:\n")
                arity = self._sig.arity
                for t in self._variadic_types:
                    lsb.append("[%d] : %s\n" % (arity, t))
                    arity += 1
            lseval.append(fmt.block("\nresolution :\n", "", fmt.tab(lsb)))
        return txt
class Main_62(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, argv):
        """main program loop"""
    
        global output_dir
    
        try:
            opts, args = getopt.getopt( sys.argv[1:], \
                                        "ht:o:p:",    \
                                        ["help", "title=", "output=", "prefix="] )
        except getopt.GetoptError:
            usage()
            sys.exit( 2 )
    
        if args == []:
            usage()
            sys.exit( 1 )
    
        # process options
        #
        project_title  = "Project"
        project_prefix = None
        output_dir     = None
    
        for opt in opts:
            if opt[0] in ( "-h", "--help" ):
                usage()
                sys.exit( 0 )
    
            if opt[0] in ( "-t", "--title" ):
                project_title = opt[1]
    
            if opt[0] in ( "-o", "--output" ):
                utils.output_dir = opt[1]
    
            if opt[0] in ( "-p", "--prefix" ):
                project_prefix = opt[1]
    
        check_output()
    
        # create context and processor
        source_processor  = SourceProcessor()
        content_processor = ContentProcessor()
    
        # retrieve the list of files to process
        file_list = make_file_list( args )
        for filename in file_list:
            source_processor.parse_file( filename )
            content_processor.parse_sources( source_processor )
    
        # process sections
        content_processor.finish()
    
        formatter = HtmlFormatter( content_processor, project_title, project_prefix )
    
        formatter.toc_dump()
        formatter.index_dump()
        formatter.section_dump_all()
class Get_history_92(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """get all msg_ids, ordered by time submitted."""
            cursor = self._records.find({},{'msg_id':1}).sort('submitted')
            return [ rec['msg_id'] for rec in cursor ]
class Read_85(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *paths):
        """Build a file path from *paths* and return the contents."""
        with open(os.path.join(*paths), 'r') as file_handler:
            return file_handler.read()
class Conjugate_8(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return the conjugate of the QuantumChannel."""
            # pylint: disable=assignment-from-no-return
            stine_l = np.conjugate(self._data[0])
            stine_r = None
            if self._data[1] is not None:
                stine_r = np.conjugate(self._data[1])
            return Stinespring((stine_l, stine_r), self.input_dims(),
                               self.output_dims())
class _fetchchildren_53(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''Fetch and return new child items.'''
            children = []
    
            # List paths under this directory.
            paths = []
            for name in os.listdir(self.path):
                paths.append(os.path.normpath(os.path.join(self.path, name)))
    
            # Handle collections.
            collections, remainder = clique.assemble(
                paths, [clique.PATTERNS['frames']]
            )
    
            for path in remainder:
                try:
                    child = ItemFactory(path)
                except ValueError:
                    pass
                else:
                    children.append(child)
    
            for collection in collections:
                children.append(Collection(collection))
    
            return children
class Get_history_78(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """get all msg_ids, ordered by time submitted."""
            msg_ids = self._records.keys()
            return sorted(msg_ids, key=lambda m: self._records[m]['submitted'])
class Index_42(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Display a list of all user institutes."""
        institute_objs = user_institutes(store, current_user)
        institutes_count = ((institute_obj, store.cases(collaborator=institute_obj['_id']).count())
                            for institute_obj in institute_objs if institute_obj)
        return dict(institutes=institutes_count)
class To_fmt_66(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """
        Return an Fmt representation for pretty-printing
        """
        params = ""
        txt = fmt.sep(" ", ['val'])
        name = self.show_name()
        if name != "":
            txt.lsdata.append(name)
        txt.lsdata.append('(%s)' % self.value)
        txt.lsdata.append(': ' + self.tret)
        return txt
class Get_memory_info_84(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return a tuple with the process' RSS and VMS size."""
            rss, vms = _psutil_bsd.get_process_memory_info(self.pid)[:2]
            return nt_meminfo(rss, vms)
class Count_relations_38(IterativePE):
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
    
        root_w0_relations = set(chain.from_iterable(relations[t.index, :].indices for t in w0.root))
        flexing_w0_relations = set(chain.from_iterable(relations[t.index, :].indices for t in w0.flexing))
    
        def f(w1):
            root_w1 = set(t.index for t in w1.root)
            flexing_w1 = set(t.index for t in w1.flexing)
    
            count = [root_w0_relations.intersection(root_w1),
                     flexing_w0_relations.intersection(flexing_w1),
                     root_w0_relations.intersection(flexing_w1) | flexing_w0_relations.intersection(root_w1)]
    
            if any(count):
                return max((1,2,3), key=lambda i: len(count[i - 1]))
            else:
                return 0
        return f
class Dist_in_usersite_87(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, dist):
        """
        Return True if given Distribution is installed in user site.
        """
        if user_site:
            return normalize_path(dist_location(dist)).startswith(normalize_path(user_site))
        else:
            return False
class Get_vid_from_url_0(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, url):
            """Extracts video ID from URL.
            """
            vid = match1(url, 'https?://www.mgtv.com/(?:b|l)/\d+/(\d+).html')
            if not vid:
                vid = match1(url, 'https?://www.mgtv.com/hz/bdpz/\d+/(\d+).html')
            return vid
class Transpose_15(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return the transpose of the QuantumChannel."""
            return SuperOp(
                np.transpose(self._data),
                input_dims=self.output_dims(),
                output_dims=self.input_dims())
class _get_notes_31(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            :rtype: list(list(str))
            """
            notes = []
            for child in self.vcard.getChildren():
                if child.name == "NOTE":
                    notes.append(child.value)
            return sorted(notes)
class Other_supplementary_files_50(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """The supplementary files of this notebook"""
            if self._other_supplementary_files is not None:
                return self._other_supplementary_files
            return getattr(self.nb.metadata, 'other_supplementary_files', None)
class To_matrix_7(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return a Numpy.array for the U3 gate."""
            isqrt2 = 1 / numpy.sqrt(2)
            phi, lam = self.params
            phi, lam = float(phi), float(lam)
            return numpy.array([[isqrt2, -numpy.exp(1j * lam) * isqrt2],
                                [
                                    numpy.exp(1j * phi) * isqrt2,
                                    numpy.exp(1j * (phi + lam)) * isqrt2
                                ]],
                               dtype=complex)
class Close_74(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Stop listing for new connections and close all open connections.
            
            :returns: Deferred that calls back once everything is closed.
            """
            assert self._opened, "RPC System is not opened"
            logger.debug("Closing rpc system. Stopping ping loop")
            self._ping_loop.stop()
            if self._ping_current_iteration:
                self._ping_current_iteration.cancel()
            return self._connectionpool.close()
class Inputhook_glut_86(ProducerPE):
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
    
        signal.signal(signal.SIGINT, glut_int_handler)
    
        try:
            t = clock()
    
            # Make sure the default window is set after a window has been closed
            if glut.glutGetWindow() == 0:
                glut.glutSetWindow( 1 )
                glutMainLoopEvent()
                return 0
    
            while not stdin_ready():
                glutMainLoopEvent()
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
class To_esri_wkt_27(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Returns the CS as a ESRI WKT formatted string.
            """
            string = 'PROJCS["%s", %s, %s, ' % (self.name, self.geogcs.to_esri_wkt(), self.proj.to_esri_wkt() )
            string += ", ".join(param.to_esri_wkt() for param in self.params)
            string += ', %s' % self.unit.to_esri_wkt()
            string += ', AXIS["X", %s], AXIS["Y", %s]]' % (self.twin_ax[0].esri_wkt, self.twin_ax[1].esri_wkt )
            return string
class Get_nicknames_30(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            :rtype: list(list(str))
            """
            nicknames = []
            for child in self.vcard.getChildren():
                if child.name == "NICKNAME":
                    nicknames.append(child.value)
            return sorted(nicknames)
class Format_location_35(IterativePE):
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
        location = {}
        core_obj = proc_obj.core
        dbgr_obj = proc_obj.debugger
    
        # Evaluation routines like "exec" don't show useful location
        # info. In these cases, we will use the position before that in
        # the stack.  Hence the looping below which in practices loops
        # once and sometimes twice.
        while i_stack >= 0:
            frame_lineno = proc_obj.stack[i_stack]
            i_stack -= 1
            frame, lineno = frame_lineno
    
            filename = Mstack.frame2file(core_obj, frame)
    
            location['filename'] = filename
            location['fn_name']  = frame.f_code.co_name
            location['lineno']   = lineno
    
            if '<string>' == filename and dbgr_obj.eval_string:
                filename = pyficache.unmap_file(filename)
                if '<string>' == filename:
                    fd = tempfile.NamedTemporaryFile(suffix='.py',
                                                     prefix='eval_string',
                                                     delete=False)
                    fd.write(bytes(dbgr_obj.eval_string, 'UTF-8'))
                    fd.close()
                    pyficache.remap_file(fd.name, '<string>')
                    filename = fd.name
                    pass
                pass
    
            opts = {
                'reload_on_change' : proc_obj.settings('reload'),
                'output'           : 'plain'
                }
            line = pyficache.getline(filename, lineno, opts)
            if not line:
                line = linecache.getline(filename, lineno,
                                         proc_obj.curframe.f_globals)
                pass
    
            if line and len(line.strip()) != 0:
                location['text'] = line
                pass
            if '<string>' != filename: break
            pass
    
        return location
class Get_last_name_first_name_28(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            :rtype: str
            """
            last_names = []
            if self._get_last_names():
                last_names += self._get_last_names()
            first_and_additional_names = []
            if self._get_first_names():
                first_and_additional_names += self._get_first_names()
            if self._get_additional_names():
                first_and_additional_names += self._get_additional_names()
            if last_names and first_and_additional_names:
                return "{}, {}".format(
                    helpers.list_to_string(last_names, " "),
                    helpers.list_to_string(first_and_additional_names, " "))
            elif last_names:
                return helpers.list_to_string(last_names, " ")
            elif first_and_additional_names:
                return helpers.list_to_string(first_and_additional_names, " ")
            else:
                return self.get_full_name()
class Virtual_memory_79(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """System virtual memory as a namedtuple."""
        total, active, inactive, wired, free = _psutil_osx.get_virtual_mem()
        avail = inactive + free
        used = active + inactive + wired
        percent = usage_percent((total - avail), total, _round=1)
        return nt_virtmem_info(total, avail, percent, used, free,
                               active, inactive, wired)
class Systemctypeofsig_37(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, signalItem):
        """
        Check if is register or wire
        """
        if signalItem._const or\
           arr_any(signalItem.drivers,
                   lambda d: isinstance(d, HdlStatement)
                   and d._now_is_event_dependent):
    
            return SIGNAL_TYPE.REG
        else:
            return SIGNAL_TYPE.WIRE
class Get_dag_code_1(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, dag_id):
        """Return python code of a given dag_id."""
        try:
            return get_code(dag_id)
        except AirflowException as err:
            _log.info(err)
            response = jsonify(error="{}".format(err))
            response.status_code = err.status_code
            return response
class _populate_commands_34(ProducerPE):
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
            cmd_instances = []
            from trepan.bwprocessor import command as Mcommand
            eval_cmd_template = 'command_mod.%s(self)'
            for mod_name in Mcommand.__modules__:
                import_name = "command." + mod_name
                try:
                    command_mod = getattr(__import__(import_name), mod_name)
                except:
                    print('Error importing %s: %s' % (mod_name, sys.exc_info()[0]))
                    continue
    
                classnames = [ tup[0] for tup in
                               inspect.getmembers(command_mod, inspect.isclass)
                               if ('DebuggerCommand' != tup[0] and
                                   tup[0].endswith('Command')) ]
                for classname in classnames:
                    eval_cmd = eval_cmd_template % classname
                    try:
                        instance = eval(eval_cmd)
                        cmd_instances.append(instance)
                    except:
                        print('Error loading %s from %s: %s' %
                              (classname, mod_name, sys.exc_info()[0]))
                        pass
                    pass
                pass
            return cmd_instances
class _fetchchildren_54(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            '''Fetch and return new child items.'''
            children = []
            for path in self._collection:
                try:
                    child = ItemFactory(path)
                except ValueError:
                    pass
                else:
                    children.append(child)
    
            return children
class Pseudo_tempname_88(ProducerPE):
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
                pid = random.randint(0,sys.maxint)
            return os.path.join(self.install_dir, "test-easy-install-%s" % pid)
class Pip_version_check_95(ConsumerPE):
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
                pypi_version = resp.json()["info"]["version"]
    
                # save that we've performed a check
                state.save(pypi_version, current_time)
    
            pip_version = pkg_resources.parse_version(pip.__version__)
    
            # Determine if our pypi_version is older
            if pip_version < pkg_resources.parse_version(pypi_version):
                logger.warning(
                    "You are using pip version %s, however version %s is "
                    "available.\nYou should consider upgrading via the "
                    "'pip install --upgrade pip' command." % (pip.__version__,
                                                              pypi_version)
                )
    
        except Exception:
            logger.debug(
                "There was an error checking the latest version of pip",
                exc_info=True,
            )
class Safe_start_capture_45(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, event):
        '''Start a capture process but make sure to catch any errors during this
        process, log them but otherwise ignore them.
        '''
        try:
            start_capture(event)
        except Exception:
            logger.error('Recording failed')
            logger.error(traceback.format_exc())
            # Update state
            recording_state(event.uid, 'capture_error')
            update_event_status(event, Status.FAILED_RECORDING)
            set_service_status_immediate(Service.CAPTURE, ServiceStatus.IDLE)
class Pid_exists_75(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, pid):
        """Check whether pid exists in the current process table."""
        if not isinstance(pid, int):
            raise TypeError('an integer is required')
        if pid < 0:
            return False
        try:
            os.kill(pid, 0)
        except OSError:
            e = sys.exc_info()[1]
            return e.errno == errno.EPERM
        else:
            return True
class Bit_string_index_11(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, s):
        """Return the index of a string of 0s and 1s."""
        n = len(s)
        k = s.count("1")
        if s.count("0") != n - k:
            raise VisualizationError("s must be a string of 0 and 1")
        ones = [pos for pos, char in enumerate(s) if char == "1"]
        return lex_index(n, k, ones)

class _viewport_default_57(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Trait initialiser """
    
            vp = Viewport(component=self.diagram_canvas, enable_zoom=True)
            vp.view_position = [0,0]
            vp.tools.append(ViewportPanTool(vp))
            return vp
class Playerseasonfinder_63(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, **kwargs):
        """ Docstring will be filled in by __init__.py """
    
        if 'offset' not in kwargs:
            kwargs['offset'] = 0
    
        playerSeasons = []
        while True:
            querystring = _kwargs_to_qs(**kwargs)
            url = '{}?{}'.format(PSF_URL, querystring)
            if kwargs.get('verbose', False):
                print(url)
            html = utils.get_html(url)
            doc = pq(html)
            table = doc('table#results')
            df = utils.parse_table(table)
            if df.empty:
                break
    
            thisSeason = list(zip(df.player_id, df.year))
            playerSeasons.extend(thisSeason)
    
            if doc('*:contains("Next Page")'):
                kwargs['offset'] += 100
            else:
                break
    
        return playerSeasons
class Conjugate_14(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return the conjugate of the QuantumChannel."""
            return SuperOp(
                np.conj(self._data), self.input_dims(), self.output_dims())
class Transpose_9(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return the transpose of the QuantumChannel."""
            din, dout = self.dim
            dtr = self._data[0].shape[0] // dout
            stine = [None, None]
            for i, mat in enumerate(self._data):
                if mat is not None:
                    stine[i] = np.reshape(
                        np.transpose(np.reshape(mat, (dout, dtr, din)), (2, 1, 0)),
                        (din * dtr, dout))
            return Stinespring(
                tuple(stine),
                input_dims=self.output_dims(),
                output_dims=self.input_dims())
class _get_webpages_32(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            :rtype: list(list(str))
            """
            urls = []
            for child in self.vcard.getChildren():
                if child.name == "URL":
                    urls.append(child.value)
            return sorted(urls)

class Bip32_deserialize_52(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, data):
        """
        Derived from code from pybitcointools (https://github.com/vbuterin/pybitcointools)
        by Vitalik Buterin
        """
        dbin = changebase(data, 58, 256)
        if bin_dbl_sha256(dbin[:-4])[:4] != dbin[-4:]:
            raise Exception("Invalid checksum")
        vbytes = dbin[0:4]
        depth = from_byte_to_int(dbin[4])
        fingerprint = dbin[5:9]
        i = decode(dbin[9:13], 256)
        chaincode = dbin[13:45]
        key = dbin[46:78]+b'\x01' if vbytes in PRIVATE else dbin[45:78]
        return (vbytes, depth, fingerprint, i, chaincode, key)
class To_ogc_wkt_26(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Returns the CS as a OGC WKT formatted string.
            """
            string = 'PROJCS["%s", %s, %s, ' % (self.name, self.geogcs.to_ogc_wkt(), self.proj.to_ogc_wkt() )
            string += ", ".join(param.to_ogc_wkt() for param in self.params)
            string += ', %s' % self.unit.to_ogc_wkt()
            string += ', AXIS["X", %s], AXIS["Y", %s]]' % (self.twin_ax[0].ogc_wkt, self.twin_ax[1].ogc_wkt )
            return string
class _name_default_58(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Trait initialiser.
            """
            # 'obj' is a io.File
            self.obj.on_trait_change(self.on_path, "path")
    
            return basename(self.obj.path)
class Get_disk_usage_76(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, path):
        """Return disk usage associated with path."""
        st = os.statvfs(path)
        free = (st.f_bavail * st.f_frsize)
        total = (st.f_blocks * st.f_frsize)
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        percent = usage_percent(used, total, _round=1)
        # NB: the percentage is -5% than what shown by df due to
        # reserved blocks that we are currently not considering:
        # http://goo.gl/sWGbH
        return nt_diskinfo(total, used, free, percent)
class Fetch_ensembl_exons_41(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, build='37'):
        """Fetch the ensembl genes
        
        Args:
            build(str): ['37', '38']
        """
        LOG.info("Fetching ensembl exons build %s ...", build)
        if build == '37':
            url = 'http://grch37.ensembl.org'
        else:
            url = 'http://www.ensembl.org'
        
        dataset_name = 'hsapiens_gene_ensembl'
        
        dataset = pybiomart.Dataset(name=dataset_name, host=url)
        
        attributes = [
            'chromosome_name',
            'ensembl_gene_id',
            'ensembl_transcript_id',
            'ensembl_exon_id',
            'exon_chrom_start',
            'exon_chrom_end',
            '5_utr_start',
            '5_utr_end',
            '3_utr_start',
            '3_utr_end',
            'strand',
            'rank'
        ]
        
        filters = {
            'chromosome_name': CHROMOSOMES,
        }
        
        result = dataset.query(
            attributes = attributes,
            filters = filters
        )
        
        return result
class Read_55(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, *paths):
        """Build a file path from *paths* and return the contents."""
        filename = os.path.join(*paths)
        with codecs.open(filename, mode='r', encoding='utf-8') as handle:
            return handle.read()
class Ainv_94(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            'Returns a Solver instance'
    
            if getattr(self, '_Ainv', None) is None:
                self._Ainv = self.Solver(self.A, 13)
                self._Ainv.run_pardiso(12)
            return self._Ainv
class Get_scope_names_64(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
     list
class Register_18(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, linter):
        """required method to auto register this checker"""
        linter.register_checker(EncodingChecker(linter))
        linter.register_checker(ByIdManagedMessagesChecker(linter))
class _get_name_59(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ Property getter.
            """
            if (self.tail_node is not None) and (self.head_node is not None):
                return "%s %s %s" % (self.tail_node.ID, self.conn,
                                     self.head_node.ID)
            else:
                return "Edge"
class Failure_message_49(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """ str: A message describing the query failure. """
    
            message = failure_message(self.query.description, self.query.options)
    
            if len(self) > 0:
                message += ", found {count} {matches}: {results}".format(
                    count=len(self),
                    matches=declension("match", "matches", len(self)),
                    results=", ".join([desc(node.text) for node in self]))
            else:
                message += " but there were no matches"
    
            if self._rest:
                elements = ", ".join([desc(element.text) for element in self._rest])
                message += (". Also found {}, which matched the selector"
                            " but not all filters.".format(elements))
    
            return message
class Get_config_5(ProducerPE):
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
            'units': self.units,
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
        base_config = super(_DenseVariational, self).get_config()
        return dict(list(base_config.items()) + list(config.items()))
class Get_count_query_3(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """
            Default filters for model
            """
            return (
                super().get_count_query()
                .filter(models.DagModel.is_active)
                .filter(~models.DagModel.is_subdag)
            )
class Assemble_6(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Assemble a QasmQobjInstruction"""
            instruction = super().assemble()
            if self.label:
                instruction.label = self.label
            return instruction
class Prepare_outdir_21(ProducerPE):
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
    
            # handle gene_sets
            logfile = os.path.join(self.outdir, "gseapy.%s.%s.log" % (self.module, self.descriptions))
            return logfile
class Ds2p_73(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Calculates the derivative of the neutron separation energies:
    
            ds2n(Z,A) = s2n(Z,A) - s2n(Z,A+2)
            """
            idx = [(x[0] + 2, x[1]) for x in self.df.index]
            values = self.s2p.values - self.s2p.loc[idx].values
            return Table(df=pd.Series(values, index=self.df.index, name='ds2p' + '(' + self.name + ')'))
class Add_parameters_46(ConsumerPE):
    def __init__(self):
        ConsumerPE.__init__(self)
    def _process(self, traj):
            """Adds all neuron group parameters to `traj`."""
            assert(isinstance(traj,Trajectory))
    
            traj.v_standard_parameter = Brian2Parameter
            scale = traj.simulation.scale
    
            traj.f_add_parameter('connections.R_ee', 1.0, comment='Scaling factor for clustering')
    
            traj.f_add_parameter('connections.clustersize_e', 100, comment='Size of a cluster')
            traj.f_add_parameter('connections.strength_factor', 2.5,
                                 comment='Factor for scaling cluster weights')
    
            traj.f_add_parameter('connections.p_ii', 0.25,
                                comment='Connection probability from inhibitory to inhibitory' )
            traj.f_add_parameter('connections.p_ei', 0.25,
                                comment='Connection probability from inhibitory to excitatory' )
            traj.f_add_parameter('connections.p_ie', 0.25,
                                comment='Connection probability from excitatory to inhibitory' )
            traj.f_add_parameter('connections.p_ee', 0.1,
                                comment='Connection probability from excitatory to excitatory' )
    
            traj.f_add_parameter('connections.J_ii', 0.027/np.sqrt(scale),
                                 comment='Connection strength from inhibitory to inhibitory')
            traj.f_add_parameter('connections.J_ei', 0.032/np.sqrt(scale),
                                 comment='Connection strength from inhibitory to excitatroy')
            traj.f_add_parameter('connections.J_ie', 0.009/np.sqrt(scale),
                                 comment='Connection strength from excitatory to inhibitory')
            traj.f_add_parameter('connections.J_ee', 0.012/np.sqrt(scale),
                                 comment='Connection strength from excitatory to excitatory')
class Conjugate_12(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Return the conjugate of the QuantumChannel."""
            return Choi(np.conj(self._data), self.input_dims(), self.output_dims())
class Assemble_16(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
            """Assemble a QasmQobjInstruction"""
            instruction = super().assemble()
            instruction.label = self._label
            instruction.snapshot_type = self._snapshot_type
            return instruction
class Setup_33(ProducerPE):
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
    
            else:
                self.stack = self.curframe = \
                    self.botframe = None
                pass
            if self.curframe:
                self.list_lineno = \
                    max(1, inspect.getlineno(self.curframe))
            else:
                self.list_lineno = None
                pass
            # if self.execRcLines()==1: return True
            return False
class To_fmt_68(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
     fmt.indentable
class Swap_memory_80(ProducerPE):
    def __init__(self):
        ProducerPE.__init__(self)
    def _process(self):
        """Swap system memory as a (total, used, free, sin, sout) tuple."""
        total, used, free, sin, sout = _psutil_osx.get_swap_mem()
        percent = usage_percent(used, total, _round=1)
        return nt_swapmeminfo(total, used, free, percent, sin, sout)
class Cwd_filt2_77(IterativePE):
    def __init__(self):
        IterativePE.__init__(self)
    def _process(self, depth):
        """Return the last depth elements of the current working directory.
    
        $HOME is always replaced with '~'.
        If depth==0, the full path is returned."""
    
        full_cwd = os.getcwdu()
        cwd = full_cwd.replace(HOME,"~").split(os.sep)
        if '~' in cwd and len(cwd) == depth+1:
            depth += 1
        drivepart = ''
        if sys.platform == 'win32' and len(cwd) > depth:
            drivepart = os.path.splitdrive(full_cwd)[0]
        out = drivepart + '/'.join(cwd[-depth:])
    
        return out or os.sep
