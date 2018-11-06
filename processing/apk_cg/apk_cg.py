"""generate call graph using Androguard (3.2.1) in GML.  This is doing exactly
the same thing as androcg.py"""

import json
import os
import traceback

from fame.common.utils import tempdir
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    from androguard.misc import AnalyzeAPK, AnalyzeDex
    from androguard.core.bytecode import FormatClassToJava
    HAVE_ANDROGUARD = True
except ImportError:
    HAVE_ANDROGUARD = False

try:
    import networkx as nx
    HAVE_NETWORKX = True
except ImportError:
    HAVE_NETWORKX = False


class APK_cg(ProcessingModule):
    name = "apk_cg"
    description = "Generate Call graph (DiGraph) of an APK"
    acts_on = ["apk"]

    def each(self, target):
        self.results = dict()
        try:
            cg = self.get_call_graph(target)
            self._store_call_graph(cg)
        except:
            print('[+] {}'.format(traceback.print_exc()))
        return True

    def initialize(self):
        if not HAVE_ANDROGUARD:
            raise ModuleInitializationError(self, "Missing dependency: androguard")
        if not HAVE_NETWORKX:
            raise ModuleInitializationError(self, "Missing dependency: networkx")

    def _store_call_graph(self, cg):
        filepath = os.path.join(tempdir(), 'cg.gml')
        nx.write_gml(cg, filepath, stringizer=str)
        self.add_support_file('Call Graph GML', filepath)

    def get_call_graph(self, apk):
        a, d, dx = AnalyzeAPK(apk)

        entry_points = map(FormatClassToJava, a.get_activities() + a.get_providers() + a.get_services() + a.get_receivers())
        entry_points = list(entry_points)


        #TODO make these Configurable
        # args.classname,
        # args.methodname,
        # args.descriptor,
        # args.accessflag,
        # args.no_isolated,
        CG = dx.get_call_graph(entry_points=entry_points)

        # write_methods = dict(gml=_write_gml,
        #                      gexf=nx.write_gexf,
        #                      gpickle=nx.write_gpickle,
        #                      graphml=nx.write_graphml,
        #                      yaml=nx.write_yaml,
        #                      net=nx.write_pajek,
        return CG
