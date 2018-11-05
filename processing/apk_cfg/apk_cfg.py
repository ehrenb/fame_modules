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
    from networkx.readwrite import json_graph
    HAVE_NETWORKX = True
except ImportError:
    HAVE_NETWORKX = False


class APK_CFG(ProcessingModule):
    name = "apk_cfg"
    description = "Generate NetworkX Control-flow graph (DiGraph) of an APK"
    acts_on = ["apk"]

    def each(self, target):
        self.results = dict()
        try:
            cfg = self.get_call_graph(target)
            self.results['cfg_nx'] = cfg
            self._store_call_graph()
        except:
            print('[+] {}'.format(traceback.print_exc()))
        return True

    def initialize(self):
        if not HAVE_ANDROGUARD:
            raise ModuleInitializationError(self, "Missing dependency: androguard")
        if not HAVE_NETWORKX:
            raise ModuleInitializationError(self, "Missing dependency: networkx")

    def _store_call_graph(self):
        filepath = os.path.join(tempdir(), 'cfg_nx.json')
        with open(filepath, 'w') as f:
            json.dump(self.results['cfg_nx'], f, sort_keys=True, indent=4)
        self.add_support_file('NetworkX Control Flow Graph', filepath)

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
        return json_graph.node_link_data(CG)
