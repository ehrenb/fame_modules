import json
import traceback
import os

try:
    from androguard.misc import AnalyzeDex
    HAVE_ANDROGUARD = True
except ImportError:
    HAVE_ANDROGUARD = False

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from fame.common.utils import tempdir


class OAT(ProcessingModule):
    name = "oat"
    description = "Perform static analysis on OAT (ODEX, OAT) files"
    acts_on = "oat"

    def _get_internal_classes(self, vm_analysis):
        results = []
        for c in vm_analysis.get_internal_classes():
            name = c.get_vm_class().get_name()
            methods = [m.get_method().get_name() for m in c.get_methods()]
            results.append({'name': name,
                            'methods': methods})
        return results

    def _store_internal_classes(self):
        filepath = os.path.join(tempdir(), 'internal_classes.json')
        with open(filepath, 'w') as f:
            json.dump(self.results['internal_classes'], f, sort_keys=True, indent=4)
        self.add_support_file('Internal Classes & Methods', filepath)

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")
        if not HAVE_ANDROGUARD:
            raise ModuleInitializationError(self, "Missing dependency: androguard")

    def each(self, target):
        self.results = dict()
        try:
            # lief
            oat = lief.parse(target)
            oat_dict = json.loads(lief.to_json(oat), parse_int=str)
            self.results.update(oat_dict)

            # add extracted dex files
            for idx,dex_file in enumerate(oat.dex_files):
                temp = tempdir()
                fname = 'classes_{}.dex'.format(str(idx))
                dex_filepath = os.path.join(temp, fname)
                dex_file.save(dex_filepath)
                if os.path.isfile(dex_filepath):
                    self.add_extracted_file(dex_filepath)

            # androguard
            sha256, vm, vm_analysis = AnalyzeDex(target)
            aguard_dict = {'androguard': {'internal_classes':self._get_internal_classes(vm_analysis)}}
            self.results.update(aguard_dict)
        except:
            self.log('error', traceback.print_exc())
        return True