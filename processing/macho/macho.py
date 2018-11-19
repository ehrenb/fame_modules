import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class MachO(ProcessingModule):
    name = "macho"
    description = "Perform static analysis on MachO files"
    acts_on = "macho"

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def each(self, target):
        self.results = dict()
        try:
            binary = lief.parse(target)
            binary_dict = json.loads(lief.to_json(binary).decode('utf-8','ignore'))
            self.results.update(binary_dict)
        except:
            self.log('error', traceback.print_exc())
        return True