import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class DEX(ProcessingModule):
    name = "dex"
    description = "Perform static analysis on DEX files"
    acts_on = "dex"

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def each(self, target):
        self.results = dict()
        try:
            binary = lief.DEX.parse(target)
            binary_dict = json.loads(lief.to_json(binary))
            self.results.update(binary_dict)
        except:
            self.log('error', traceback.print_exc())
        return True