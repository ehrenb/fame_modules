import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class PE(ProcessingModule):
    name = "pe"
    description = "Perform static analysis on PE files"
    acts_on = "executable"

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def each(self, target):
        self.results = dict()
        try:
            binary = lief.parse(target)
            binary_dict = json.loads(lief.to_json(binary))
            self.results.update(binary)
        except:
            self.log('error', traceback.print_exc())
        return True