import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False
    
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class ART(ProcessingModule):
    name = "art"
    description = "Perform static analysis on ART files"
    acts_on = "art"

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def each(self, target):
        self.results = dict()
        try:
            binary = lief.ART.parse(target)
            binary_dict = json.loads(lief.to_json(binary))
            self.results.update(binary)
        except:
            self.log('error', traceback.print_exc())
        return True