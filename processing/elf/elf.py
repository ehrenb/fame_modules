import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False
    
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class ELF(ProcessingModule):
    name = "elf"
    description = "Perform static analysis on ELF files"
    acts_on = "elf"

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