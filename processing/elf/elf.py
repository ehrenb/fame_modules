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
            if lief.OAT.is_oat(target):
                self.change_type(target, 'oat')
                self.results = {
                'message': 'File type was changed to oat.'
            }
                return True
            binary = lief.parse(target)
            binary_dict = json.loads(lief.to_json(binary), parse_int=str)
            self.results.update(binary_dict)
        except:
            self.log('error', traceback.print_exc())
        return True