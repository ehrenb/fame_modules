"""resolve abstract types for files using Lief"""

import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class LiefAnalysis(ProcessingModule):
    name = 'liefanalysis'
    description = 'Use lief to perform basic static analysis for abstract types: vdex, dex, executable, elf, macho, oat, art'
    acts_on = ["vdex", "dex", "executable", "elf", "macho", "oat", "art"]
    
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




