import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.modules.community.processing.LiefProcessingModule import LiefProcessingModule
from fame.common.exceptions import ModuleInitializationError


class VDEX(LiefProcessingModule):
    name = "vdex"
    description = "Perform static analysis on VDEX files"
    acts_on = ["vdex"]

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def each(self, target):
        self.results = dict()
        try:
            lief_analysis = self.lief_analysis(target)
            self.results.update(lief_analysis)

            ## Do other analyses here
        except:
            print('[+] {}'.format(traceback.print_exc()))
        return True