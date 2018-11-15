import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class LiefProcessingModule(ProcessingModule):
    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def lief_analysis(self, target):
        try:
            binary = lief.parse(target)
            binary_dict = json.loads(lief.to_json(binary))
        except:
            print('[+] {}'.format(traceback.print_exc()))
        return binary_dict

    def each(self, target):
        pass
