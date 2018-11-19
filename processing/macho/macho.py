import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

#typically fails due to utf-8 encoding issues that can't be handled
#unless hooking lief's to_json function and decoding
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
            #convert very long ints to str for Mongo
            binary_dict = json.loads(lief.to_json(binary), parse_int=str)
            self.results.update(binary_dict)
        except:
            self.log('error', traceback.print_exc())
        return True