import json
import traceback

try: 
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

try: 
    import peutils
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False


from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

PE_ID_SIGS_FILE = os.path.join(os.getcwd(),'peid_sigs_11262018.txt')

class PE(ProcessingModule):
    name = "pe"
    description = "Perform static analysis on PE files"
    acts_on = "executable"

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")
        if not HAVE_PEFILE:
            raise ModuleInitializationError(self, "Missing dependency: pefile")

    def each(self, target):
        self.results = dict()
        try:
            # lief analysis
            binary = lief.parse(target)
            binary_dict = json.loads(lief.to_json(binary), parse_int=str)
            self.results.update(binary_dict)

            # packet detect using pefile (PEiD sigs)
            # sig file obtained here https://github.com/erocarrera/pefile/blob/wiki/PEiDSignatures.md
            # named after date downloaded & added to FAME
            signatures = peutils.SignatureDatabase(PE_ID_SIGS_FILE)
            matches = signatures.match(target, ep_only = True)
            packer_dict = {'packers': matches}
            self.results.update(packer_dict)

        except:
            self.log('error', traceback.print_exc())
        return True