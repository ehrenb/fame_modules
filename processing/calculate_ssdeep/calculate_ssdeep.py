import pydeep

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    import pydeep
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

class CalculateSSDeep(ProcessingModule):
    name = "calculate_ssdeep"
    description = "Calculate the SSDEEP fuzzy hash for this binary"

    def initialize(self):
        if not HAVE_PYDEEP:
            raise ModuleInitializationError(self, "Missing dependency: pydeep")

    def each(self, target):
        self.results = dict()
        h = pydeep.hash_file(target)
        self.results['ssdeep'] = h

        return True
