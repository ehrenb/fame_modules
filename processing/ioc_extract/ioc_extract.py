import json
import re
import string

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    import iocextract
    HAVE_IOCEXTRACT = True
except ImportError:
    HAVE_IOCEXTRACT = False


def _strings(filename, min=4):
    # with open(filename, errors="ignore") as f:  # Python 3.x
    with open(filename, "rb") as f:           # Python 2.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

class IOCExtract(ProcessingModule):
    name = "ioc_extract"
    description = "Search for IOCs using iocextract"
    # acts_on = []

    def initialize(self):
        if not HAVE_IOCEXTRACT:
            raise ModuleInitializationError(self, "Missing dependency: iocextract")

    def each(self, target):
        self.results = dict()

        # combine strings into one space-separated string
        target_strings = ' '.join(list(_strings(target)))

        # extract and add iocs
        self.results['iocs'] = list(iocextract.extract_iocs(target_strings))

        # Add observables
        for ioc in self.results['iocs']:
            self.add_ioc(ioc)
        return True
