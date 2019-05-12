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


def strings(filename, min=4):
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
        strings = ' '.join(list(strings(target)))

        # extract and add iocs
        self.results['iocs'] = iocextract.extract_iocs(strings)

        # Add observables
        for url in self.results['iocs']:
            self.add_ioc(url)
        return True
