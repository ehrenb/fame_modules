import string

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    import iocextract
    HAVE_IOCEXTRACT = True
except ImportError:
    HAVE_IOCEXTRACT = False

blacklist = ['127.0.0.1', '8.8.8.8']


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

    def initialize(self):
        if not HAVE_IOCEXTRACT:
            raise ModuleInitializationError(self, "Missing dependency: iocextract")

    def each(self, target):
        self.results = dict()



        # combine strings into one space-separated string
        target_strings = ' '.join(list(_strings(target)))

        # extract and add iocs
        iocs = []
        iocs.extend(list(iocextract.extract_ips(target_strings)))
        iocs.extend(list(iocextract.extract_emails(target_strings)))
        iocs.extend(list(iocextract.extract_hashes(target_strings)))
        iocs.extend(list(iocextract.extract_yara_rules(target_strings)))
        # iocs.extend(list(iocextract.extract_urls(target_strings)))
        iocs[:] = (value for value in iocs if value not in blacklist)

        # extract and add iocs
        self.results['iocs'] = iocs

        # Add observables
        for ioc in self.results['iocs']:
            self.add_ioc(ioc)# TODO: tag
        return True
