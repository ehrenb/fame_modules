import json
import re

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    from androguard.misc import AnalyzeAPK, AnalyzeDex
    HAVE_ANDROGUARD = True
except ImportError:
    HAVE_ANDROGUARD = False

#src https://www.owasp.org/index.php/OWASP_Validation_Regex_Repository
r= [r'^((((https?|ftps?|gopher|telnet|nntp)://)|(mailto:|news:))(%[0-9A-Fa-f]{2}|[-()_.!~*\';/?:@&=+$,A-Za-z0-9])+)([).!\';/?:,][[:blank:]])?$']

class APKFindURLS(ProcessingModule):
    name = "apk_find_urls"
    description = "Search for strings that match URL and IP patterns"
    acts_on = ["apk", "dex"]

    def initialize(self):
        if not HAVE_ANDROGUARD:
            raise ModuleInitializationError(self, "Missing dependency: androguard")

    def each(self, target):
        self.results = dict()
        self.results['urls'] = []
        try:
            apk, vm, vm_analysis = AnalyzeAPK(target)
        except:
            self.log('error', '[+] AnalyzeAPK failed, running AnalyzeDex')
            apk = None
            vm, vm_analysis = AnalyzeDex(target)
            self.results['dex'] = True
            
        strings = []
        for v in vm:
            strings.extend(v.get_strings())
        for s in strings:
            for regex_str in r:
                match = re.search(regex_str, s, re.IGNORECASE)
                if match:
                    self.results['urls'].append(match.group(0))
        self.results['urls'] = list(set(self.results['urls']))

        # Add observables
        for url in self.results['urls']:
            self.add_ioc(url)
        return True