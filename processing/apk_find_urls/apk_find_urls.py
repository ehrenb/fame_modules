import json
import re

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    from androguard.misc import AnalyzeAPK, AnalyzeDex
    HAVE_ANDROGUARD = True
except ImportError:
    HAVE_ANDROGUARD = False


#The hostname regex matches on 'google.com' which might be too broad
r = [r'^([[a-zA-Z]+:\/\/){0,1}((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))(:[0-9]{0,5}){0,1}$',
     r'^([[a-zA-Z]+:\/\/){0,1}((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(:[0-9]{0,5}){0,1}$']

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
        apk, vm, vm_analysis = AnalyzeAPK(target)
        strings = []
        for v in vm:
            strings.extend(v.get_strings())
        for s in strings:
            for regex_str in r:
                matches = re.findall(regex_str, s)
                self.results['urls'].extend(matches)
            # if any(re.search(regex_str, s) for regex_str in r)