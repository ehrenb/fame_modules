import json
import re

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    from androguard.misc import AnalyzeAPK, AnalyzeDex
    HAVE_ANDROGUARD = True
except ImportError:
    HAVE_ANDROGUARD = False

r= [r'(content://.*)']
class APKFindContentProviders(ProcessingModule):
    name = "apk_find_content_providers"
    description = "Search for content provider strings containign content://"
    acts_on = ["apk", "dex"]

    def initialize(self):
        if not HAVE_ANDROGUARD:
            raise ModuleInitializationError(self, "Missing dependency: androguard")

    def each(self, target):
        self.results = dict()
        self.results['content_providers'] = []
        try:
            apk, vm, vm_analysis = AnalyzeAPK(target)
        except:
            print('[+] AnalyzeAPK failed, running AnalyzeDex')
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
                    self.results['content_providers'].append(match.group(0))
        self.results['content_providers'] = list(set(self.results['content_providers']))
        return True
