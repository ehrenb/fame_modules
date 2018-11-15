import json
import traceback

from fame.core.module import ProcessingModule
from fame.modules.community.processing.LiefProcessingModule import LiefProcessingModule
from fame.common.exceptions import ModuleInitializationError


class PE(LiefProcessingModule):
    name = "pe"
    description = "Perform static analysis on PE files"
    acts_on = ["executable"]

    def initialize(self):
        if not HAVE_LIEF:
            raise ModuleInitializationError(self, "Missing dependency: lief")

    def each(self, target):
        self.results = dict()
        try:
            lief_analysis = self.lief_analysis(target)
            self.results.update(lief_analysis)

            ## Do other analyses here
        except:
            print('[+] {}'.format(traceback.print_exc()))
