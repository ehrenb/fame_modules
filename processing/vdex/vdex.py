import json
import traceback

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class VDEX(ProcessingModule):
    name = "vdex"
    description = "Perform static analysis on VDEX files"
    acts_on = "vdex"

    def initialize(self):
        pass

    def each(self, target):
        self.results = dict()
        return True