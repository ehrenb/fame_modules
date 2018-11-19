import json
import traceback

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class PE(ProcessingModule):
    name = "pe"
    description = "Perform static analysis on PE files"
    acts_on = "executable"

    def initialize(self):
        pass

    def each(self, target):
        self.results = dict()
        return True