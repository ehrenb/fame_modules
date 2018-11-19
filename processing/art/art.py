import json
import traceback

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class ART(ProcessingModule):
    name = "art"
    description = "Perform static analysis on ART files"
    acts_on = "art"

    def initialize(self):
        pass
        
    def each(self, target):
        self.results = dict()
        return True