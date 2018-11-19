import json
import traceback

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError


class DEX(ProcessingModule):
    name = "dex"
    description = "Perform static analysis on DEX files"
    acts_on = "dex"

    def initialize(self):
        pass

    def each(self, target):
        self.results = dict()
        return True