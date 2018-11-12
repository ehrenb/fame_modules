import os
import gzip
import shutil

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir


class Gz(ProcessingModule):
    name = "gz"
    description = "Extract files from GZip archive."
    acts_on = "gz"

    def each(self, target):
        tmpdir = tempdir()

        with gzip.open(target, 'rb') as f_in:
            filepath = os.path.join(tmpdir, target)
            with open(filepath, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
                self.add_extracted_file(filepath)

        return True
