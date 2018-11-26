import json
import shlex
import subprocess
import traceback
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    import apkid
    HAVE_APKID = True
except ImportError:
    HAVE_APKID = False


class APK_ID(ProcessingModule):
    name = "apk_id"
    description = "Use APKiD to detecte compiler and packers for dex and apk files"
    acts_on = ["apk", "dex"]

    def initialize(self):
        if not HAVE_APKID:
            raise ModuleInitializationError(self, "Missing dependency: apkid")

    def each(self, target):
        self.results = dict()

        try:
            # APKiD packer/compiler detection
            apkid_dict = {'apkid': self.get_apkid(target)}
            self.results.update(apkid_dict)
        except:
            self.log('error',traceback.print_exc()) 
        return True

    def get_apkid(self, target):
        cmd = shlex.split('apkid {} -j'.format(target))
        out = subprocess.check_output(cmd)
        out_dict = json.loads(out)
        return out_dict
