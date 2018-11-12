import os
from zipfile import ZipFile


from fame.core.module import ProcessingModule
from fame.common.utils import tempdir


class ApkDetectFromJAR(ProcessingModule):
    name = "apkdetectfromjar"
    description = "Detect APK from Jar file type"
    acts_on = "jar"

    def each(self, target):
        tmpdir = tempdir()

        zf = ZipFile(target)

        namelist = zf.namelist()

        if 'classes.dex' in namelist and 'META-INF/MANIFEST.MF' in namelist:
            self.change_type(target, 'apk')
            self.results = {
                'message': 'File type was changed to apk.'
            }
        return True
