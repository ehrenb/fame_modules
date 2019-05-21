import json
import os
import subprocess
import traceback

from fame.common.utils import tempdir
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

from .apk_plugins import *


try:
    from androguard.misc import AnalyzeAPK
    HAVE_ANDROGUARD = True
except ImportError:
    HAVE_ANDROGUARD = False

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False


class APK(ProcessingModule):
    name = "apk"
    description = "Perform static analysis on APK/DEX files. Will also run static analysis modules trying to extract configuration from known Android malware."
    acts_on = ["apk"]

    def _get_internal_classes(self, vm_analysis):
        results = []
        for c in vm_analysis.get_internal_classes():
            name = c.get_vm_class().get_name()
            methods = [m.get_method().get_name() for m in c.get_methods()]
            results.append({'name': name,
                            'methods': methods})
        return results

    def _store_internal_classes(self):
        filepath = os.path.join(tempdir(), 'internal_classes.json')
        with open(filepath, 'w') as f:
            json.dump(self.results['internal_classes'], f, sort_keys=True, indent=4)
        self.add_support_file('Internal Classes & Methods', filepath)

    def initialize(self):
        if not HAVE_ANDROGUARD:
            raise ModuleInitializationError(self, "Missing dependency: androguard")
        if not HAVE_MAGIC:
            raise ModuleInitializationError(self, "Missing dependency: python-magic")

    def each(self, target):
        self.results = dict(name=None,
                            files=[],
                            package=None,
                            permissions=[],
                            declared_permissions=[],
                            main_activity=None,
                            activities=[],
                            receivers=[],
                            services=[],
                            manifest=None,
                            libraries=[],
                            main_activity_content=None,
                            internal_classes=[])

        try:
            apk, vm, vm_analysis = AnalyzeAPK(target)

            # First, get basic information about the APK
            self.results['name'] = apk.get_app_name()
            self.results['files'] = apk.get_files_types()
            self.results['package'] = apk.get_package()
            self.results['permissions'] = apk.get_details_permissions()
            self.results['declared_permissions'] = apk.get_declared_permissions_details()
            self.results['main_activity'] = apk.get_main_activity()
            self.results['activities'] = apk.get_activities()
            self.results['receivers'] = apk.get_receivers()
            self.results['services'] = apk.get_services()
            self.results['manifest'] = apk.get_android_manifest_axml().get_xml()
            self.results['libraries'] = list(apk.get_libraries())
            self.results['main_activity_content'] = None
            self.results['internal_classes'] = []
            try:
                self.results['main_activity_content'] = self.results['main_activity_content'] = vm[0].get_class("L{};".format(self.results['main_activity']).replace('.', '/')).get_source()
            except:
                self.log('error',traceback.print_exc())

            try:
                self.results['internal_classes'] = self._get_internal_classes(vm_analysis)
                self._store_internal_classes()
            except:
                self.log('error',traceback.print_exc())

            # Then, run all the APK Plugins in order to see if this is a known malware
            for plugin in APKPlugin.__subclasses__():
                plugin = plugin(target, apk, vm, vm_analysis)
                plugin.apply(self)

        except:
            self.log('error', traceback.print_exc())



        return True
