import subprocess
import tempfile
import shutil
import six
import codecs
import os

class PythonRadamsa(object):

    def __init__(self, path):
        self.radamsa_path = path

        # Ensure that binary exists
        try:
            subprocess.check_output([path, "--help"], stderr=subprocess.STDOUT)
        except (subprocess.CalledProcessError, OSError) as e:
            raise ValueError("Could not execute Radamsa from %s: %s" % (path, e))

    def fuzz_values(self, valuedict, no_of_fuzzcases):
        """Run every key's valid value list through a fuzzer.

        :param valuedict: Dict of collected valid values
        :param no_of_fuzzcases: How many injection cases to produce

        """
        fuzzes = {}  # Will hold the result
        for key in valuedict.keys():
            if len(valuedict[key]) == 0:
                # If no values for a key, use the samples under the None key
                fuzzes[key] = self._get_fuzz(valuedict[None], no_of_fuzzcases)
            else:
                # Use the samples collected for the specific key
                fuzzes[key] = self._get_fuzz(valuedict[key], no_of_fuzzcases)

        return fuzzes

    def _get_fuzz(self, valuelist, no_of_fuzzcases):
        """Run Radamsa on a set of valid values.

        :param valuelist: Valid cases to feed to Radamsa.
        :param no_of_fuzzcases: Number of fuzz cases to generate.
        :return:

        """
        # Radamsa is a file-based fuzzer so we need to write the valid strings out to file
        # XXX: Isn't there also piping mechanism? Though writing files might be easier, still...
        valid_case_directory = tempfile.mkdtemp()
        fuzz_case_directory = tempfile.mkdtemp()

        try:
            # XXX: Create file per string, wtf
            for valid_string in valuelist:
                handle, tmpfile_path = tempfile.mkstemp(suffix='.case', dir=valid_case_directory)

                # Radamsa only operates on strings, so make numbers and booleans
                # into strings. (No, this won't fuzz effectively, use static
                # injection to cover those cases.)
                # TODO: Um... what? That is HUGE!
                if isinstance(valid_string, (bool, six.integer_types, float)):
                    valid_string = str(valid_string)

                with codecs.open(tmpfile_path, 'wb', 'utf-8') as fh:
                    fh.write(valid_string)

            # Run Radamsa (one execution for all files)
            try:
                subprocess.check_call([
                    self.radamsa_path,
                    "-o", fuzz_case_directory + "/%n.fuzz",
                    "-n", str(no_of_fuzzcases),
                    "-r", valid_case_directory
                ])
            except subprocess.CalledProcessError as error:
                assert False, "Could not execute Radamsa: %s" % error

            # Read the fuzz cases from the output directory and return as list
            fuzzlist = []
            for filename in os.listdir(fuzz_case_directory):
                # XXX: Radamsa produces even broken bytearrays, so we need to read contents as bytestr!
                # FIXME: Python 3?
                with open(os.path.join(fuzz_case_directory, filename), 'rb') as fh:
                    fuzzlist.append(fh.read())

        finally:
            shutil.rmtree(valid_case_directory)
            shutil.rmtree(fuzz_case_directory)

        return fuzzlist
