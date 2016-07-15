from mittn.fuzzer.static_anomalies import STATIC_ANOMALIES

class AnomalyGenerator(object):

    def __init__(self, radamsa):
        self.radamsa = radamsa

    def collect_values(self, source, target, target_key=None):
        """Recursively collect all values from a data structure into a dict where values are organised under keys,
        or a "None" key if they weren't found under any key.

        For example: {'foo': {'bar': 1, 'baz': 2}, 'toka': 1}

        --> {'foo': [1, 2],
             'toka': [1],
              None: [1, 2, 1]
            }

        XXX: Shouldn't we use set() instead?

        :param source: Source data structure
        :param target: The collected values
        :param target_key: Under which key to store the collected values

        """
        # Each key found in source will have a list of values
        if target_key not in target:
            target[target_key] = []

        # If we see a dict, we will get all the values under that key
        if isinstance(source, dict):
            for key, value in six.iteritems(source):
                self.collect_values(value, target, target_key=key)

        # If we see a list, we will add all values under current key
        elif isinstance(source, list):
            for el in source:
                self.collect_values(el, target, target_key=target_key)

        # If we see an actual value, we will add the value under both the
        # current key and the "None" key
        elif isinstance(source, (six.integer_types, six.string_types, six.text_type, float, bool)) or source is None:
            target[target_key].append(source)
            target[None].append(source)

        else:
            raise NotImplemented

    def create_anomalies(self, branch, anomaly_dict, anomaly_key=None):
        """Walk through a data structure recursively and replace each key and value with an injected (fuzz) case
        one by one.

        The anomaly that is injected is taken from a dict of anomalies. The dict has a "generic" anomaly with
        a key of None, and may have specific anomalies under other keys.

        List length: <number of keys> + <number of values>?

        :param branch: The branch of a data structure to walk into.
        :param anomaly_dict: The anomaly dictionary that has been prepared, must be 1-level deep.
        :param anomaly_key: If the branch where we walk into is under a specific key, this is under what key it is.
        :return: list

        """
        if isinstance(branch, dict):
            fuzzed_branch = []

            # Add cases where *single key* has been replaced with its fuzzed version (value is unchanged)
            for key in branch.keys():
                fuzzdict = branch.copy()

                # Replace key (unchanged value)
                try:
                    new_key = str(anomaly_dict[None])  # Keys need to be strings (why?)
                except UnicodeEncodeError:
                    # Key was too broken to be a string, revenge using key 0xFFFF
                    new_key = '\xff\xff'
                fuzzdict[new_key] = fuzzdict.pop(key)

                fuzzed_branch.append(fuzzdict)

            # Add cases where *single value* has been replaced with its fuzzed version (key is unchanged)
            for key, value in six.iteritems(branch):
                sub_branches = self.create_anomalies(value, anomaly_dict, anomaly_key=key)
                for sub_branch in sub_branches:
                    fuzzdict = branch.copy()
                    fuzzdict[key] = sub_branch
                    fuzzed_branch.append(fuzzdict)

            return fuzzed_branch

        elif isinstance(branch, list):
            fuzzed_branch = []

            # Add cases where *single list item* has been replaced with its fuzzed version
            for i, el in enumerate(branch):
                sub_branches = self.create_anomalies(el, anomaly_dict, anomaly_key=anomaly_key)
                for sub_branch in sub_branches:
                    fuzzdict = copy.copy(branch)
                    fuzzdict[i] = sub_branch
                    fuzzed_branch.append(fuzzdict)

            return fuzzed_branch

        # A leaf node; return just a list of anomalies for a value
        elif isinstance(branch, (six.integer_types, six.string_types, six.text_type, float, bool)) or branch is None:
            anomaly = anomaly_dict.get(anomaly_key, anomaly_dict.get(None))
            return [anomaly]

        # If the data structure contains something that a unserialised JSON
        # cannot contain; instead of just removing it, we return it as-is without
        # injection
        # FIXME: JSON probably cannot contain the *non-fuzzed* version of it (fuzzed version is str), so let's disable this!
        # return [branch]
        raise NotImplemented

    def generate_anomalies(self, wireframe, submissions, amount):

        # Collect values per key from all submissions
        values = {}
        for submission in submissions:
            self.collect_values(submission, values)

        # Create the list of fuzz injections using a helper generator
        fuzzed_anomalies = self.radamsa.fuzz_values(values, amount)

        for index in range(0, amount):
            # Walk through the submission and inject at every key, value

            injection = {}
            for key, value in six.iteritems(fuzzed_anomalies):
                injection[key] = value[index]

            for fuzzed_submission in self.create_anomalies(wireframe, injection):
                yield fuzzed_submission

    def generate_static(self, anomaly_list=STATIC_ANOMALIES):
        for anomaly in anomaly_list:
            yield anomaly
