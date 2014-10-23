# coding=utf-8


import re
import os.path
import gwt.GWTRequestParser


class GWTReq(object):
    def __init__(self, verbose, debug):
        self.verbose = verbose
        self.debug = debug

        self.is_pipe_used = True
        self.methods_lookup = dict()
        self.re_class_name = re.compile("([\w]+)\.[\w]+\(", re.I)
        self.re_method_name = re.compile("\.([\w]+)\(", re.I)

    def _build_methods_lookup(self, methods):
        if os.path.isfile(methods):
            with open(methods) as f:
                all_methods = f.readlines()

            for method in all_methods:
                method = method.strip()
                class_name = re.search(self.re_class_name, method).group(1)
                method_name = re.search(self.re_method_name, method).group(1)
                params = method.split("(")[1].rstrip(")").split(", ") if "," in method else [method.split("(")[1].rstrip(")")]

                if len(params) == 1 and params[0] == '':
                    l = 0
                else:
                    l = len(params)

                self.methods_lookup[method_name] = {"class": class_name, "nb": l, "params": params}

    def _get_method_and_params(self, method, params):
        try:
            m = self.methods_lookup[method]
        except:
            return None
        else:
            for i, param in enumerate(params):
                m['params'][i] += " " + param

            m['method'] = method

            return m

    def _method_call_to_string(self, method_call):
        return method_call['class'] + "." + method_call['method'] + "(" + ", ".join(method_call['params']) + ")"

    def fuzz(self, user_input):
        pass

    def parse(self, user_input, output, pretty, burp, replace, surround, methods):
        self._build_methods_lookup(methods)
        # method_call = self._get_method_and_params("register", ["t", "b", "c", "d", "e"])
        # print(self._method_call_to_string(method_call))
        # method_call = self._get_method_and_params("getUserInSession", [])
        # print(self._method_call_to_string(method_call))

        if os.path.isfile(user_input):
            with open(user_input) as f:
                content = f.read()
        else:
            content = user_input

        if content.find(b"\xEF\xBF\xBF"):
            self.is_pipe_used = False

        unhex = content.replace(b"\xEF\xBF\xBF", "|")
        requests_to_parse = [a[0] for a in re.findall("\n([\d]+\|[\d]+(.*?)\|[\d]+\|)\n", unhex)]

        for request in requests_to_parse:
            if self.is_pipe_used is False:
                original_request = request.replace("|", b"\xEF\xBF\xBF")
            else:
                original_request = request
