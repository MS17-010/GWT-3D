# coding=utf-8


import re
import sys
import os.path
import gwt.GWTRequestParser


class GWTReq(object):
    def __init__(self, user_input, output, pretty, burp, replace, surround, methods, verbose, debug):
        self.user_input = user_input
        self.output = output
        self.pretty = pretty
        self.burp = burp
        self.replace = replace
        self.surround = surround
        self.verbose = verbose
        self.debug = debug

        self._parser = gwt.GWTRequestParser.GWTReqParser(burp, replace, surround, verbose, debug)
        self._is_pipe_used = True
        self._methods_lookup = dict()
        self._re_class_name = re.compile("([\w]+)\.[\w]+\(", re.I)
        self._re_method_name = re.compile("\.([\w]+)\(", re.I)
        self._to_display = "\n"
        self._original_request = ""

        if methods is not None:
            self._build_methods_lookup(methods)

    def _build_methods_lookup(self, methods):
        if os.path.isfile(methods):
            with open(methods) as f:
                all_methods = f.readlines()

            for method in all_methods:
                method = method.strip()
                class_name = re.search(self._re_class_name, method).group(1)
                method_name = re.search(self._re_method_name, method).group(1)
                params = method.split("(")[1].rstrip(")").split(", ") if "," in method else [method.split("(")[1].rstrip(")")]

                if len(params) == 1 and params[0] == '':
                    l = 0
                else:
                    l = len(params)

                self._methods_lookup[method_name] = {"class": class_name, "nb": l, "params": params}

    def _get_method_and_params(self, deserialized):
        try:
            m = self._methods_lookup[deserialized['method']]
        except:
            return None
        else:
            for i, param in enumerate(deserialized['params']):
                m['params'][i] += " " + str(param)

            m['method'] = deserialized['method']

            return m

    def _method_call_to_string(self, method_call):
        return method_call['class'] + "." + method_call['method'] + "(" + ", ".join(method_call['params']) + ")"

    def _pretty(self, deserialized):
        pass

    def _out(self):
        if self.output == "stdout":
            sys.stdout.write(self._to_display)
            sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            with open(self.output, "w") as f:
                f.write(self._to_display)

            if not os.name == 'nt':
                print("Output saved to \033[91m" + self.output + "\033[0m\n")
            else:
                print("Output saved to " + self.output + "\n")

    def _fuzz(self):
        fuzzstr = self._parser.get_fuzzstr()
        if not os.name == 'nt' and self.output == "stdout":
            self._to_display += "\033[4mResulting fuzzing string:\033[0m\n"
            self._to_display += re.sub("(%[a-z]+|§[^§]+§" +
                                       ((re.escape(self.surround) + "[^"+ re.escape(self.surround) +
                                         "]+" + re.escape(self.surround)) if self.surround else
                                        re.escape(self.replace) if self.replace else "") +
                                       ")", "\033[91m\\1\033[0m", fuzzstr) + "\n"
        else:
            self._to_display += "Resulting fuzzing string:\n"
            self._to_display += fuzzstr + "\n"

        if not re.search("%|§" + ("|" + (re.escape(self.surround) + "[^\|]+" +
                                         re.escape(self.surround)) if self.surround else
                                  "|" + re.escape(self.replace) if self.replace else ""), fuzzstr):
            if not os.name == 'nt' and self.output == "stdout":
                self._to_display += "\033[91mNothing to fuzz for this request\033[0m\n"
            else:
                self._to_display += "Nothing to fuzz for this request\n"

        self._to_display += "\n"

    def parse(self):
        is_file = False
        if os.path.isfile(self.user_input):
            is_file = True
            with open(self.user_input) as f:
                content = f.read()

            if content.find(b"\xEF\xBF\xBF".decode()) > -1:
                self._is_pipe_used = False

            unhex = str(bytes(content.encode()).replace(b"\xEF\xBF\xBF", b"|").decode())
        else:
            content = self.user_input

            if content.find("\xEF\xBF\xBF") > -1:
                self._is_pipe_used = False

            unhex = content.replace("\xEF\xBF\xBF", "|")

        if is_file is True:
            requests_to_parse = [a[0] for a in re.findall("\n([\d]+\|[\d]+(.*?)\|[\d]+\|)\r?\n", unhex)]
        else:
            requests_to_parse = [unhex]

        for request in requests_to_parse:
            if self._is_pipe_used is False:
                original_request = request.replace("|", "\xEF\xBF\xBF")
            else:
                original_request = request

            if not os.name == 'nt' and self.output == "stdout":
                self._to_display += "\033[4mOriginal request:\033[0m\n"
            else:
                self._to_display += "Original request:\n"
            self._to_display += original_request + "\n"

            try:
                deserialized = self._parser.deserialize(request)
            except IndexError:
                if not os.name == 'nt':
                    print("\033[4mEncountered Error During Parsing with request:\033[0m\n" + request + "\n")
                else:
                    print("Encountered Error During Parsing with request:\n" + request + "\n")
            else:
                if self.pretty is True:
                    self._pretty(deserialized)
                else:
                    if len(self._methods_lookup) > 0:
                        method_call = self._get_method_and_params(deserialized)

                        if not os.name == 'nt' and self.output == "stdout":
                            self._to_display += "\033[4mEquivalent Java method call:\033[0m\n"
                        else:
                            self._to_display += "Equivalent Java method call:\n"
                        self._to_display += self._method_call_to_string(method_call) + "\n"

                self._fuzz()

        self._out()
