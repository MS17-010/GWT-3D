# coding=utf-8


import re
import sys
import os.path
import gwt3d.GWTRequestParser


class GWTReq(object):
    def __init__(self, user_input, output, fuzz, pretty, burp, replace, surround, methods, verbose, debug):
        self.user_input = user_input
        self.output = output
        self.fuzz = fuzz
        self.pretty = pretty
        self.burp = burp
        self.replace = replace
        self.surround = surround
        self.verbose = verbose
        self.debug = debug

        self._parser = gwt3d.GWTRequestParser.GWTReqParser(burp, replace, surround, verbose, debug)
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

        fuzzable = True
        if not re.search("%|§" + ("|" + (re.escape(self.surround) + "[^\|]+" +
                                         re.escape(self.surround)) if self.surround else
                                  "|" + re.escape(self.replace) if self.replace else ""), fuzzstr):
            fuzzable = False

        if not os.name == 'nt' and self.output == "stdout":
            if self.fuzz is not True:
                self._to_display += "\033[4mResulting fuzzing string:\033[0m\n"

            if (self.fuzz is True and fuzzable is True) or self.fuzz is not True:
                self._to_display += re.sub("(%[a-z]+|§[^§]+§" +
                                           ((re.escape(self.surround) + "[^"+ re.escape(self.surround) +
                                             "]+" + re.escape(self.surround)) if self.surround else
                                            re.escape(self.replace) if self.replace else "") +
                                           ")", "\033[91m\\1\033[0m", fuzzstr) + "\n"
        else:
            if self.fuzz is not True:
                self._to_display += "Resulting fuzzing string:\n"

            if (self.fuzz is True and fuzzable is True) or self.fuzz is not True:
                self._to_display += fuzzstr + "\n"

        if self.fuzz is not True and fuzzable is False:
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

            try:
                if content.find(b"\xEF\xBF\xBF".decode()) > -1:
                    self._is_pipe_used = False
            except UnicodeDecodeError:
                if content.find(b"\xEF\xBF\xBF") > -1:
                    self._is_pipe_used = False

            try:
                unhex = str(bytes(content.encode()).replace(b"\xEF\xBF\xBF", b"|").decode())
            except UnicodeDecodeError:
                unhex = content.replace(b"\xEF\xBF\xBF", "|")
        else:
            content = self.user_input

            if content.find("ï¿¿") > -1:
                self._is_pipe_used = False

            unhex = content.replace("ï¿¿", "|")

        if is_file is True:
            requests_to_parse = [a[0] for a in re.findall("\n([\d]+\|[\d]+(.*?)\|[\d]+\|)\r?\n", unhex)]
        else:
            requests_to_parse = [unhex]

        for request in requests_to_parse:
            if self._is_pipe_used is False:
                original_request = request.replace("|", "ï¿¿")
            else:
                original_request = request

            if self.fuzz is not True:
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
                    if self.fuzz is not True:
                        if len(self._methods_lookup) > 0:
                            method_call = self._get_method_and_params(deserialized)

                            if not os.name == 'nt' and self.output == "stdout":
                                self._to_display += "\033[4mEquivalent Java method call:\033[0m\n"
                            else:
                                self._to_display += "Equivalent Java method call:\n"
                            self._to_display += self._method_call_to_string(method_call) + "\n"

                self._fuzz()

        self._out()
