# coding=utf-8


import re
import os
import sys
import base64
import getpass
try:
    import urllib2 as urllib
except:
    import urllib.request as urllib


class GWTEnum(object):
    def __init__(self, url, output, proxy, basic_auth, cookies, verbose, debug):
        self.url = url
        self.output = output
        self.proxy = proxy
        self.basic_auth = basic_auth
        self.cookies = cookies
        self.verbose = verbose
        self.debug = debug

        self.docroot = '/'.join(url.split('/')[:-1]) + '/'
        self.basic_auth_encoded = None

        self.methods = list()
        self.content = ""
        self.html_file = ""
        self.html_lines = list()
        self.rpc_js_function = iter([""])

    def _get_global_value(self, var_name):
        if self.debug:
            print("var_name", var_name)

        for html_line in self.html_lines:
            if self.debug:
                print("html_line", html_line)

            match = re.match(".*," + re.escape(var_name) +
                             "\=\'([A-Za-z0-9_\$\.\!\@\#%\^\&\*\(\)\-\+\=\:\;\"\|\\\\/\?\>\,\<\~\`]+)\',", html_line)

            if match is not None:
                if self.debug:
                    print("match", match.groups())

                return match.group(1)
        return None

    def _request_file(self, url):
        req = urllib.Request(url)
        handlers = [urllib.HTTPHandler()]

        if self.url.startswith("https://"):
            try:
                import ssl
            except:
                print("SSL support for Python is need for https URL")
                exit()

            handlers.append(urllib.HTTPSHandler())

        if self.proxy is not None:
            handlers.append(urllib.ProxyHandler({
                'http': self.proxy,
                'https': self.proxy
            }))

        opener = urllib.build_opener(*handlers)
        urllib.install_opener(opener)

        if self.basic_auth is True and self.basic_auth_encoded is None:
            try:
                username = input("Basic auth username: ")
            except:
                username = raw_input("Basic auth username: ")

            password = getpass.getpass("Basic auth password: ")
            self.basic_auth_encoded = base64.encode('%s:%s' % (username, password)).strip()
            req.add_header("Authorization", "Basic %s" % self.basic_auth_encoded)

        if self.cookies is not None:
            req.add_header("Cookies", self.cookies)

        return urllib.urlopen(req)

    def _find_html_files(self):
        self.html_files = re.findall("([A-Z0-9]{30,35})", self.content)

        if self.debug:
            print("html_files", self.html_files)

        if self.html_files is None:
            print("No cached HTML files found")
            exit()

    def _get_param_number(self, payload, function):
        number_of_params = 0
        param_match = re.search(
            "^" + re.escape(payload) + "\([A-Za-z0-9_\$]+\.[A-Za-z0-9_\$]+,([A-Za-z0-9_\$]+)\)",
            function,
            re.I
        )

        if param_match is None:
            function = next(self.rpc_js_function)

            param_match = re.search(
                "^" + re.escape(payload) + "\([A-Za-z0-9_\$]+\.[A-Za-z0-9_\$]+,([A-Za-z0-9_\$]+)\)",
                function,
                re.I
            )

        if param_match is not None:
            number_of_params = int(self._get_global_value(param_match.group(1)))

        return number_of_params

    def _set_param_definition(self, num_of_params, payload):
        if self.debug:
            print("num", num_of_params)

        for j in range(0, num_of_params):
            function = next(self.rpc_js_function)

            param_var_match = re.match(
                "^" + re.escape(payload) + "\([A-Za-z0-9_\$]+\.[A-Za-z0-9_\$]+,[A-Za-z0-9_\$]+\+"
                "[A-Za-z0-9_\$]+\([A-Za-z0-9_\$]+,([A-Za-z0-9_\$]+)\)\)$",
                function
            )

            if self.debug:
                print("param_var_match", "None" if param_var_match is None else param_var_match.groups())

            if param_var_match is not None:
                param = self._get_global_value(param_var_match.group(1))

                if param is not None:
                    self.methods[-1] += param + ", "
                else:
                    self.methods[-1] += "undefined, "

    def enum(self):
        print("This can take a very long time (like 3-4mn)")
        self.content = self._request_file(self.url).read().decode()
        self._find_html_files()

        for html_file in self.html_files:
            self.html_file = html_file
            cache_html = "%s%s.cache.html" % (self.docroot, html_file)

            if self.verbose is True:
                print("Analyzing %s.cache.html" % self.html_file)

            self.html_lines = self._request_file(cache_html).read().decode().splitlines()
            for line in self.html_lines:
                rpc_method_match = re.match("^function \w+\(.*method:([A-Za-z0-9_\$]+),.*$", line, re.I)

                if rpc_method_match is not None:
                    if rpc_method_match.group(1) == "a":
                        continue

                    if self.debug:
                        print("rpc_method_match", rpc_method_match.groups())

                    self.rpc_js_function = iter(rpc_method_match.group(0).split(";"))
                    method_name = self._get_global_value(rpc_method_match.group(1))

                    if self.debug:
                        print("rpc_js_function", self.rpc_js_function)
                        print("method_name", method_name)

                    if method_name is None:
                        continue

                    self.methods.append("%s(" % method_name.replace('_Proxy.', '.'))

                    if self.debug:
                        print("methods", self.methods[-1])

                    if re.search("try{.*", rpc_method_match.group(0)):
                        for js_function in self.rpc_js_function:
                            try_match = re.match("^try{.*$", js_function)

                            if try_match is not None:
                                js_function = next(self.rpc_js_function)
                                payload_function = ""
                                func_match = re.match("^([A-Za-z0-9_\$]+)\(.*", js_function)

                                if func_match is not None:
                                    payload_function = func_match.group(1)

                                number_of_param = self._get_param_number(payload_function, js_function)
                                self._set_param_definition(number_of_param, payload_function)
                                self.methods[-1] = self.methods[-1][:-2] + ")"

                                break
                    else:
                        func_match = re.search(
                            "([a-z])=.*?\([A-Za-z0-9_\$]+\);(.*?)\(\\1\.[A-Za-z0-9_\$]+," +
                            "[A-Za-z0-9_\$]+\+[A-Za-z0-9_\$]+\([A-Za-z0-9_\$]+,[A-Za-z0-9_\$]+\)\)",
                            line
                        )

                        if func_match is not None:
                            payload_function = func_match.group(2)
                            for js_function in self.rpc_js_function:
                                func_match = re.search(
                                    "^" + re.escape(payload_function) +
                                    "\([A-Za-z0-9_\$]+\.[A-Za-z0-9_\$]+,[A-Za-z0-9_\$]+\+" +
                                    "[A-Za-z0-9_\$]+\([A-Za-z0-9_\$]+,[A-Za-z0-9_\$]+\)\)$",
                                    js_function
                                )

                                if func_match is not None:
                                    next(self.rpc_js_function)
                                    js_function = next(self.rpc_js_function)

                                    number_of_param = self._get_param_number(payload_function, js_function)
                                    self._set_param_definition(number_of_param, payload_function)


                                    if number_of_param > 0:
                                        a_method = self.methods[-1][:-2]
                                    else:
                                        a_method = self.methods[-1]

                                    self.methods[-1] = a_method + ")"

                                    break
                        else:
                            self.methods[-1] += ")"

    def display(self):
        methods = sorted(list(set(self.methods)))

        out = ""
        for method in methods:
            out += method + "\n"

        if self.output == "stdout":
            sys.stdout.write(out)
            sys.stdout.flush()
        else:
            with open(self.output, "wb") as f:
                f.write(out)

            if not os.name == 'nt':
                print("Output saved to \033[91m" + self.output + "\033[0m\n")
            else:
                print("Output saved to " + self.output + "\n")
