# coding=utf-8


class GWTReqParser(object):
    def __init__(self, user_input, output, burp, pretty, replace, surround, verbose, debug):
        self.user_input = user_input
        self.output = output
        self.burp = burp
        self.pretty = pretty
        self.replace = replace
        self.surround = surround
        self.verbose = verbose
        self.debug = debug
