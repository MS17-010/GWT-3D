# coding=utf-8


class Param(object):
    def __init__(self, tn):
        self.typename = tn
        self.values = list()
        self.flag = False
        self.is_custom_obj = False
        self.is_list = False
        self.is_array = False

    def _add_value(self, val):
        self.values.append(val)

    def _set_flag(self, flag_value):
        self.flag = flag_value

    def __repr__(self):
        return "<Parameter %r>" % self.__dict__
