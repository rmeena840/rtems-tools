#
# RTEMS Tools Project (http://www.rtems.org/)
# Copyright 2017 Chris Johns (chrisj@rtems.org)
# All rights reserved.
#
# This file is part of the RTEMS Tools package in 'rtems-tools'.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

#
# Host specifics.
#

from __future__ import print_function

import os
import re

from rtemstoolkit import error
from rtemstoolkit import path

class configuration:

    def __init__(self, raw = True):
        self.raw = True
        try:
            import configparser
            self.config = configparser.ConfigParser(strict = False)
        except:
            # python2
            import ConfigParser as configparser
            self.config = configparser.ConfigParser()
        self.ini = None
        self.macro_filter = re.compile('\$\{.+\}')

    def __str__(self):
        if self.ini is None:
            return 'empty'
        s = ['Base: %s' % (self.ini['base'])]
        s += ['Files:']
        for f in self.ini['files']:
            s += [' %s' % (f)]
        s += ['Defaults:']
        for default in self.config.defaults():
            s += ' ' + default
        s += ['Sections:']
        for section in self.config.sections():
            s += [' [%s]' % (section)]
            for option in self.config.options(section):
                s += ['  %s = %s' % (option,
                                     self.config.get(section,
                                                     option,
                                                     raw = self.raw))]
        return os.linesep.join(s)

    def get_item(self, section, label, err = True):
        try:
            rec = self.config.get(section, label, raw = self.raw).replace(os.linesep, ' ')
        except:
            if err:
                raise error.general('config: no "%s" found in "%s"' % (label, section))
            return None
        #
        # On Python 2.7 there is no extended interpolation so add support here.
        # On Python 3 this should happen automatically and so the findall
        # should find nothing.
        #
        for m in self.macro_filter.findall(rec):
            if ':' not in m:
                raise error.general('config: interpolation is ${section:value}: %s' % (m))
            section_value = m[2:-1].split(':')
            if len(section_value) != 2:
                raise error.general('config: interpolation is ${section:value}: %s' % (m))
            try:
                ref = self.config.get(section_value[0],
                                      section_value[1],
                                      raw = self.raw).replace(os.linesep, ' ')
                rec = rec.replace(m, ref)
            except:
                pass
        return rec

    def get_items(self, section, err = True, flatten = True):
        try:
            items = []
            for name, key in self.config.items(section, raw = self.raw):
                if flatten:
                    items += [(name, key.replace(os.linesep, ' '))]
                else:
                    items += [(name, key)]
            return items
        except:
            if err:
                raise error.general('config: section "%s" not found' % (section))
        return []

    def comma_list(self, section, label, err = True):
        items = self.get_item(section, label, err)
        if items is None:
            return []
        return sorted(set([a.strip() for a in items.split(',')]))

    def get_item_names(self, section, err = True):
        try:
            return [item[0] for item in self.config.items(section, raw = self.raw)]
        except:
            if err:
                raise error.general('config: section "%s" not found' % (section))
        return []

    def has_section(self, section):
        return self.config.has_section(section)

    def load(self, name):
        #
        # Load all the files.
        #
        self.ini = { 'base'     : path.dirname(name),
                     'files'    : [] }
        includes = [name]
        still_loading = True
        while still_loading:
            still_loading = False
            for include in includes:
                if not path.exists(include):
                    rebased_inc = path.join(self.ini['base'],
                                            path.basename(include))
                    if not path.exists(rebased_inc):
                        e = 'config: cannot find configuration: %s' % (include)
                        raise error.general(e)
                    include = rebased_inc
                if include not in self.ini['files']:
                    try:
                        self.config.read(include)
                    except configparser.ParsingError as ce:
                        raise error.general('config: %s' % (ce))
                    still_loading = True
                    self.ini['files'] += [include]
            includes = []
            if still_loading:
                for section in self.config.sections():
                    includes += self.comma_list(section, 'include', err = False)

    def files(self):
        return self.ini['files']
