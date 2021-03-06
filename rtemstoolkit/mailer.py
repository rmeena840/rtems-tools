#
# RTEMS Tools Project (http://www.rtems.org/)
# Copyright 2013-2016 Chris Johns (chrisj@rtems.org)
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
# Manage emailing results or reports.
#

from __future__ import print_function

import os
import smtplib
import socket

from rtemstoolkit import error
from rtemstoolkit import options
from rtemstoolkit import path

_options = {
    '--mail'     : 'Send email report or results.',
    '--smtp-host': 'SMTP host to send via.',
    '--mail-to'  : 'Email address to send the email too.',
    '--mail-from': 'Email address the report is from.'
}

def append_options(opts):
    for o in _options:
        opts[o] = _options[o]

def add_arguments(argsp):
    argsp.add_argument('--mail', help = _options['--mail'], action = 'store_true')
    for o in ['--smtp-host', '--mail-to', '--mail-from']:
        argsp.add_argument(o, help = _options[o], type = str)

class mail:
    def __init__(self, opts):
        self.opts = opts

    def _args_are_macros(self):
        return isinstance(self.opts, options.command_line)

    def _get_arg(self, arg):
        if self._args_are_macros():
            value = self.opts.find_arg(arg)
            if value is not None:
                value = self.opts.find_arg(arg)[1]
        else:
            if arg.startswith('--'):
                arg = arg[2:]
            arg = arg.replace('-', '_')
            if arg in vars(self.opts):
                value = vars(self.opts)[arg]
            else:
                value = None
        return value

    def from_address(self):

        def _clean(l):
            if '#' in l:
                l = l[:l.index('#')]
            if '\r' in l:
                l = l[:l.index('r')]
            if '\n' in l:
                l = l[:l.index('\n')]
            return l.strip()

        addr = self._get_arg('--mail-from')
        if addr is not None:
            return addr
        mailrc = None
        if 'MAILRC' in os.environ:
            mailrc = os.environ['MAILRC']
        if mailrc is None and 'HOME' in os.environ:
            mailrc = path.join(os.environ['HOME'], '.mailrc')
        if mailrc is not None and path.exists(mailrc):
            # set from="Joe Blow <joe@blow.org>"
            try:
                with open(mailrc, 'r') as mrc:
                    lines = mrc.readlines()
            except IOError as err:
                raise error.general('error reading: %s' % (mailrc))
            for l in lines:
                l = _clean(l)
                if 'from' in l:
                    fa = l[l.index('from') + len('from'):]
                    if '=' in fa:
                        addr = fa[fa.index('=') + 1:].replace('"', ' ').strip()
            if addr is not None:
                return addr
        if self._args_are_macros():
            addr = self.opts.defaults.get_value('%{_sbgit_mail}')
        else:
            raise error.general('no valid from address for mail')
        return addr

    def smtp_host(self):
        host = self._get_arg('--smtp-host')
        if host is not None:
            return host[1]
        if self._args_are_macros():
            host = self.opts.defaults.get_value('%{_mail_smtp_host}')
        if host is not None:
            return host
        return 'localhost'

    def send(self, to_addr, subject, body):
        from_addr = self.from_address()
        msg = "From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % \
            (from_addr, to_addr, subject) + body
        try:
            s = smtplib.SMTP(self.smtp_host())
            s.sendmail(from_addr, [to_addr], msg)
        except smtplib.SMTPException as se:
            raise error.general('sending mail: %s' % (str(se)))
        except socket.error as se:
            raise error.general('sending mail: %s' % (str(se)))

    def send_file_as_body(self, to_addr, subject, name, intro = None):
        try:
            with open(name, 'r') as f:
                body = f.readlines()
        except IOError as err:
            raise error.general('error reading mail body: %s' % (name))
        if intro is not None:
            body = intro + body
        self.send(to_addr, from_addr, body)

if __name__ == '__main__':
    import sys
    from rtemstoolkit import macros
    optargs = {}
    rtdir = 'rtemstoolkit'
    defaults = '%s/defaults.mc' % (rtdir)
    append_options(optargs)
    opts = options.command_line(base_path = '.',
                                argv = sys.argv,
                                optargs = optargs,
                                defaults = macros.macros(name = defaults, rtdir = rtdir),
                                command_path = '.')
    options.load(opts)
    m = mail(opts)
    print('From: %s' % (m.from_address()))
    print('SMTP Host: %s' % (m.smtp_host()))
    if '--mail' in sys.argv:
        m.send(m.from_address(), 'Test mailer.py', 'This is a test')
