"""apachelogs.py: code for reading and parsing Apache log files.
Based heavily on apachelogs.py, authored by Kevin Scott (kevin.scott@gmail.com)

Sample use -- counting the number of 40xs seen:

  import apachelogs

  alf = ApacheLogFile('access.log')
  40x_count = 0
  for log_line in alf:
    if log_line.http_response_code.startswith('40'):
      40x_count += 1
  alf.close()
  print "Saw %d 40x responses" % 40x_count
"""


import re
import time
import urlparse
import cgi
import datetime
import os
import mmap
import fileinput

class ApacheLogLine:
  """A Python class whose attributes are the fields of Apache log line.

  Designed specifically with combined format access logs in mind.  For
  example, the log line

  127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"

  would have the following field values as an ApacheLogLine:

  ip = '127.0.0.1'
  ident = '-'
  http_user = 'frank'
  time = '10/Oct/2000:13:55:36 -0700'
  request_line = 'GET /apache_pb.gif HTTP/1.0'
  http_response_code = '200'
  http_response_size = 2326
  referrer = 'http://www.example.com/start.html'
  user_agent = 'Mozilla/4.08 [en] (Win98; I ;Nav)'
  http_method = 'GET'
  url = '/apache_pb.gif'
  http_vers = 'HTTP/1.0'
  """
  def __init__(self, *rgroups ):
    self.ip, self.ident, \
    self.http_user, self.time, \
    self.request_line, self.http_response_code, \
    self.http_response_size, self.referrer, self.user_agent = rgroups
    self.http_method, self.url, self.http_vers = self.request_line.split()
    
  def __str__(self):
    """Return a simple string representation of an ApacheLogLine."""
    return ' '.join([self.ip, self.ident, self.time, self.request_line,
        self.http_response_code, self.http_response_size, self.referrer,
        self.user_agent])


_lineRegex = re.compile(r'(\d+\.\d+\.\d+\.\d+) ([^ ]*) ([^ ]*) \[([^\]]*)\] "([^"]*)" (\d+) ([^ ]*) "([^"]*)" "([^"]*)"')

class ApacheLogFile:
  """An abstraction for reading and parsing Apache log files."""
  def __init__(self, *filename):
    """Instantiating an ApacheLogFile opens a log file.  
    Client is responsible for closing the opened log file by calling close()"""
    self.f = fileinput.input(filename)

  def close(self):
    """Closes the Apache log file."""
    self.f.close()

  def __iter__(self):
    """Returns a log line object for each iteration. """
    match = _lineRegex.match
    for line in self.f:
      m = match(line)
      if m:
        try:
          log_line = ApacheLogLine(*m.groups())
          yield log_line
        except GeneratorExit:
           pass
        except Exception as e:
          print "NON_COMPLIANT_FORMAT: ", line
          
        
