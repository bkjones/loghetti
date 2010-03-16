#!/usr/bin/env python
__author__ = 'Brian K. Jones (bkjones@gmail.com)'
__credits__ = ["Doug Hellmann", "Kent Johnson"]
__version__ = 0.91
__license__ = "BSD"
__maintainer__ = "Brian K. Jones"
__email__ = "bkjones@gmail.com"

# stdlib imports
import cgi
import operator
import re
import sys
import time
import urlparse
import argparse
import inspect

# non-standard library imports
import apachelogs

class Rule(object):
  """
  A simple object that assembles arguments for building a rule into a form that's easy to retrieve from later.
  It's also handy in the event that you need to pull all of the Rule objects together into one place,
  because you can filter __dict__ to pull out only "Rule" objects.

  You'll see it used in just about all of the optionHandler_* methods below. 
  """
  def __init__(self,attr,cmp,val):
    self.attr = attr
    self.getter = operator.attrgetter(attr)
    self.cmp = cmp
    self.val = val

  def __str__(self):
    return ','.join([self.attr, self.cmp, self.val])


class UrlDataRule(object):
  def __init__(self, attr, cmp, val):
    def getter(line):
      return line.urldata.get(attr, [None])[0]

    self.getter = getter
    self.attr = attr
    self.cmp = cmp
    self.val = val

  def __str__(self):
    return ','.join([self.attr, self.cmp, self.val])


class Filter(object):
  """
  Gets passed an apachelog file (as produced by the apachelogs.py module), and applies all of the rules
  to each apache log_line object. Instead of printing out matching lines, this is a generator object that
  allows the calling object to iterate over the returned lines and handle output how ever it wants
  """
  def __init__(self, file, ruleset, process_date, process_url, process_qstring):
    self.log = file
    self.rules = ruleset
    self.process_date = process_date
    self.process_url = process_url
    self.process_qstring = process_qstring
    self.baserex = re.compile("^\/.*[\?\/]") # find everything up to the first occurence of "?" or "/"


  def strainer(self):
    """
    Applies rules in ruleset to each line in the log, returning matching lines to the caller to output as it pleases. 
    """
    for line in self.log:
      if self.process_date:
        line.time = line.time.split()[0]
        line.date = time.strptime(line.time, '%d/%b/%Y:%H:%M:%S')
        line.year, line.month, line.day, line.hour, line.minute, line.second = line.date[0:6]
      if self.process_url:
        line.urlbase = urlparse.urlparse(line.url)[2]
        line.base = self.baserex.search(line.urlbase)
        if not line.base:
          line.base = line.urlbase.strip("?/")
        else:
          line.base = line.base.group(0).strip("?/") # gives us a clean first element of requested url.
      if self.process_qstring:
        line.args = urlparse.urlparse(line.url)[4]
        line.urldata = cgi.parse_qs(line.args)

      show_line = True

      for rule in self.rules:
        show_line &= (rule.val == rule.getter(line)) # returns false if the right side is false.
        if not show_line:
          break # *all* rules must match (until 'or' is implemented). If *any* check fails, immediately move on to the next line. 
      if show_line:
        yield line


class loghetti(object):
  """
  This is the meat of the application. This is an application to help troubleshoot issues and generate statistics by
  slicing and dicing the data in your apache combined format access logs.
  """
  def __init__(self):
    self.ruleset = []
    self.count = False
    self.process_date = False
    self.process_url = False
    self.process_qstring = False
    self.fields = False
    self.nolazy = False
    self.customOutput = False

  def optionHandler_nolazy(self, dest=None):
    self.nolazy = True
    self.process_date=True
    self.process_url=True
    self.process_qstring=True

  def optionHandler_code(self, respcode, dest=None):
    """
    Return all lines in file containing the user-supplied HTTP response code (500, 404, 200, etc)
    """
    coderule = Rule("http_response_code", "=", respcode)
    self.ruleset.append(coderule)
    return

  def optionHandler_count(self, val):
    """
    Don't spit out every line - just the number of matches. Good for reporting, testing without
    losing terminal history in the scrollback, or sitting in meetings and saying
    "yeah, that happened 400 times in the last half hour" :-) 
    """
    self.count = val
    return

  def optionHandler_ip(self, ip, dest=None):
    """
    Return lines in the log that match the given IP address.
    """
    self.iprule = Rule("ip", "=", ip)
    self.ruleset.append(self.iprule)
    return

  def optionHandler_month(self, month, dest=None):
    """
    Pass in a date using max 4-digits. No zero-padding, no spaces, no slashes. So if you want
    to see lines from January 31, the way to do that is to pass "131". February 3rd? Pass "23". Lame, I know.
    I'm working on it :) 
    """
    self.monthrule = Rule("month", "=", int(month))
    self.ruleset.append(self.monthrule)
    self.process_date = True
    return

  def optionHandler_day(self, day, dest=None):
    """
    Pass in a non-zero-padded day (1-31). Sorry, doesn't yet accept a range, though passing
    multiple --day arguments should work.
    """
    self.dayrule = Rule("day", "=", int(day))
    self.ruleset.append(self.dayrule)
    self.process_date = True
    return

  def optionHandler_year(self, year):
    """
    Pass in a non-zero-padded month (1-12). Sorry, doesn't yet accept a range, though passing
    multiple --year arguments should work.
    """
    self.yearrule = Rule("year", "=", int(year))
    self.ruleset.append(self.yearrule)
    self.process_date = True
    return

  def optionHandler_hour(self, hour):
    """
    Pass in a non-zero-padded hour (0-23). Sorry, doesn't yet accept a range, though passing
    multiple --hour arguments should work.
    """
    self.hourrule = Rule("hour", "=", int(hour))
    self.ruleset.append(self.hourrule)
    self.process_date = True
    return

  def optionHandler_minute(self, minute):
    """
    Pass in a non-zero-padded minute (0-59). Sorry, doesn't yet accept a range, though passing
    multiple --minute arguments should work.
    """
    self.minuterule = Rule("minute", "=", int(minute))
    self.ruleset.append(self.minuterule)
    self.process_date = True
    return

  def optionHandler_urlbase(self, urlbase):
    """
    Match log lines on a base path. So, pass 'file.php', not 'http://mydomain.com/file.php'
    Useful for matching on url's that would contain lots of random data attached. So, to find lines like:
    '/file.php?foo=bar&bar=baz&abc=def&stuff=idunno', you just ask for 'file.php' instead of that big long
    url. 
    """
    self.urlrule = Rule("base", "=", urlbase)
    self.ruleset.append(self.urlrule)
    self.process_url = True
    return

  def optionHandler_method(self, method):
    """
    Pass in an http method (probably GET or POST, but any should work) to filter on.
    """
    self.methodrule = Rule("http_method" , "=", method)
    self.ruleset.append(self.methodrule)
    return

  def optionHandler_urldata(self, keyval):
    """
    Pass in a pair like "--urldata=key:val", and it'll return log lines where &key=val in a query line like:
    /file.php?abc=def&foo=bar&key=val. Currently, only an equality match is supported. 
    """
    key, val = keyval.split(':')
    self.urldatarule = UrlDataRule(key, "=", val)
    self.ruleset.append(self.urldatarule)
    self.process_qstring = True
    return

  def optionHandler_return(self, fields):
    """A list of fields to spit out instead of the whole line. These map directly to attributes of line objects,
    so to get the response code and IP *only*, you'd say '--return=http_response_code,ip'

    Field names are passed directly to apachelogs.py, so they need to be the names used there. Here's an example:
    The following Apache log line:
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
    self.fields = fields.split(',')
    return

  def optionHandler_output(self, methodname):
    """You can write your own method (or maybe module?) to define what to do with
    lines that would otherwise be returned as-is, and pass the name of the method/module
    as an argument, i.e. '--output=MyModule'"""
    self.customOutput = True
    self.outmod = __import__(methodname)
    return

  def opt_method_map(self):
     meth_prefix = 'optionHandler_'
     mapping = {}
     for meth in inspect.getmembers(self.__class__, inspect.ismethod):
        opt = meth[0][len(meth_prefix):]
        if opt:
           mapping[opt] = meth[0]

     return mapping

  def main(self, args):
    """
    Takes a single log file as an argument (for now)
    """
    handler_map = self.opt_method_map()

    for opt,val in args.__dict__.iteritems():
       "For each option passed in, map it to an optionHandler."
       if opt and val:
          if opt in handler_map:
            opt_handler = getattr(self, handler_map[opt])
            optval = getattr(args, opt)
            opt_handler(optval)
          else:
            setattr(self, opt, val)
  
    log = apachelogs.ApacheLogFile(self.logfile)

    myfilter = Filter(log, self.ruleset, self.process_date, self.process_url, self.process_qstring)

    if self.customOutput:
      for line in myfilter.strainer():
        self.outmod.munge(line)

    else:
      count = 0
      for line in myfilter.strainer():
        if self.fields:
          flist = []
          for field in self.fields:
            flist.append(getattr(line, field))
          for item in flist:
             print item,
          print 
          continue
        if self.count:
          count +=1
        else:
          print line #line # note this line still has the apachelog attributes. You can 'print line.ip' instead if you want.

      if self.count:
        print "Matching lines: ", count


if __name__ == "__main__":
   l = loghetti()
   parser = argparse.ArgumentParser(description="An Apache combined format log file strainer.")
   parser.add_argument('--code', action='store', dest='code', help="HTTP response code (500, 404, 200, etc)")
   parser.add_argument('--count', action='store_true', dest='count', help="Return *only* total number of matching lines")
   parser.add_argument('--file', action='store', dest='logfile', help="Log file to process")
   parser.add_argument('--ip', action='store', dest='ip', help="IP of requesting device.")
   parser.add_argument('--month', action='store', dest='month', help="Filter by month. No leading zeroes, please")
   parser.add_argument('--day', action='store', dest='day', help="Filter by day of month (usu. used w/ --month). No leading zeroes, please")
   parser.add_argument('--year', action='store', dest='year', help="Filter by 4-digit year")
   parser.add_argument('--hour', action='store', dest='hour', help="Filter by hour.")
   parser.add_argument('--minute', action='store', dest='minute', help="Filter by minute (usu. used w/ --hour).")
   parser.add_argument('--return', action='store', dest='return',
                       help="""Comma-separated list of fields to return. Valid fields are:\n 
                                 ip,ident,http_user,time,request_line,http_response_code,http_response_size,referrer,user_agent,http_method,url,http_vers """)
   args = parser.parse_args()
   l.main(args)
