"""This is just a dead simple example of a custom output module you could
use to load your log lines into a database. Try using this by passing '--nolazy --output=logsql' to loghetti
if you don't pass --nolazy, then there's a chance that not all attributes of 'line' will be defined. """

COLUMNS = ('id', 'ip', 'ident', 'user', 'month', 'day',
             'year', 'hour', 'method', 'url', 'http_version',
             'referrer', 'user_agent',
             # 'foo', 'bar',
             )
COLUMNS_REPR = repr(COLUMNS)

def munge(line):
  try:
    vals = (' ', line.ip, line.ident, line.http_user, 
                line.month, line.day, line.year, line.hour,
                line.http_method, line.url, line.http_vers, line.referrer, 
                line.user_agent, 
                #line.urldata['foo'][0], line.urldata['bar'][0],
                )
  except KeyError: 
    pass
  else:
    print ' '.join(["INSERT INTO sometable",
                   COLUMNS_REPR,
                   "VALUES",
                   repr(vals),
                   ';',
                   ])
