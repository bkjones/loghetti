''' Simple test for apachelogs '''

import unittest

from apachelogs import ApacheLogFile

class apachelogs_test(unittest.TestCase):
    def test_foo(self):
        log = ApacheLogFile('test.log')
        line = iter(log).next()

        self.assertEquals(line.ip,  '127.0.0.1')
        self.assertEquals(line.ident,  '-')
        self.assertEquals(line.http_user,  'frank')
        self.assertEquals(line.time,  '5/Oct/2000:13:55:36 -0700')
        self.assertEquals(line.request_line,  'GET /apache_pb.gif?foo=bar&baz=zip HTTP/1.0')
        self.assertEquals(line.http_response_code,  '200')
        self.assertEquals(line.http_response_size,  '2326')
        self.assertEquals(line.referrer,  'http://www.example.com/start.html')
        self.assertEquals(line.user_agent,  'Mozilla/4.08 [en] (Win98; I ;Nav)')
        log.close()
        
    def setUp(self):
        pass

    
if __name__ == '__main__':
    unittest.main()
