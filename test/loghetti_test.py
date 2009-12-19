''' Very basic unit test for loghetti '''

import unittest

from loghetti import loghetti
import __main__

class loghetti_test(unittest.TestCase):
    def test_loghetti(self):
      self.checkFinds('--code=200')
      self.checkMisses('--code=404')

      self.checkFinds('--ip=127.0.0.1')
      self.checkMisses('--ip=192.168.0.1')

      self.checkFinds('--month=10')
      self.checkMisses('--month=11')

      self.checkFinds('--day=5')
      self.checkMisses('--day=6')

      self.checkFinds('--year=2000')
      self.checkMisses('--year=2001')

      self.checkFinds('--hour=13')
      self.checkMisses('--hour=14')

      self.checkFinds('--minute=55')
      self.checkMisses('--minute=56')

      self.checkFinds('--urlbase=apache_pb.gif')
      self.checkMisses('--urlbase=foo')

      self.checkFinds('--method=GET')
      self.checkMisses('--method=POST')

      self.checkFinds('--urldata=foo:bar')
      self.checkFinds('--urldata=baz:zip')
      self.checkMisses('--urldata=foo:zip')
      self.checkMisses('--urldata=bing:zip')


    def checkFinds(self, args):
        run(args)
        self.assertEquals(1, count)
        
    def checkMisses(self, args):
        run(args)
        self.assertEquals(0, count)
        
        
    def setUp(self):
        pass


def run(args):
    global count
    count = 0
    args = args + ' --count test.log'
    args = args.split()
    l = loghetti(args)
    l.force_exit = False
    l.customOutput = True
    l.outmod = __main__
    l.run()


count = 0
def munge(line):
    global count
    count += 1
    
if __name__ == '__main__':
	unittest.main()