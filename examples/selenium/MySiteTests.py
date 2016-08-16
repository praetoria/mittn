import unittest
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
#we have to proxy all test to burp
from selenium.webdriver.common.proxy import *
#firefox needs a display to run
from pyvirtualdisplay import Display

class MyFeature(unittest.TestCase):

    def setUp(self):
        #Create a virtual display for running firefox over a TTY.
        self.display = Display(visible=0, size=(1024, 768))
        self.display.start() 

        #configure proxy, this is the only change that would be made
        #to existing tests in order to get them to work in mittn
        proxystring = "127.0.0.1:8080"
        proxy = Proxy({
            'proxyType': ProxyType.MANUAL,
            'httpProxy': proxystring,
            'ftpProxy': proxystring,
            'sslProxy': proxystring,
            'noProxy': '' # set this value as desired
        })

        #start Firefox, just like in your regular Selenium tests
        self.driver = webdriver.Firefox(proxy = proxy)

    def fancy_feature(self):
        #this should be an actual test scenario
        self.driver.get("http://127.0.0.1:5000/true")
        assert True

    def fun_functionality(self):
        #this should be an actual test scenario
        self.driver.get("http://127.0.0.1:5000/false")
        assert True

    def tearDown(self):
        self.driver.close()
        self.display.stop()

if __name__ == "__main__":
    unittest.main()
