from parser import Parser
from scraper import Scraper

'''
    TODO:
    create parser init and parse method so it can account for files
    parse the domains from the file into a python-friendly format (e.g. array)
    flesh out looping in scraper, save to something
    could be in dictionary to allow easy saving
'''


# UPDATE ARGUMENTS WHEN WE HAVE FILE
parser = Parser(None)
webpages_list = parser.parse()

scraper = Scraper(None)
scraper.scrape()
