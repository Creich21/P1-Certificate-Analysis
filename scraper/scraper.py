import socket, ssl, requests
from fake_headers import Headers

# REMOVE AND CHANGE WITH THE DATA WE GET FROM PUNKTUM.DK
# may need to parse and dig through data to get domain
webpages = ['http://google.com', 'http://www.aau.dk', 'https://www.facebook.com', 'https://www.discord.com']

class Scraper(): 
    '''
    webpages = array or something in that order. change when data known
    headers = 
    '''
    def __init__(self, webpages=None):
        if webpages == None:
            raise Exception("webpages not loaded")
        
        self.webpages = webpages
        # generate fake headers for request
        self.header_props = Headers(
            browser="chrome",
            os="win",
            headers=True
        ).generate()

    def scrape(self):
        # CHANGE LOOP VARIABLE TO DOMAINS FROM PUNKTUM.DK DATA 
        for i in range(len(self.webpages)):

            print(webpages[i])

            # fetch the webpage, 
            response = requests.get(webpages[i],self.header_props)
            if response.status_code == 200:
                # CHANGE TO STORE SOMEWHERE INSTEAD OF PRINTING
                print(response.headers)
            else:
                print("website", webpages[i], "returned error", requests.status_code)


# debugging
if __name__ == "__main__":
    scraper = Scraper(webpages=webpages)
    scraper.scrape()
