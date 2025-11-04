import requests
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
        header_list = []
        # CHANGE LOOP VARIABLE TO DOMAINS FROM PUNKTUM.DK DATA 
        for i in range(len(self.webpages)):
            # fetch the webpage, 
            response = requests.get(webpages[i],self.header_props)
            if response.status_code == 200:
                #print(response.headers)
                # TODO:
                # figure out why every entry starts with _store
                header_list.append(response.headers.__dict__)
            else:
                # add some error thingy if website is down. dunno what yet
                header_list.append("")
                print("website", webpages[i], "returned error", requests.status_code)

        return header_list


# debugging
if __name__ == "__main__":
    scraper = Scraper(webpages=webpages)
    h_list = scraper.scrape()
    print(h_list)
    #f = open("test.json", "w")
    #json.dump(h_list, f, indent=4)
    
