import socket, ssl

# REMOVE AND CHANGE WITH THE DATA WE GET FROM PUNKTUM.DK
# may need to parse and dig through data to get domain
webpages = ['www.google.com', 'www.aau.dk', 'www.facebook.com', 'www.discord.com']

class Scraper(): 
    '''
    webpages = array or something in that order. change when data known
    '''
    def __init__(self, webpages=None):
        if webpages == None:
            raise Exception("webpages not loaded")
        self.webpages = webpages
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.check_hostname = True
        self.context.load_default_certs()

    def scrape(self):
        # CHANGE LOOP VARIABLE TO DOMAINS FROM PUNKTUM.DK DATA 
        for i in range(len(self.webpages)):
            # create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            print(webpages[i])

            # wrap socket in ssl context and connect
            ssl_sock = self.context.wrap_socket(s, server_hostname=webpages[i])
            ssl_sock.connect((webpages[i], 443))

            # get an print tls cert. CHANGE TO ENRICH DATA INSTEAD OF PRINTING IT
            print(ssl_sock.getpeercert())

            # close socket to not get errors lol
            ssl_sock.close()


# debugging
if __name__ == "__main__":
    scraper = Scraper(webpages=webpages)
    scraper.scrape()
