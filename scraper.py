import socket, ssl

# REMOVE AND CHANGE WITH THE DATA WE GET FROM PUNKTUM.DK
# may need to parse and dig through data to get domain
webpages = ['www.google.com', 'www.aau.dk', 'www.facebook.com', 'www.discord.com']

# initiate ssl context. default ssl stuff (see https://docs.python.org/3/library/ssl.html )
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
context.load_default_certs()

# CHANGE LOOP VARIABLE TO DOMAINS FROM PUNKTUM.DK DATA 
for i in range(len(webpages)):
    # create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(webpages[i])

    # wrap socket in ssl context and connect
    ssl_sock = context.wrap_socket(s, server_hostname=webpages[i])
    ssl_sock.connect((webpages[i], 443))

    # get an print tls cert. CHANGE TO ENRICH DATA INSTEAD OF PRINTING IT
    print(ssl_sock.getpeercert())

    # close socket to not get errors lol
    ssl_sock.close()
