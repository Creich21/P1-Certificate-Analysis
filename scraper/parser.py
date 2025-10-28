
# TODO: create parse method. 
class Parser():
    '''
    file = dataset file
    '''
    def __init__(self, file=None):
        if file == None:
            raise Exception("no file loaded")
        self.file = file

    def parse(self):
        # add code to parse file to something python-friendly
        return self.file



# debugging
if __name__ == "__main__":
    parser = Parser(None)
    parser.parse()
    
