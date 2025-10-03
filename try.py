import os

users = []
dictusers = {}
i = 0

class Query:
    def __init__(self, query, id, textFull):
        self.query = query
        self.id = id
        self.textFull = textFull
        self.text = b""
        self.timeFull = b""
        self.timeQueue = b""
        self.timeWork = b""

    def setTime(self, timeFull, timeQueue, timeWork):
        self.timeFull = timeFull
        self.timeQueue = timeQueue
        self.timeWork = timeWork
    
    def setText(self, text):
        self.text = text

    def printQuery(self, filename):
        output = b""
        output += b"-----QUERY-----\n"
        output += b"Query:      " + self.query + b"\n"
        output += b"Qid:        " + self.id + b"\n"
        output += b"Text full:  " + self.textFull + b"\n"
        output += b"Text:       " + self.text + b"\n"
        output += b"Time full:  " + self.timeFull + b"\n"
        output += b"Time queue: " + self.timeQueue + b"\n"
        output += b"Time work:  " + self.timeWork + b"\n"
        output += b"-----query-----\n"
        return output

class User:
    def __init__(self, log):
        self.connection = log[1][5:-1:]
        self.ip = log[3]
        self.queries = []
        self.worker = b""
        self.queryId = b""
        self.id = b""
        self.textFull = b""
        self.queryText = b""
        self.timeFull = b""
        self.timeQueue = b""
        self.timeWork = b""

    def setQueryId(self, queryId):
        self.queryId = queryId
    
    def setQueryText(self, text):
        self.queryText = b"\x20".join(text)

    def setQuery(self, id, textFull):
        self.id = id
        self.textFull = textFull

    def setWorker(self, worker):
        self.worker = worker

    def setTime(self, timeFull, timeQueue, timeWork):
        self.timeFull = timeFull
        self.timeQueue = timeQueue
        self.timeWork = timeWork

    def getConnection(self):
        return self.connection

    def getQueryId(self):
        return self.queryId

    def printUser(self, filename):
        with open(filename, 'ab') as f:
            f.write(b"-----USER------\n")
            f.write(b"Connection: " + self.connection + b"\n")
            f.write(b"IP:         " + self.ip + b"\n")
            f.write(b"Worker:     " + self.worker + b"\n")
            f.write(b"-----QUERY-----\n")
            f.write(b"Id:         " + self.id + b"\n")
            f.write(b"Text full:  " + self.textFull + b"\n")
            f.write(b"Text:       " + self.queryText + b"\n")
            f.write(b"-----TIME------\n")
            f.write(b"Time full:  " + self.timeFull + b"\n")
            f.write(b"Time queue: " + self.timeQueue + b"\n")
            f.write(b"Time work:  " + self.timeWork + b"\n")
            f.write(b"-----user------\n")
            f.write(b"\n\n")

def byteTextToHex(byteText):
    return hex(int(byteText.decode(), 16))

def proccessLog(logLine):
    logData = logLine.split(b' ')[9::]
    global i

    try:
        if (logData[0] == b'Incoming'):
            dictusers[hex(int(logData[1][5:-1:].decode(), 16))[2::]] = User(logData)
            
        if (logData[0] == b'On'):
            dictusers[byteTextToHex(logData[1][5:-1:])[2::]].setQueryId(logData[3][6:-1:])
            queryText = logData[5::]
            if queryText[-1][-1] == 10:
                queryText[-1] = queryText[-1][:-1:]
            dictusers[byteTextToHex(logData[1][5:-1:])[2::]].setQueryText(queryText)
        
        if (logData[0][:5:] == b'Query'):
            queryIdNew = logData[0][6:-1:].decode()
            queryIdFirst = dictusers[list(dictusers.keys())[0]].getQueryId().decode()
            queryIdDiff = int(queryIdNew, 16) - int(queryIdFirst, 16)
            connectionFirst = int(list(dictusers.keys())[0], 16)
            connectionNew = str(hex(connectionFirst + queryIdDiff))[2::]
            queryId = logData[0][6:-1:]
            id = logData[1][1:-1:]
            text = logData[4][2:(logData[4].find(b'&_')):]
            dictusers[connectionNew].setQuery(id, text)
        
        if (logData[0] == b'Sending'):
            queryIdNew = logData[1][6:-1:].decode()
            queryIdFirst = dictusers[list(dictusers.keys())[0]].getQueryId().decode()
            queryIdDiff = int(queryIdNew, 16) - int(queryIdFirst, 16)
            connectionFirst = int(list(dictusers.keys())[0], 16)
            connectionNew = str(hex(connectionFirst + queryIdDiff))[2::]
            dictusers[connectionNew].setWorker(logData[4][7:-2:])
        
        if (logData[0] == b'End'):
            queryIdNew = logData[1][6:-1:].decode()
            queryIdFirst = dictusers[list(dictusers.keys())[0]].getQueryId().decode()
            queryIdDiff = int(queryIdNew, 16) - int(queryIdFirst, 16)
            connectionFirst = int(list(dictusers.keys())[0], 16)
            connectionNew = str(hex(connectionFirst + queryIdDiff))[2::]
            timeFull = logData[6]
            timeQueue = logData[8]
            timeWork = logData[10]
            dictusers[connectionNew].setTime(timeFull, timeQueue, timeWork)
                    

    except Exception as e:
        pass
        with open('errors.txt', 'ab') as f:
            f.write(b"-----ERROR-----\n")
            f.write(b"Log line:     " + logLine + b"\n")
            f.write(b"Unexpect err: " + str(e).encode() + b"\n")
            f.write(b"i:            " + str(i).encode() + b"\n")
            f.write(b"-----error-----\n")
            f.write(b"\n\n\n\n")
    i += 1
    
        

def readLogs():
    with open('spcd.log copy.11', 'rb') as file:
        for line in file:
            proccessLog(line)

def resizeDict():
    firstConn = None
    lastConn = None

    with open('spcd.log copy.11', 'rb') as file:
        for line in file:
            if line.find(b'Incoming') != -1:
                logData = line.split(b' ')[9::]
                if firstConn == None:
                    firstConn = logData[1][5:-1:]
                    lastConn = firstConn
                else:
                    lastConn = logData[1][5:-1:]

    keys = []
    for i in range(int(byteTextToHex(firstConn), 16), int(byteTextToHex(lastConn), 16) + 1):
        keys.append(hex(i)[2::])

    dictusers = dict.fromkeys(keys, 0)

    # print(dictusers)



def main():
    # os.remove('errors.txt') if os.path.exists('errors.txt') else None
    os.remove('users.txt') if os.path.exists('users.txt') else None
    resizeDict()
    readLogs()
    for user in dictusers:
        dictusers[user].printUser('users.txt')
    for user in users:
        user.printUser('users.txt')

if __name__ == "__main__":
    main()