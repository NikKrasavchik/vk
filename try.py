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
        self.queryText = b""

    def setQueryId(self, queryId):
        self.queryId = queryId
    
    def setQueryText(self, text):
        self.queryText = text

    def setQuery(self, query):
        self.queries.append(query)

    def setWorker(self, worker):
        self.worker = worker

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
            for query in self.queries:
                f.write(query.printQuery(filename))
            f.write(b"-----user------\n")
            f.write(b"\n\n")



def proccessLog(logLine):
    logData = logLine.split(b' ')[9::]
    global i

    try:

        if (logData[0] == b'Incoming'):
            users.append(User(logData))
            
        if (logData[0] == b'On'):
            for user in users:
                if user.getConnection() == logData[1][5:-1:]:
                    user.setQueryId(logData[3][6:-1:])
                    user.setQueryText(logData[5::])
                    break
        
        if (logData[0][:5:] == b'Query'):
            for user in users:
                if user.getQueryId() == logData[0][6:-1:]:
                    queryId = logData[0][6:-1:]
                    id = logData[1][1:-1:]
                    text = logData[4][2:(logData[4].find(b'&_')):]
                    query = Query(queryId, id, text)
                    queryText = b"\x20".join(user.queryText)
                    query.setText(queryText[:-1:])
                    user.setQuery(query)
                    break
        
        if (logData[0] == b'Sending'):
            for user in users:
                userrr = user
                if user.getQueryId() == logData[1][6:-1:]:
                    user.setWorker(logData[4][7:-2:])
                    break
        
        if (logData[0] == b'End'):
            for user in users:
                for query in user.queries:
                    if query.id == logData[2][1:-2:]:
                        timeFull = logData[6]
                        timeQueue = logData[8]
                        timeWork = logData[10]
                        query.setTime(timeFull, timeQueue, timeWork)
                        break

    except Exception as e:
        pass
        with open('errors.txt', 'ab') as f:
            f.write(b"-----ERROR-----\n")
            f.write(b"Log line: " + logLine + b"\n")
            f.write(b"Error:    " + str(e).encode() + b"\n")
            f.write(b"i:        " + str(i).encode() + b"\n")
            f.write(b"-----error-----\n")
            f.write(b"\n\n\n\n")
    i += 1
    
        

def readLogs():
    with open('spcd.log.11', 'rb') as file:
        for line in file:
            proccessLog(line)

def resizeDict():
    firstConn = None
    lastConn = None

    with open('spcd.log.11', 'rb') as file:
        for line in file:
            if line.find(b'Incoming') != -1:
                logData = line.split(b' ')[9::]
                if firstConn == None:
                    firstConn = logData[1][5:-1:]
                    lastConn = firstConn
                else:
                    lastConn = logData[1][5:-1:]

    keys = []
    for i in range(int(firstConn.decode(), 16), int(lastConn.decode(), 16) + 1):
        keys.append(hex(i)[2::])

    dictusers = dict.fromkeys(keys, 0)

    print(dictusers)



def main():
    os.remove('errors.txt') if os.path.exists('errors.txt') else None
    os.remove('users.txt') if os.path.exists('users.txt') else None
    # readLogs()
    # for user in users:
        # user.printUser('users.txt')
    resizeDict()

if __name__ == "__main__":
    main()