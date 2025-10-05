import os

dictusers = {}

class User:
    def __init__(self, log):
        self.connection = log[1][5:-1:]
        self.ip = log[3]
        self.queries = []
        self.worker = b""
        self.queryId = b""
        self.id = b""
        self.textFull = b""
        self.textQuery = b""
        self.timeFull = b""
        self.timeQueue = b""
        self.timeWork = b""
        self.dateTime = b""

    def setQueryId(self, queryId):
        self.queryId = queryId
    
    def setQueryText(self, text):
        self.textQuery = b"\x20".join(text)

    def setQuery(self, id, textFull):
        self.id = id
        self.textFull = textFull

    def setWorker(self, worker):
        self.worker = worker

    def setTime(self, timeFull, timeQueue, timeWork):
        self.timeFull = timeFull
        self.timeQueue = timeQueue
        self.timeWork = timeWork

    def setDateTime(self, dateTime):
        self.dateTime = dateTime[0][1::] + b'_' + dateTime[1][:-1:]

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
            f.write(b"DateTime:   " + self.dateTime + b"\n")
            f.write(b"-----QUERY-----\n")
            f.write(b"Qid:        " + self.queryId + b"\n")
            f.write(b"Id:         " + self.id + b"\n")
            f.write(b"Text full:  " + self.textFull + b"\n")
            f.write(b"Text:       " + self.textQuery + b"\n")
            f.write(b"-----TIME------\n")
            f.write(b"Time full:  " + self.timeFull + b"\n")
            f.write(b"Time queue: " + self.timeQueue + b"\n")
            f.write(b"Time work:  " + self.timeWork + b"\n")
            f.write(b"-----user------\n")
            f.write(b"\n\n")

def byteTextToHex(byteText):
    return hex(int(byteText.decode(), 16))

def detectIncoming(logData, dateTime):
    dictusers[hex(int(logData[1][5:-1:].decode(), 16))[2::]] = User(logData)
    dictusers[hex(int(logData[1][5:-1:].decode(), 16))[2::]].setDateTime(dateTime)

def detectOn(logData):
    dictusers[byteTextToHex(logData[1][5:-1:])[2::]].setQueryId(logData[3][6:-1:])
    textQuery = logData[5::]
    if textQuery[-1][-1] == 10:
        textQuery[-1] = textQuery[-1][:-1:]
    dictusers[byteTextToHex(logData[1][5:-1:])[2::]].setQueryText(textQuery)

def detectQuery(logData):
    queryIdNew = logData[0][6:-1:].decode()
    queryIdFirst = dictusers[list(dictusers.keys())[0]].getQueryId().decode()
    queryIdDiff = int(queryIdNew, 16) - int(queryIdFirst, 16)
    connectionFirst = int(list(dictusers.keys())[0], 16)
    connectionNew = str(hex(connectionFirst + queryIdDiff))[2::]
    queryId = logData[0][6:-1:]
    id = logData[1][1:-1:]
    text = logData[4][2:(logData[4].find(b'&_')):]
    dictusers[connectionNew].setQuery(id, text)

def detectSending(logData):
    queryIdNew = logData[1][6:-1:].decode()
    queryIdFirst = dictusers[list(dictusers.keys())[0]].getQueryId().decode()
    queryIdDiff = int(queryIdNew, 16) - int(queryIdFirst, 16)
    connectionFirst = int(list(dictusers.keys())[0], 16)
    connectionNew = str(hex(connectionFirst + queryIdDiff))[2::]
    dictusers[connectionNew].setWorker(logData[4][7:-2:])

def detectEnd(logData):
    queryIdNew = logData[1][6:-1:].decode()
    queryIdFirst = dictusers[list(dictusers.keys())[0]].getQueryId().decode()
    queryIdDiff = int(queryIdNew, 16) - int(queryIdFirst, 16)
    connectionFirst = int(list(dictusers.keys())[0], 16)
    connectionNew = str(hex(connectionFirst + queryIdDiff))[2::]
    timeFull = logData[6]
    timeQueue = logData[8]
    timeWork = logData[10]
    dictusers[connectionNew].setTime(timeFull, timeQueue, timeWork)

def proccessLog(logLine):
    logData = logLine.split(b' ')[9::]
    logDateTime = logLine.split(b' ')[6:8:]
    # print(logDateTime)

    try:
        if (logData[0] == b'Incoming'):
            detectIncoming(logData, logDateTime)
            
        if (logData[0] == b'On'):
            detectOn(logData)

        if (logData[0][:5:] == b'Query'):
            detectQuery(logData)

        if (logData[0] == b'Sending'):
            detectSending(logData)
        
        if (logData[0] == b'End'):
            detectEnd(logData)

    except Exception as e:
        with open('errors.txt', 'ab') as f:
            f.write(b"-----ERROR-----\n")
            f.write(b"Log line:     " + logLine + b"\n")
            f.write(b"Unexpect err: " + str(e).encode() + b"\n")
            f.write(b"-----error-----\n")
            f.write(b"\n\n\n\n")

def parseLogs():
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
    for i in range(int(byteTextToHex(firstConn), 16), int(byteTextToHex(lastConn), 16) + 1):
        keys.append(hex(i)[2::])

    dictusers = dict.fromkeys(keys, 0)

def determineUsers():
    unniqueIPs = set()

    for user in dictusers:
        unniqueIPs.add(dictusers[user].ip)
    
    print("Unique IPs:\t\t", len(unniqueIPs))
    # print(unniqueIPs)

def determineQuery():
    uniqueQueries = set()

    for user in dictusers:
        uniqueQueries.add(dictusers[user].textQuery)

    print("Unique Queries:\t\t", len(uniqueQueries))

def determineAverageWords():
    allWords = 0
    allQueris = 0

    for user in dictusers:
        if len(dictusers[user].textFull):
            allQueris += 1
            allWords += len(dictusers[user].textQuery.split())
    
    averageWords = allWords / allQueris

    print("Average words count:\t", averageWords)

def determineAverageTime():
    timeCount = 0
    timeAll = 0

    for user in dictusers:
        if dictusers[user].timeFull != b"":
            timeCount += 1
            timeAll += float(dictusers[user].timeFull.decode())
    
    averageTime = timeAll / timeCount

    print("Average time count:\t", averageTime)

def determineMaxTime():
    maxTime = 0

    for user in dictusers:
        if dictusers[user].timeFull != b"":
            currentTime = float(dictusers[user].timeFull.decode())
            if currentTime > maxTime:
                maxTime = currentTime

    print("Maximum time:\t\t", maxTime)

def determineAverageQuerySec():
    dictDateTime = {}

    for user in dictusers:
        if not (dictusers[user].dateTime in dictDateTime):
            dictDateTime.update({dictusers[user].dateTime: 1})
        else:
            dictDateTime[dictusers[user].dateTime] += 1
    
    allDateTimes = 0
    allQueries = 0

    for dateTime in dictDateTime:
        allDateTimes += 1
        allQueries += dictDateTime[dateTime]

    averageQuerySec = allQueries / allDateTimes
    print("Average queries per sec:", averageQuerySec)
    

def dataProccessing():
    determineUsers()
    determineQuery()
    determineAverageWords()
    determineAverageTime()
    determineMaxTime()
    determineAverageQuerySec()

def main():
    os.remove('errors.txt') if os.path.exists('errors.txt') else None
    os.remove('users.txt') if os.path.exists('users.txt') else None

    resizeDict()
    parseLogs()

    dataProccessing()

if __name__ == "__main__":
    main()