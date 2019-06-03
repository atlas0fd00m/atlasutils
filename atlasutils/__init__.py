import sys

ERROR_COUNT=0

def errorhandler():
    global ERROR_COUNT
    ERROR_COUNT += 1
    x,y,z = sys.exc_info()
    sys.excepthook(x,y,z)
    
