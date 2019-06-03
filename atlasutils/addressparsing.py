def chopaddress(address):
    addy = address.strip(' \*$')
    try:
        if (addy[1] == 'x'):
            addy = addy[2:]
        if (addy[0] == '0'):
            addy = addy[1:]
    except:
        pass
    return addy
            