from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

p_q_factor = [9391862407,9430502773,10075292329,11026721677,11040417907,11226344687,11251922861,11323087873,11823788947,11956868381,11988198241,12275776127,12481146047,12665684987,12913613113,13994049331,14050490287,14654363873,15023405711,15220261411,15307561417,15368817697,15407160677,15542678147,15597563977,15670906213,15937323977,16033412617,16069849819,16364771063,16708525877,16824901871,16945613717,16989252559]
c = 205177004615238731351591289040361532005323127359264835947822740716983136768854567377695810379804519529001108024493036086993996665747898010286174708794831060625006137526368615944348139474971845237186225728575712792546002359378966044221352721991288514552994761886718307832529541998738515780841823857133357743562860987020334737036728017641876582542
n = 325639898609361998216675485356547029510334941438608718141166837901883899013721165219381706028192734268885029193084232593567285725019760847868933043664019031900580901169223676044511691181256188001312697240016796398130516789089663998776488278420247724141996094725183171258977283897111350310752334184134343620555307982038647996863698517917545473309
e = 65537

phi = 1
for i in range(len(p_q_factor)):
    phi = (p_q_factor[i] - 1) * phi

d = inverse(e, phi)

print(long_to_bytes(pow(c, d, n)))