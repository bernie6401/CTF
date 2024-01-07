from Crypto.Util.number import bytes_to_long, long_to_bytes

C1=14329373319517329910094595162375723690471194953995321558556169294254162277705538668453980243325339753427816261142029111475247144234846016882885727145663533071136182130119228053292209771208809984132492746528809625269282592753829983388507521976867243377477954640849537476887741331874703615109385975612959091414468380017031536777991734476516317157981442455577238107616801315626655159876761118421984338130984228353230728562696860822826559627356625141123883884945447094600300992458333564564296532813708795906558439681619942846653080988908977672946445195172938376300391179821528530252529176854868260667172992998933129501608
C2=11389521277483219174710268840773862474800275636835679065758799085530280493963918298152804099928040708104232332955946587999569406575670872205956724694146228920807898859535438101281568455368108648046741664442986581906590194429333064239333038116111580160586779124315174833920044365962516606754570281540990881959906671506211283154958977355263511481610818215654414279413081975920352313374317999647646760566197547053299198474475474002853759414754208537251177410768509696961532935449922991417583681261962975551707020572807024862846209206597691395619892437529584699712218242227025180039543477416133621794570299309289200097792
N=27774150882677842211492548709193696703098757465302842179492926974516706384656342991972681477009974966222604385423065899792406253646130584101515112374044496297511781909760943153866973803586182512632536710983363319883574434583670917346858845127410163793596621244561688724195728965882142664951437819873591646219487892296378933749950894525312038479193727519196480493923706929294762865297318055034541880315629230099458535789176673342817343298709444390541822512275435396362064116339684017528311855470999853571243459256591205349962478941916814022489927831386782615562016980118698497283997963609853039627654406282758401516101
e = 3
BITSIZE =  N.bit_length()
m = floor(BITSIZE/(e*e)) - 400


def short_pad_attack(c1, c2, e, n):
    PRxy.<x,y> = PolynomialRing(Zmod(n))
    PRx.<xn> = PolynomialRing(Zmod(n))
    PRZZ.<xz,yz> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x+y)^e - c2
    q1 = g1.change_ring(PRZZ)
    q2 = g2.change_ring(PRZZ)
    h = q2.resultant(q1)
    h = h.univariate_polynomial()
    h = h.change_ring(PRx).subs(y=xn)
    h = h.monic()
    kbits = n.nbits()//(2*e*e)
    diff = h.small_roots(X=2^m, beta=0.5)[0]
    return diff


def related_message_attack(c1, c2, diff, e, n):
    PRx.<x> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x+diff)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    return -gcd(g1, g2)[0]


diff = short_pad_attack(C1, C2, e, n)
m1 = related_message_attack(C1, C2, diff, e, n)
long_to_bytes(int(int(m1) // 2**m))