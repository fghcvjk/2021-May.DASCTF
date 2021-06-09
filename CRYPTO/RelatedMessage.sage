from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, getRandomRange
from secret import flag

flag = bytes_to_long(flag)

p, q = [getPrime(int(256)) for _ in range(2)]
a, b = [getRandomRange(1, p*q) for _ in range(2)]

class Task():
    def __init__(self, a, b, p, q, e):
        self.p, self.q = p, q
        self.a, self.b = a, b
        self.N = self.p*self.q
        self.e = e
        self.Kbits = 8

        Ep = EllipticCurve(IntegerModRing(self.p), [self.a, self.b])
        Eq = EllipticCurve(IntegerModRing(self.q), [self.a, self.b])
        N1 = Ep.order()
        N2 = 2*self.p+2-N1
        N3 = Eq.order()
        N4 = 2*self.q+2-N3

        self.d = {
            ( 1, 1): inverse_mod(self.e, lcm(N1, N3)),
            ( 1,-1): inverse_mod(self.e, lcm(N1, N4)),
            (-1, 1): inverse_mod(self.e, lcm(N2, N3)),
            (-1, 1): inverse_mod(self.e, lcm(N2, N4))
        }

        self.E = EllipticCurve(IntegerModRing(self.N), [self.a, self.b])

    def Enc(self, plaintext):
        try:
            msg_point = self.msg_to_point(plaintext)
            cip_point = self.e*msg_point
            return cip_point.xy()[0]
        except:
            return None

    def Dec(self, ciphertext):
        x = ciphertext
        w = x^3 + self.a*x + self.b % self.N

        P.<Yp> = PolynomialRing(Zmod(self.p))
        fp = x^3 + self.a*x + self.b -Yp^2
        yp = fp.roots()[0][0]

        P.<Yq> = PolynomialRing(Zmod(self.q))
        fq = x^3 + self.a*x + self.b -Yq^2
        yq = fq.roots()[0][0]

        y = crt([int(yp), int(yq)], [self.p, self.q])

        cip_point = self.E.point([x, y])

        legendre_symbol_p = legendre_symbol(w, self.p)
        legendre_symbol_q = legendre_symbol(w, self.q)
        msg_point = self.d[(legendre_symbol_p, legendre_symbol_q)]*cip_point

        return msg_point.xy()[0] >> self.Kbits

    def msg_to_point(self, x, shift=False):
        if shift:
            x <<= self.Kbits
        checkPoint = None
        for i in range(2<<self.Kbits):
            P.<Yp> = PolynomialRing(Zmod(self.p))
            fp = x^3 + self.a*x + self.b - Yp^2
            P.<Yq> = PolynomialRing(Zmod(self.q))
            fq = x^3 + self.a*x + self.b - Yq^2
            try:
                yp, yq = int(fp.roots()[0][0]), int(fq.roots()[0][0])
                y = crt([yp, yq], [self.p, self.q])
                E = EllipticCurve(IntegerModRing(self.p*self.q), [self.a, self.b])
                checkPoint = E.point((x, y))
                break
            except:
                x += 1
        return checkPoint

delta = 28552609273
e = 137
cip = Task(a, b, p, q, e)

print(f"a = {a}")
print(f"b = {b}")
print(f"n = {p*q}")


plaintext1 = cip.msg_to_point(flag, shift=True).xy()[0]
ciphertext1 = cip.Enc(plaintext1)
print(f"ciphertext1 = {ciphertext1}")

plaintext2 = cip.msg_to_point(flag+delta, shift=True).xy()[0]
ciphertext2 = cip.Enc(plaintext2)
print(f"ciphertext2 = {ciphertext2}")

delta = plaintext2 - plaintext1
print(f"delta = {delta}")

# a = 4281014323581546488462714122303747203636223358897123235803046898862939653328802115362584316327572195541081125920528501180620492421895128401613948866529122
# b = 1504110610934153564757355169781343270879282969971532470271782059859117769089994716068562704547770368420258743734175281689611986131092394954948339191589449
# n = 6638798722521613809421411597209101115203859862340555482590990067056543831415553727351714220257486793657912537305448979625073630917241320204281256125412671
# ciphertext1 = 6327639450575093157999054915625304951894564605402541939450801256931875815282143921161475586010526883609974743159835451980804875847625527741681757415519394
# ciphertext2 = 3275348139763310265438126795688591830796510682708632201044899744259822398076574133105844638686347122066389056025294466297206704146167073441486603569471235
# delta = 7309467973885
