using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;

namespace DSA
{
    public class DSA
    {
        //public static BigInteger PublicKey { get; private set; }

        public struct PublicKey
        {
            public BigInteger p;
            public BigInteger q;
            public BigInteger g;
            public BigInteger y;
        }
        
        public static PublicKey publicKey { get; private set; }
        
        
        public static Tuple<BigInteger, BigInteger> Signature { get; set; }
        public static bool GenerateSignature()
        {
            PublicKey pb = new PublicKey();
            if (GeneratePQ())
            {
                Console.WriteLine("Generated q = " + publicKey.q);
                Console.WriteLine("Generated p = " + publicKey.p);
                pb.p = publicKey.p;
                pb.q = publicKey.q;
            }
            else
            {
                return false;
            }

            //pb.p = new BigInteger("283");
            //pb.q = new BigInteger("47");
            
            pb.g = pow(new BigInteger("40"), pb.p.Subtract(BigInteger.One).Divide(pb.q)).Mod(pb.p);//new BigInteger("60");
            
            Console.WriteLine("g="+pb.g);
            
            BigInteger a = new BigInteger("24");
            
            pb.y = pow(pb.g, a).Mod(pb.p);
            Console.WriteLine("Y (pb)=" + pb.y);
            BigInteger h = new BigInteger("41");
            
            BigInteger k = new BigInteger("15");

            BigInteger x = pow(pb.g, k);

            x = x.Mod(pb.p);

            Console.WriteLine("X="+x);

            BigInteger r = x.Mod(pb.q);
            
            Console.WriteLine("r="+r);

            if (r.CompareTo(BigInteger.Zero) == 0)
            {
                return false;
            }

            BigInteger km = k.ModInverse(pb.q);
            
            Console.WriteLine("k^-1 mod q="+km.ToString());

            BigInteger s = km.Multiply(h.Add(a.Multiply(r))).Mod(pb.q);

            Signature = new Tuple<BigInteger, BigInteger>(r,s);
            
            Console.WriteLine("s="+s.ToString());

            publicKey = pb;
            //Console.WriteLine(pow(BigInteger.Two, BigInteger.Two).ToString()); 
            return true;
        }

        public static bool checkSignature(Tuple<BigInteger, BigInteger> signature, PublicKey pKey)
        {
            //BigInteger p = new BigInteger("283");
            //BigInteger q = new BigInteger("47");
            //BigInteger g = new BigInteger("64");
            
            //BigInteger a = new BigInteger("158");
            BigInteger h = new BigInteger("41");
            
            BigInteger r = signature.Item1;

            BigInteger s = signature.Item2;

            if (r.CompareTo(pKey.q) != -1 || r.CompareTo(BigInteger.Zero) == 0 ||
                s.CompareTo(pKey.q) != -1 || s.CompareTo(BigInteger.Zero) == 0)
            {
                return false;
            }

            BigInteger w = s.ModInverse(pKey.q);
            Console.WriteLine("w="+w.ToString());
            
            BigInteger u1 = h.Multiply(w).Mod(pKey.q);
            Console.WriteLine("u1="+u1.ToString());
            BigInteger u2 = r.Multiply(w).Mod(pKey.q);
            Console.WriteLine("u2="+u2.ToString());

            BigInteger x = pow(pKey.g, u1).Multiply(pow(pKey.y, u2)).Mod(pKey.p);
            Console.WriteLine("x="+x.ToString());
            BigInteger v = x.Mod(pKey.q);
            Console.WriteLine("v="+v.ToString());

            if (r.CompareTo(v) == 0)
            {
                Console.WriteLine("Signature accept");
                return true;
            }
            
            Console.WriteLine("Signature reject");
            return false;
        }

        private static BigInteger pow(BigInteger a, BigInteger _pow)
        {
            Console.WriteLine("a^pow a="+a+"; n="+_pow);
            BigInteger res = BigInteger.One;

            /*for (BigInteger i = BigInteger.Zero; i.CompareTo(n) == -1; i = i.Add(BigInteger.One))
            {
                v = v.Multiply(a);
            }*/

            while (_pow.CompareTo(BigInteger.Zero) == 1)
            {
                if (_pow.Mod(BigInteger.Two).CompareTo(BigInteger.One) == 0)
                {
                    res = res.Multiply(a);
                }
                res = res.Multiply(a);
                _pow = _pow.Divide(BigInteger.Two);
            }
            

            return res;
        }

        private static bool GeneratePQ()
        {
            PublicKey PK = publicKey;
            while (true)
            {
                BigInteger q = BigInteger.Zero;
                BigInteger p = BigInteger.Zero;
                int n = 6;
                BigInteger rightVal = BigInteger.Two.Pow(159);
                BigInteger leftVal = BigInteger.Two.Pow(160);
                SHA1 sha1 = new SHA1CryptoServiceProvider();
                BigInteger seed;
                int g = 160;

                int L = 1024;
                int b = 63;
                int LM = 160 * n + b;

                BigInteger twoPowL = BigInteger.Two.Pow(L);
                BigInteger twoPowLm1 = BigInteger.Two.Pow(LM);

                do
                {
                    Org.BouncyCastle.Security.SecureRandom ran = new Org.BouncyCastle.Security.SecureRandom();
                    seed = new BigInteger(g, ran);

                    BigInteger u_1 = new BigInteger(sha1.ComputeHash(seed.ToByteArray()));
                    BigInteger u_2 =
                        new BigInteger(sha1.ComputeHash(seed.Add(BigInteger.One).Mod(BigInteger.Two.Pow(g))
                            .ToByteArray()));
                    BigInteger u = u_1.Xor(u_2);

                    q = u.Or(BigInteger.Two.Pow(159)).Or(BigInteger.One);

                } while (!q.IsProbablePrime(100) && (q.CompareTo(rightVal) == 0 || q.CompareTo(rightVal) == -1 ||
                                                     q.CompareTo(leftVal) == 0 || q.CompareTo(leftVal) == 1));

                

                BigInteger offset = BigInteger.Two;
                BigInteger counter = BigInteger.Zero;

                while (counter.CompareTo(new BigInteger("4096")) == -1)
                {
                    BigInteger w = BigInteger.Zero;


                    for (int k = 0; k <= n; k++)
                    {
                        BigInteger v = new BigInteger(sha1.ComputeHash(seed.Add(offset)
                            .Add(new BigInteger(k.ToString()))
                            .Mod(BigInteger.Two.Pow(g)).ToByteArray()));
                        if (k == n)
                        {
                            w = w.Add(v).Mod(BigInteger.Two.Pow(b)).Multiply(BigInteger.Two.Pow(n * 160));
                        }
                        else
                        {
                            w = w.Add(v).Multiply(BigInteger.Two.Pow(k * 160));
                        }
                    }


                    if (w.CompareTo(BigInteger.Zero) == -1 || w.CompareTo(twoPowLm1) == 1 ||
                        w.CompareTo(twoPowLm1) == 0)
                    {
                        //Console.WriteLine("2^(L-1) =" + twoPowLm1);
                        Console.WriteLine("Bad W = " + w);
                        return false;
                    }

                    //Console.WriteLine("W = " + w);

                    BigInteger x = w.Add(twoPowLm1);

                    if (x.CompareTo(twoPowLm1) == -1 || x.CompareTo(twoPowL) == 1 || x.CompareTo(twoPowL) == 0)
                    {
                        Console.WriteLine("Bad X = " + x);
                        return false;
                    }

                    //Console.WriteLine("X = " + x);

                    BigInteger c = x.Mod(BigInteger.Two.Multiply(q));
                    p = x.Subtract(c.Subtract(BigInteger.One));

                    if (p.CompareTo(twoPowLm1) == 1)
                    {
                        if (p.IsProbablePrime(100))
                        {
                            PK.p = p;
                            PK.q = q;
                            publicKey = PK;
                            return true;
                        }
                    }

                    offset = offset.Add(new BigInteger(n.ToString())).Add(BigInteger.One);
                    counter = counter.Add(BigInteger.One);
                }
            }
            
        }
    }
}