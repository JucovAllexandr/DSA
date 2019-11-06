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
            GeneratePQ();
            pb.p = new BigInteger("283");
            pb.q = new BigInteger("47");
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

        private static BigInteger pow(BigInteger a, BigInteger n)
        {
            BigInteger v = BigInteger.One;

            for (BigInteger i = BigInteger.Zero; i.CompareTo(n) == -1; i = i.Add(BigInteger.One))
            {
                v = v.Multiply(a);
            }

            return v;
        }

        private static void GeneratePQ()
        {
            BigInteger q = BigInteger.Zero;
            int n = 50;
            BigInteger rightVal = BigInteger.Two.Pow(159);
            BigInteger leftVal = BigInteger.Two.Pow(160);
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            BigInteger seed;
            int g = 160;
            
            do
            {
                Org.BouncyCastle.Security.SecureRandom ran = new Org.BouncyCastle.Security.SecureRandom();
                seed = new BigInteger(g, ran);

                BigInteger u_1 = new BigInteger(sha1.ComputeHash(seed.ToByteArray()));
                BigInteger u_2 = new BigInteger(sha1.ComputeHash(seed.Add(BigInteger.One).Mod(BigInteger.Two.Pow(g)).ToByteArray()));
                BigInteger u = u_1.Xor(u_2);

                q = u.Or(BigInteger.Two.Pow(159)).Or(BigInteger.One);
                
            } while (!q.IsProbablePrime(100) && (q.CompareTo(rightVal) == 0 || q.CompareTo(rightVal) == -1 || q.CompareTo(leftVal) == 0 || q.CompareTo(leftVal) == 1));
            
            Console.WriteLine("Generated q = "+q);

            BigInteger offset = BigInteger.Two;
            BigInteger w = BigInteger.Zero;
            for (int k = 0; k <= n; k++)
            {
                BigInteger v = new BigInteger(sha1.ComputeHash(seed.Add(offset).Add(new BigInteger(k.ToString())).Mod(BigInteger.Two.Pow(g)).ToByteArray()));
                if (k == n)
                {
                    w = w.Add(v);
                }
                else
                {
                    w = w.Add(v);
                }

                
            }

        }
    }
}