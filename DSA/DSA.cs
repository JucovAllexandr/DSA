using System;
using System.Collections.Generic;
using Org.BouncyCastle.Math;

namespace DSA
{
    public class DSA
    {
        public static BigInteger PublicKey { get; private set; }

        public static Tuple<BigInteger, BigInteger> Signature { get; set; }
        public static bool GenerateSignature()
        {
            
            BigInteger p = new BigInteger("283");
            BigInteger q = new BigInteger("47");
            BigInteger g = pow(new BigInteger("2"), p.Subtract(BigInteger.One).Divide(q)).Mod(p);//new BigInteger("60");
            Console.WriteLine("g="+g.ToString());
            BigInteger a = new BigInteger("24");
            PublicKey = pow(g, a).Mod(p);
            Console.WriteLine("public key="+PublicKey.ToString());
            BigInteger h = new BigInteger("41");
            
            BigInteger k = new BigInteger("15");

            BigInteger x = pow(g, k);

            x = x.Mod(p);

            Console.WriteLine("X="+x.ToString());

            BigInteger r = x.Mod(q);
            
            Console.WriteLine("r="+r.ToString());

            if (r.CompareTo(BigInteger.Zero) == 0)
            {
                return false;
            }

            BigInteger km = k.ModInverse(q);
            
            Console.WriteLine("k^-1 mod q="+km.ToString());

            BigInteger s = km.Multiply(h.Add(a.Multiply(r))).Mod(q);

            Signature = new Tuple<BigInteger, BigInteger>(r,s);
            
            Console.WriteLine("s="+s.ToString());
            
            
            //Console.WriteLine(pow(BigInteger.Two, BigInteger.Two).ToString()); 
            return true;
        }

        public static bool checkSignature(Tuple<BigInteger, BigInteger> signature, BigInteger publicKey)
        {
            BigInteger p = new BigInteger("283");
            BigInteger q = new BigInteger("47");
            BigInteger g = new BigInteger("64");
            
            //BigInteger a = new BigInteger("158");
            BigInteger h = new BigInteger("41");
            
            BigInteger r = signature.Item1;

            BigInteger s = signature.Item2;

            if (r.CompareTo(q) != -1 || r.CompareTo(BigInteger.Zero) == 0 ||
                s.CompareTo(q) != -1 || s.CompareTo(BigInteger.Zero) == 0)
            {
                return false;
            }

            BigInteger w = s.ModInverse(q);
            Console.WriteLine("w="+w.ToString());
            
            BigInteger u1 = h.Multiply(w).Mod(q);
            Console.WriteLine("u1="+u1.ToString());
            BigInteger u2 = r.Multiply(w).Mod(q);
            Console.WriteLine("u2="+u2.ToString());

            BigInteger x = pow(g, u1).Multiply(pow(publicKey, u2)).Mod(p);
            Console.WriteLine("x="+x.ToString());
            BigInteger v = x.Mod(q);
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
    }
}