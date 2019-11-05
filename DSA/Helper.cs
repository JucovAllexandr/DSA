using System;
using System.Runtime.ConstrainedExecution;
using Org.BouncyCastle.Math;

namespace DSA
{
    public class Helper
    {
        static public Org.BouncyCastle.Math.BigInteger GenerateBigIntegerPrimes(int bits)
        {
            Org.BouncyCastle.Security.SecureRandom ran = new Org.BouncyCastle.Security.SecureRandom();
            Org.BouncyCastle.Math.BigInteger c = new Org.BouncyCastle.Math.BigInteger(bits, ran);
            
            for (; ; )
            {
                if (c.IsProbablePrime(100) == true) break;
                c = c.Subtract(new Org.BouncyCastle.Math.BigInteger("1"));
            }
            return (c);
        }

        static public Org.BouncyCastle.Math.BigInteger GenerateBigIntegerP(int bits, BigInteger q)
        {
            Org.BouncyCastle.Security.SecureRandom ran = new Org.BouncyCastle.Security.SecureRandom();
            BigInteger c = new BigInteger(bits, ran);

            while (true)
            {
               // Console.WriteLine("c"+c);
               // Console.WriteLine("q"+q);
               // Console.WriteLine("mod"+c.Mod(q));
                if (c.Mod(q).Equals(BigInteger.Zero))
                {
                    break;
                }
                //c = c.Subtract(new Org.BouncyCastle.Math.BigInteger("1"));
                c = c.Subtract(q);
            }
            Console.WriteLine("c"+c);
            Console.WriteLine("q"+q);
            return c.Add(BigInteger.One);
        }
    }
}