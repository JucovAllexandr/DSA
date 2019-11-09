using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;

namespace DSA
{
    public class DSA
    {
        public struct PublicKey
        {
            public BigInteger p;
            public BigInteger q;
            public BigInteger g;
            public BigInteger y;
        }

        private struct PrivateKey
        {
            public BigInteger x;
            public BigInteger k;
        }

        private static String message;
        
        static SHA1 sha1 = new SHA1CryptoServiceProvider();

        public static PublicKey publicKey { get; private set; }
        private static PrivateKey privateKey { get; set; }

        private static Random random = new Random();

        public static Tuple<BigInteger, BigInteger> Signature { get; set; }

        public static bool GenerateSignature(String msg)
        {
            while (true)
            {
                if (GenerateKeys())
                {
                    if (publicKey.q.IsProbablePrime(100) && publicKey.p.IsProbablePrime(100))
                    {
                        Console.WriteLine("Generated q = " + publicKey.q);
                        Console.WriteLine("Generated p = " + publicKey.p);
                        break;
                    }
                }
                else
                {
                    return false;
                }
            }

            BigInteger r = publicKey.g.Mod(publicKey.p).ModPow(privateKey.k, publicKey.p)
                .Mod(publicKey.q); //pow(publicKey.g, privateKey.k).Mod(publicKey.q);

            BigInteger km = privateKey.k.ModInverse(publicKey.q);
            BigInteger shaM = new BigInteger(sha1.ComputeHash(Encoding.ASCII.GetBytes(msg)));

            BigInteger s = km.Multiply(shaM.Add(privateKey.x.Multiply(r))).Mod(publicKey.q);

            Signature = new Tuple<BigInteger, BigInteger>(r, s);

            FileStream stream = File.Create("file.sig");
            stream.Write(Encoding.ASCII.GetBytes(r.ToString()+"\n"));
            stream.Write(Encoding.ASCII.GetBytes(s.ToString()+"\n"));
            
            stream.Write(Encoding.ASCII.GetBytes(publicKey.p.ToString()+"\n"));
            stream.Write(Encoding.ASCII.GetBytes(publicKey.q.ToString()+"\n"));
            stream.Write(Encoding.ASCII.GetBytes(publicKey.g.ToString()+"\n"));
            stream.Write(Encoding.ASCII.GetBytes(publicKey.y.ToString()+"\n"));
            stream.Write(Encoding.ASCII.GetBytes(msg+"\n"));
            
            stream.Flush();
            stream.Close();
            return true;
        }

        public static bool checkSignature()
        {
            Console.WriteLine("Message: "+message);
            BigInteger h = new BigInteger(sha1.ComputeHash(Encoding.ASCII.GetBytes(message)));

            BigInteger r = Signature.Item1;

            BigInteger s = Signature.Item2;

            if (r.CompareTo(publicKey.q) != -1 || r.CompareTo(BigInteger.Zero) == 0 ||
                s.CompareTo(publicKey.q) != -1 || s.CompareTo(BigInteger.Zero) == 0)
            {
                return false;
            }

            BigInteger w = s.ModInverse(publicKey.q);
            //Console.WriteLine("w="+w.ToString());

            BigInteger u1 = h.Multiply(w).Mod(publicKey.q);
            //Console.WriteLine("u1="+u1.ToString());
            BigInteger u2 = r.Multiply(w).Mod(publicKey.q);
            //Console.WriteLine("u2="+u2.ToString());

            //BigInteger x = pow(pKey.g, u1).Multiply(pow(pKey.y, u2)).Mod(pKey.p);
            BigInteger x = publicKey.g.ModPow(u1, publicKey.p).Multiply(publicKey.y.ModPow(u2, publicKey.p)).Mod(publicKey.p);
            //Console.WriteLine("x="+x.ToString());
            BigInteger v = x.Mod(publicKey.q);


            if (r.CompareTo(v) == 0)
            {
                Console.WriteLine("Signature accept");
                return true;
            }

            Console.WriteLine("Signature reject");

            Console.WriteLine("v=" + v);
            Console.WriteLine("r=" + r);
            return false;
        }


        private static bool GenerateKeys()
        {
            PublicKey PK = new PublicKey();
            PrivateKey PRK = new PrivateKey();

            int L = 512;
            int N = 160;

            BigInteger q; //= BigInteger.ProbablePrime(160, random);
            BigInteger p;

            while (true)
            {
                q = BigInteger.Zero;
                p = BigInteger.Zero;

                BigInteger rightVal = BigInteger.Two.Pow(159);
                BigInteger leftVal = BigInteger.Two.Pow(160);
                SHA1 sha1 = new SHA1CryptoServiceProvider();
                BigInteger seed;

                int g = 160;

                int n = (L - 1) / g;
                int b = (L - 1) % g;
                //int LM = 160 * n + b;

                BigInteger twoPowL = BigInteger.Two.Pow(L);
                BigInteger twoPowLm1 = BigInteger.Two.Pow(L - 1);

                do
                {
                    Org.BouncyCastle.Security.SecureRandom ran = new Org.BouncyCastle.Security.SecureRandom();
                    seed = new BigInteger(g, ran);

                    BigInteger u_1 = new BigInteger(sha1.ComputeHash(seed.ToByteArray()));
                    //Console.WriteLine("u_1="+u_1);

                    BigInteger u_2 =
                        new BigInteger(sha1.ComputeHash(seed.Add(BigInteger.One).Mod(BigInteger.Two.Pow(g))
                            .ToByteArray()));

                    //  Console.WriteLine("u_2="+u_2);
                    BigInteger u = u_1.Xor(u_2);
                    // Console.WriteLine("u = "+u);
                    q = u.Or(BigInteger.Two.Pow(159)).Or(BigInteger.One);
                } while (!q.IsProbablePrime(1000) && (q.CompareTo(rightVal) == 0 || q.CompareTo(rightVal) == -1 ||
                                                      q.CompareTo(leftVal) == 0 || q.CompareTo(leftVal) == 1) || q.CompareTo(BigInteger.Zero) == -1);

                //Console.WriteLine("Seed = "+seed);
                // Console.WriteLine("q = "+q);

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

                    if (p.CompareTo(twoPowLm1) == 1 || p.CompareTo(twoPowLm1) == 0)
                    {
                        if (p.IsProbablePrime(1000))
                        {
                            PK.p = p;
                            PK.q = q;

                            BigInteger h;

                            while (true)
                            {
                                h = new BigInteger(L, random);
                                //h = new BigInteger("3669993692229251313854754248816828779761634399763514055853838870257564499824336162921198089886421101332496624418678604946485757680612951632783009120193861");
                                if (h.CompareTo(p.Subtract(BigInteger.One)) == -1 && h.CompareTo(BigInteger.One) == 1)
                                {
                                    //h = pow(h, p.Subtract(BigInteger.One).Divide(q)).Mod(p);
                                    h = h.Mod(p).ModPow(p.Subtract(BigInteger.One).Divide(q), p);
                                    if (h.CompareTo(BigInteger.One) == 1)
                                    {
                                        break;
                                    }
                                }
                            }

                            PK.g = h;

                            //Console.WriteLine("g = " + h);

                            do
                            {
                                PRK.x = new BigInteger(N, random);
                            } while (PRK.x.CompareTo(q) == 1 || PRK.x.CompareTo(BigInteger.Zero) == -1);

                            // PK.y = pow(PK.g, PRK.x).Mod(p);

                            PK.y = PK.g.ModPow(PRK.x, p).Mod(p);

                            do
                            {
                                PRK.k = new BigInteger(N, random);
                            } while (PRK.x.CompareTo(q) == 1 || PRK.x.CompareTo(BigInteger.Zero) == -1);

                            publicKey = PK;
                            privateKey = PRK;

                            return true;
                        }
                    }

                    offset = offset.Add(new BigInteger(n.ToString())).Add(BigInteger.One);
                    counter = counter.Add(BigInteger.One);
                }
            }

            /*do
            {
                p = BigInteger.ProbablePrime(L, random);
                p = p.Subtract(p.Subtract(BigInteger.One).Remainder(q));
            }
            while (!(p.IsProbablePrime(4)));*/

            //q = new BigInteger("965374022299544018528982088693838875551253807301");
            //p = new BigInteger("8085529794999426297544118999403491855208277419768638549705160907398560722488833907398861054957260133768843576946761641628972879831456643124215719146511689");
        }

        public static void ReadFile(String filename)
        {
            StreamReader stream = File.OpenText(filename);

            
            BigInteger r = new BigInteger(stream.ReadLine());
            BigInteger s = new BigInteger(stream.ReadLine());
            
            BigInteger p = new BigInteger(stream.ReadLine());
            BigInteger q = new BigInteger(stream.ReadLine());
            BigInteger g = new BigInteger(stream.ReadLine());
            BigInteger y = new BigInteger(stream.ReadLine());

            message = stream.ReadLine();

            Signature = new Tuple<BigInteger, BigInteger>(r, s);
            
            PublicKey pb = new PublicKey();
            pb.p = p;
            pb.q = q;
            pb.g = g;
            pb.y = y;

            publicKey = pb;
        }
        
    }
}