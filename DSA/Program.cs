using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;

namespace DSA
{
    class Program
    {
        static void Main(string[] args)
        {
          /*  byte[] bytes = Encoding.UTF8.GetBytes("My Content Thanks");
            SHA1 sha1 = new SHA1Managed();
            Console.Out.WriteLine(BitConverter.ToString(sha1.ComputeHash(bytes)).Replace("-",""));

            BigInteger q = Helper.GenerateBigIntegerPrimes(160);
            Console.WriteLine("q = "+q);
            BigInteger p = Helper.GenerateBigIntegerP(1024, q);
            
            Console.WriteLine("p = "+p);*/

          Console.Write("Enter 1 for create signature or 2 for check signature: ");
          String flag = Console.ReadLine();
          switch (flag)
          {
              case "1": 
              Console.Write("Enter message:");
              String msg = Console.ReadLine();
              if (DSA.GenerateSignature(msg))
              {
                  Console.WriteLine("File file.sig created");
              }
              else
              {
                  Console.WriteLine("Error create signature");
              }
              break;
              case "2":
                  Console.Write("Enter file name:");
                  String filename = Console.ReadLine();
                  
                  DSA.ReadFile(filename);
                  DSA.checkSignature();
                  break;
          }
          
          
        }
    }
}

