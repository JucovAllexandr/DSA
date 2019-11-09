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

