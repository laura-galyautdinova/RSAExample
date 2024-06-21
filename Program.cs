using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        try
        {
            // Utwórz instancję RSA
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Eksportuj klucze publiczny i prywatny do plików
                ExportPublicKey(rsa);
                ExportPrivateKey(rsa);

                // Szyfruj i deszyfruj plik tekstowy
                string inputFile = "input.txt";
                string encryptedFile = "encrypted.txt";
                string decryptedFile = "decrypted.txt";

                EncryptFile(inputFile, encryptedFile, rsa);
                DecryptFile(encryptedFile, decryptedFile, rsa);

                Console.WriteLine("Operacje zakończone pomyślnie.");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"Wystąpił wyjątek: {e.Message}");
        }
    }

    static void ExportPublicKey(RSACryptoServiceProvider rsa)
    {
        // Eksportuj klucz publiczny
        string publicKey = rsa.ToXmlString(false);
        File.WriteAllText("public_key.xml", publicKey);
        Console.WriteLine("Eksportowano klucz publiczny do pliku: public_key.xml");
    }

    static void ExportPrivateKey(RSACryptoServiceProvider rsa)
    {
        // Eksportuj klucz prywatny
        string privateKey = rsa.ToXmlString(true);
        File.WriteAllText("private_key.xml", privateKey);
        Console.WriteLine("Eksportowano klucz prywatny do pliku: private_key.xml");
    }

    static void EncryptFile(string inputFile, string outputFile, RSACryptoServiceProvider rsa)
    {
        // Odczytaj tekst do zaszyfrowania
        string plaintext = File.ReadAllText(inputFile);

        // Szyfruj dane
        byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(plaintext), false);

        // Zapisz zaszyfrowane dane do pliku
        File.WriteAllBytes(outputFile, encryptedData);
        Console.WriteLine($"Zaszyfrowano plik {inputFile} i zapisano jako {outputFile}");
    }

    static void DecryptFile(string inputFile, string outputFile, RSACryptoServiceProvider rsa)
    {
        // Odczytaj zaszyfrowane dane
        byte[] encryptedData = File.ReadAllBytes(inputFile);

        // Deszyfruj dane
        byte[] decryptedData = rsa.Decrypt(encryptedData, false);

        // Zapisz odszyfrowane dane do pliku
        File.WriteAllText(outputFile, Encoding.UTF8.GetString(decryptedData));
        Console.WriteLine($"Odszyfrowano plik {inputFile} i zapisano jako {outputFile}");
    }
}
