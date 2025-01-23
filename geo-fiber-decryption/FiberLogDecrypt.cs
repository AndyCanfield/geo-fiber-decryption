using System.IO;
using System.Security.Cryptography;
using System.Text;

public class FiberLogDecrypt
{
    public static void Main(string[] args)
    {
        var decrypt = new FiberLogDecrypt();
        const int BufferSize = 1024;
        using (var fileStream = File.OpenRead(args[0]))
        {
            using (var streamReader = new StreamReader(fileStream, Encoding.UTF8, true, BufferSize))
            {
                using (var streamWriter = new StreamWriter(args[1], true))
                {
                    string line;
                    while ((line = streamReader.ReadLine()) != null)
                    {
                        var decryptedLine = decrypt.DecryptString(line);
                        streamWriter.WriteLine(decryptedLine);
                    }
                }
            }
        }
        
    }

    private byte[] InitializationVector = Encoding.Unicode.GetBytes("GroundControltoMajorTomGroundControltoMajorTomTakeyourproteinpillsandputyourhelmeton");

    private byte[] DerivedKeyFromPhrase
    {
        get
        {
            var passPhrase = "Youcannotpass,hesaid.Theorcsstoodstill,andadeadsilencefell.IamaservantoftheSecretFire,wielderoftheflameofAnor.Youcannotpass.Thedarkfirewillnotavailyou,flameofUdûn.GobacktotheShadow!Youcannotpass.";
            var verucaSalt = Encoding.Unicode.GetBytes("ItriedtokeepheronashortleashItriedtocalmherdownItriedtoramherintotheground");
            var iterations = 1000;
            var desiredKeyLength = 16; // 16 bytes equal 128 bits.
            var hashMethod = HashAlgorithmName.SHA384;
            return Rfc2898DeriveBytes.Pbkdf2(Encoding.Unicode.GetBytes(passPhrase),
                                             verucaSalt,
                                             iterations,
                                             hashMethod,
                                             desiredKeyLength);
        }

    }

    public string EncryptString(string clearText)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = DerivedKeyFromPhrase;
            aes.IV = InitializationVector;

            using (MemoryStream output = new())
            {
                using (CryptoStream cryptoStream = new(output, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(Encoding.Unicode.GetBytes(clearText));
                    cryptoStream.FlushFinalBlock();
                    return Encoding.Unicode.GetString(output.ToArray());
                }
            }
        }
    }

    private string DecryptString(string encryptedString)
    {
        var encryptedBytes = Encoding.Unicode.GetBytes(encryptedString);
        using (Aes aes = Aes.Create())
        {
            aes.Key = DerivedKeyFromPhrase;
            aes.IV = InitializationVector;

            using (MemoryStream input = new(encryptedBytes))
            {
                using (CryptoStream cryptoStream = new(input, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (MemoryStream output = new())
                    {
                        cryptoStream.CopyTo(output);
                        return Encoding.Unicode.GetString(output.ToArray());
                    }
                }
            }
        }
    }
}
