using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class FiberLogDecrypt
{
    public static void Main(string[] args)
    {
        var decrypt = new FiberLogDecrypt();
        const int BufferSize = 128;
        var delimString = "<----||||||---->";
        var delimiterByteArray = Encoding.UTF8.GetBytes(delimString);
        var delimSize = delimiterByteArray.Length;

        /*
        //Encrypt
        using (var fileStream = File.OpenRead(args[0]))
        {
            using (var streamReader = new StreamReader(fileStream))
            {
                using (var fs = new FileStream(args[1], FileMode.Create|FileMode.Append, FileAccess.Write))
                {
                    string line;
                    while ((line = streamReader.ReadLine()) != null)
                    {
                        var encryptedLine = decrypt.EncryptStringToBytes(line);
                        fs.Write(delimiterByteArray, 0, delimSize);
                        fs.Write(encryptedLine, 0, encryptedLine.Length);
                    }
                }
            }
        }*/

        //Decrypt
        using (var fileStream = File.OpenRead(args[0]))
        {
            int numBytesToRead = (int)fileStream.Length;
            //int numBytesRead = 0;
            var currentBytes = new List<byte>();
            using (var streamWriter = new StreamWriter(args[1]))
            {
                while (numBytesToRead > 0)
                {
                    byte[] nextChunk = new byte[delimSize];
                    // Read may return anything from 0 to numBytesToRead.
                    int n = fileStream.Read(nextChunk, 0, delimSize);

                    // Break when the end of the file is reached.
                    if (n == 0)
                    {
                        if (currentBytes.Count > 0)
                        {
                            var decryptedLine = decrypt.DecryptBytes(currentBytes.ToArray());
                            streamWriter.WriteLine(decryptedLine);
                            currentBytes.Clear();
                        }
                        break;
                    }
                    var stringChunk = Encoding.UTF8.GetString(nextChunk);
                    if (stringChunk != delimString)
                    {
                        currentBytes.AddRange(nextChunk);
                    }
                    else
                    {
                        if (currentBytes.Count > 0)
                        {
                            var decryptedLine = decrypt.DecryptBytes(currentBytes.ToArray());
                            streamWriter.WriteLine(decryptedLine);
                        }
                        currentBytes.Clear();
                    }

                    numBytesToRead -= n;
                }
                if (currentBytes.Count > 0)
                {
                    var decryptedLine = decrypt.DecryptBytes(currentBytes.ToArray());
                    streamWriter.WriteLine(decryptedLine);
                    currentBytes.Clear();
                }
            }

            
        }

    }

    private byte[] InitializationVector = Encoding.UTF8.GetBytes("GroundControltoM");

    private byte[] DerivedKeyFromPhrase
    {
        get
        {
            var passPhrase = "Youcannotpasshes";
            var verucaSalt = Encoding.UTF8.GetBytes("Itriedtokeephero");
            var iterations = 1000;
            var desiredKeyLength = 16; // 16 bytes equal 128 bits.
            var hashMethod = HashAlgorithmName.SHA384;
            return Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passPhrase),
                                             verucaSalt,
                                             iterations,
                                             hashMethod,
                                             desiredKeyLength);
        }

    }

    public byte[] EncryptStringToBytes(string clearText)
    {
        var clearTextBytes = Encoding.UTF8.GetBytes(clearText);
        using (Aes aes = Aes.Create())
        {
            aes.Key = DerivedKeyFromPhrase;
            //aes.BlockSize = 128;
            //aes.Mode = CipherMode.CTS;
            //aes.Padding = PaddingMode.None;
            aes.IV = InitializationVector;

            using (MemoryStream output = new())
            {
                using (CryptoStream cryptoStream = new(output, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(clearTextBytes);
                }
                return output.ToArray();
            }
        }
    }

    private string DecryptBytes(byte[] encryptedBytes)
    {
        //var encryptedBytes = Encoding.UTF8.GetBytes(encryptedString);
        using (Aes aes = Aes.Create())
        {
            aes.Key = DerivedKeyFromPhrase;
            //aes.BlockSize = 128;
            //aes.Mode = CipherMode.CTS;
            //aes.Padding = PaddingMode.None;
            aes.IV = InitializationVector;

            using (MemoryStream input = new(encryptedBytes))
            {
                using (CryptoStream cryptoStream = new(input, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cryptoStream))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }
}
