using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MyEncryptionLib
{
    public static class clsEncryption
    {
        /// <summary>
        /// Provides static methods for symmetric encryption and decryption using the Advanced Encryption Standard (AES) algorithm.
        /// </summary>
        public static class Symmetric
        {
            /// <summary>
            /// Decrypts the provided cipher text using the specified key and AES algorithm.
            /// </summary>
            /// <param name="cipherText">The encrypted text to decrypt.</param>
            /// <param name="key">The secret key used for decryption.</param>
            /// <returns>The decrypted plain text.</returns>
            /// <exception cref="ArgumentNullException">Thrown if either cipherText or key is null or empty.</exception>
            /// <exception cref="CryptographicException">Thrown if decryption fails due to invalid data or key.</exception>
            public static string Decrypt(string cipherText, string key)
            {
                using (Aes aesAlg = Aes.Create())
                {
                    // Set the key and IV for AES decryption
                    aesAlg.Key = Encoding.UTF8.GetBytes(key);
                    aesAlg.IV = new byte[aesAlg.BlockSize / 8];


                    // Create a decryptor
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);


                    // Decrypt the data
                    using (var msDecrypt = new System.IO.MemoryStream(Convert.FromBase64String(cipherText)))
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    using (var srDecrypt = new System.IO.StreamReader(csDecrypt))
                    {
                        // Read the decrypted data from the StreamReader
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
            /// <summary>
            /// Encrypts the provided plain text using the specified key and AES algorithm.
            /// </summary>
            /// <param name="plainText">The plain text to encrypt.</param>
            /// <param name="key">The secret key used for encryption Should Be 16 char.</param>
            /// <returns>The encrypted text as a Base64-encoded string.</returns>
            /// <exception cref="ArgumentNullException">Thrown if either plainText or key is null or empty.</exception>
            /// <exception cref="CryptographicException">Thrown if encryption fails.</exception>
            public static string Encrypt(string plainText, string key)
            {
                using (Aes aesAlg = Aes.Create())
                {
                    // Set the key and IV for AES encryption
                    aesAlg.Key = Encoding.UTF8.GetBytes(key);
                    aesAlg.IV = new byte[aesAlg.BlockSize / 8];


                    // Create an encryptor
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);


                    // Encrypt the data
                    using (var msEncrypt = new System.IO.MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (var swEncrypt = new System.IO.StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }


                        // Return the encrypted data as a Base64-encoded string
                        return Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }
        }

        /// <summary>
        /// Provides static methods for asymmetric encryption, decryption, and key generation using the RSA algorithm.
        /// </summary>
        public static class Asymmetric
        {
            public class Keys
            {
                public string PublicKey { get; }
                public string PrivateKey { get; }
                public Keys()
                {
                    try
                    {
                        // Generate public and private key pair
                        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                        {
                            // Get the private & Public Keys
                            this.PrivateKey = rsa.ToXmlString(true);
                            this.PublicKey = rsa.ToXmlString(false);
                        }
                    }
                    catch (CryptographicException ex)
                    {
                        Console.WriteLine($"Encryption/Decryption error: {ex.Message}");
                        Console.ReadKey();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                        Console.ReadKey();
                    }
                }
            }


            /// <summary>
            /// Encrypts the given plain text using the provided public key and RSA algorithm.
            /// </summary>
            /// <param name="plainText">The plain text to be encrypted.</param>
            /// <param name="publicKey">The public key in XML format.</param>
            /// <returns>The encrypted data as a Base64-encoded string.</returns>
            /// <exception cref="CryptographicException">Thrown if an error occurs during encryption.</exception>
            public static string Encrypt(string plainText, string publicKey)
            {
                try
                {
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        rsa.FromXmlString(publicKey);


                        byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), false);
                        return Convert.ToBase64String(encryptedData);
                    }
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine($"Encryption error: {ex.Message}");
                    throw; // Rethrow the exception to be caught in the Main method
                }
            }
            /// <summary>
            /// Decrypts the given cipher text using the provided private key and RSA algorithm.
            /// </summary>
            /// <param name="cipherText">The cipher text to be decrypted.</param>
            /// <param name="privateKey">The private key in XML format.</param>
            /// <returns>The decrypted plain text.</returns>
            /// <exception cref="CryptographicException">Thrown if an error occurs during decryption.</exception>
            public static string Decrypt(string cipherText, string privateKey)
            {
                try
                {
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        rsa.FromXmlString(privateKey);


                        byte[] encryptedData = Convert.FromBase64String(cipherText);
                        byte[] decryptedData = rsa.Decrypt(encryptedData, false);


                        return Encoding.UTF8.GetString(decryptedData);
                    }
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine($"Decryption error: {ex.Message}");
                    throw; // Rethrow the exception to be caught in the Main method
                }
            }


        }
        /// <summary>
        /// Provides static methods for computing hash values of input data.
        /// </summary>
        public static class Hashing
        {
            /// <summary>
            /// Computes the SHA-256 hash of the given input string.
            /// </summary>
            /// <param name="input">The input string to be hashed.</param>
            /// <returns>The computed SHA-256 hash as a lowercase hexadecimal string.</returns>
            public static string ComputeHash(string input)
            {
                // Create an instance of the SHA-256 algorithm
                using (SHA256 sha256 = SHA256.Create())
                {
                    // Compute the hash value from the UTF-8 encoded input string
                    byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));

                    // Convert the byte array to a lowercase hexadecimal string
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
        }


    }
}