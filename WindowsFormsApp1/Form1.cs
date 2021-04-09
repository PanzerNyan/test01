using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Serialization;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;



namespace WindowsFormsApp1
{
    public partial class Form1 : Form
    {
        RSAParameters privateKey;
        RSAParameters publicKey;
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        public Form1()
        {
            InitializeComponent();

            //RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(); 

            privateKey = rsa.ExportParameters(true);
            publicKey = rsa.ExportParameters(false);
        }

        private void Encryptbutton_Click(object sender, EventArgs e)
        {
            UnicodeEncoding byteConverter = new UnicodeEncoding();
            byte[] input = byteConverter.GetBytes(textBox1.Text);
            string output;

            output = RSAEncryption(textBox1.Text, publicKey);

            MessageBox.Show(output, "Encryption");
            string path = @"E:\Visual_Studio_Projects\Information_security_03\result.txt";
            if (!File.Exists(path))
            {
                using (StreamWriter sw = File.CreateText(path))
                {
                    sw.WriteLine (output);
                }
            }        
            
            GetPublicKeyString();
            textBox2.Text = output;
        }

        private void Decryptbutton_Click(object sender, EventArgs e)
        {
          

            UnicodeEncoding byteConverter = new UnicodeEncoding();
            //byte[] input = byteConverter.GetBytes(textBox2.Text);
            string output;

            output = RSADecryption(textBox2.Text, privateKey);

            MessageBox.Show(output, "Decryption");
        }

        static public string RSAEncryption(string dataToEncrypt, RSAParameters publicKeyInfo)
        {
            byte[] encryptedBytes = new byte[0];
            using (var RSA = new RSACryptoServiceProvider())
            {
                try
                {
                    UTF8Encoding encoder = new UTF8Encoding();

                    byte[] encryptThis = encoder.GetBytes(dataToEncrypt);

                    RSA.ImportParameters(publicKeyInfo);

                    int blockSize = (RSA.KeySize / 8) - 32;
                    byte[] buffer = new byte[blockSize];
                    byte[] encryptedBuffer = new byte[blockSize];
                    encryptedBytes = new byte[encryptThis.Length + blockSize - (encryptThis.Length % blockSize) + 32];

                    for (int i = 0; i < encryptThis.Length; i += blockSize)
                    {
                        if (2 * i > encryptThis.Length && ((encryptThis.Length - i) % blockSize != 0))
                        {
                            buffer = new byte[encryptThis.Length - i];
                            blockSize = encryptThis.Length - i;
                        }

                        if (encryptThis.Length < blockSize)
                        {
                            buffer = new byte[encryptThis.Length];
                            blockSize = encryptThis.Length;
                        }

                        Buffer.BlockCopy(encryptThis, i, buffer, 0, blockSize);
                        encryptedBuffer = RSA.Encrypt(buffer, false);
                        encryptedBuffer.CopyTo(encryptedBytes, i);
                    }
                }
                catch (CryptographicException ex)
                {
                    Console.Write(ex);
                }
                finally
                {
                    RSA.PersistKeyInCsp = false;
                }
            }
            return Convert.ToBase64String(encryptedBytes);
            /*RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSA.ImportParameters(RSAKeyInfo);
            return RSA.Encrypt(DataToEncrypt, DoOAEPPadding);*/
        }

        static public string RSADecryption(string dataToDecrypt, RSAParameters privateKeyInfo)
        {
            byte[] decryptedBytes;

            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                try
                {
                    byte[] bytesToDecrypt = Convert.FromBase64String(dataToDecrypt);

                    RSA.ImportParameters(privateKeyInfo);

                    int blockSize = RSA.KeySize / 8;

                    byte[] buffer = new byte[blockSize];

                    byte[] decryptedBuffer = new byte[blockSize];

                    decryptedBytes = new byte[dataToDecrypt.Length];

                    for (int i = 0; i < bytesToDecrypt.Length; i += blockSize)
                    {
                        if (2 * i > bytesToDecrypt.Length && ((bytesToDecrypt.Length - i) % blockSize != 0))
                        {
                            buffer = new byte[bytesToDecrypt.Length - i];
                            blockSize = bytesToDecrypt.Length - i;
                        }

                        if (bytesToDecrypt.Length < blockSize)
                        {
                            buffer = new byte[bytesToDecrypt.Length];
                            blockSize = bytesToDecrypt.Length;
                        }

                        Buffer.BlockCopy(bytesToDecrypt, i, buffer, 0, blockSize);
                        decryptedBuffer = RSA.Decrypt(buffer, false);
                        decryptedBuffer.CopyTo(decryptedBytes, i);
                    }
                }
                finally
                {
                    RSA.PersistKeyInCsp = false;
                }
            }

            var encoder = new UTF8Encoding();
            return encoder.GetString(decryptedBytes).TrimEnd(new[] { '\0' });
            //return Convert.ToString(decryptedBytes);

            /*RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSA.ImportParameters(RSAKeyInfo);
            return RSA.Decrypt(DataToDecrypt, DoOAEPPadding);*/
        }

        public void GetPublicKeyString()
        {
            //var rsa = new RSACryptoServiceProvider(2048);
            var rsaKeyPair = DotNetUtilities.GetRsaKeyPair(rsa);
            var writer = new StringWriter();
            var pemWriter = new PemWriter(writer);
            pemWriter.WriteObject(rsaKeyPair.Public);
            pemWriter.WriteObject(rsaKeyPair.Private);
            string path = @"E:\Visual_Studio_Projects\Information_security_03\key.txt";
            if (!File.Exists(path))
            {
                using (StreamWriter sw = File.CreateText(path))
                {
                    sw.WriteLine(writer);
                }
            }
            /*var lines = System.IO.File.ReadAllLines(@"E:\Visual_Studio_Projects\Information_systems_02\key.txt");
            System.IO.File.WriteAllLines(@"E:\Visual_Studio_Projects\Information_systems_02\key.txt", lines.Skip(1).ToArray());
            lines = System.IO.File.ReadAllLines(@"E:\Visual_Studio_Projects\Information_systems_02\key.txt");
            System.IO.File.WriteAllLines(@"E:\Visual_Studio_Projects\Information_systems_02\key.txt", lines.Take(lines.Length - 2).ToArray());*/
        }
    }
}

