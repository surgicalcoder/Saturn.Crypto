using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GoLive.Saturn.Crypto
{
    public class Hash
    {
        public static string CreateHMAC(string message, string secret)
        {
            if (String.IsNullOrWhiteSpace(message))
            {
                throw new ArgumentNullException(nameof(message));
            }

            if (string.IsNullOrWhiteSpace(secret))
            {
                throw new ArgumentNullException(nameof(secret));
            }

            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }

        public static string CreateTimeStampedHMAC(string message, string secret, DateTime dt = default(DateTime))
        {
            if (String.IsNullOrWhiteSpace(message))
            {
                throw new ArgumentNullException(nameof(message));
            }

            if (string.IsNullOrWhiteSpace(secret))
            {
                throw new ArgumentNullException(nameof(secret));
            }

            if (dt == default(DateTime))
            {
                dt = DateTime.UtcNow;
            }
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(message + dt.ToString("O"));
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }

        public static string CalculateSHA3(string Input)
        {
            using (SHA3Managed managed = new SHA3Managed(512))
            {
                return ByteArrayToString(managed.ComputeHash(Encoding.UTF8.GetBytes(Input)));

            }
        }

        public static string CalculateSHA3FromFile(string FilePath)
        {
            using (SHA3Managed managed = new SHA3Managed(512))
            {
                using (StreamReader reader = new StreamReader(FilePath))
                {
                    return ByteArrayToString(managed.ComputeHash(reader.BaseStream));
                }
            }
        }

        public static string ByteArrayToString(byte[] ba)
        {
            string hex = BitConverter.ToString(ba);
            return hex.Replace("-", "");
        }


        public static string CalculateSHA512(string Input)
        {
            using (MemoryStream memStream = new MemoryStream(Encoding.UTF8.GetBytes(Input)))
            {
                return CalculateSHA512(memStream);
            }
        }

        public static string CalculateSHA512(Stream streamIn)
        {
            const int bufferSizeForMd5Hash = 1024 * 1024 * 8; // 8MB
            string hashString;
            using (var md5Prov = new SHA256Managed())
            {
                int readCount;
                long bytesTransfered = 0;
                var buffer = new byte[bufferSizeForMd5Hash];
                while ((readCount = streamIn.Read(buffer, 0, buffer.Length)) != 0)
                {
                    // Need to figure out if this is final block
                    if (bytesTransfered + readCount == streamIn.Length)
                    {
                        md5Prov.TransformFinalBlock(buffer, 0, readCount);
                    }
                    else
                    {
                        md5Prov.TransformBlock(buffer, 0, bufferSizeForMd5Hash, buffer, 0);
                    }
                    bytesTransfered += readCount;
                }
                hashString = BitConverter.ToString(md5Prov.Hash).Replace("-", String.Empty);
                md5Prov.Clear();
            }
            return hashString;
        }
    }
}