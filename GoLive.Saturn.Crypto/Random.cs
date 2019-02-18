﻿using System;
using System.Linq;
using System.Security.Cryptography;

namespace GoLive.Saturn.Crypto
{
    public class Random
    {
        public static string GetRandomString(int length, string characterSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"?$%^&*()-_=+[]#';/\\")
        {
            if (length < 0)
                throw new ArgumentException("length must not be negative", "length");
            if (length > int.MaxValue / 8) // 250 million chars ought to be enough for anybody
                throw new ArgumentException("length is too big", "length");
            if (characterSet == null)
                throw new ArgumentNullException("characterSet");
            var characterArray = characterSet.Distinct().ToArray();
            if (characterArray.Length == 0)
                throw new ArgumentException("characterSet must not be empty", "characterSet");

            var bytes = new byte[length * 8];
            new RNGCryptoServiceProvider().GetBytes(bytes);
            var result = new char[length];
            for (int i = 0; i < length; i++)
            {
                ulong value = BitConverter.ToUInt64(bytes, i * 8);
                result[i] = characterArray[value % (uint)characterArray.Length];
            }

            return new string(result);
        }
    }
}