using System;
using VBNetEncrypt;

namespace Security {
    public class Encrypt {
        private Encryption encObj = new Encryption();

        private string _retVal = "";
        private string _reterr = "";
        private string _retSeed = "";
        private string _key = "Couldn't decrypt sql connect string";

        public string DecryptValue(string decryptKey, string value) {
            value = _ValidateText(value);
            if(!String.Equals(decryptKey, "", StringComparison.Ordinal))
                _key = decryptKey;
            if(!encObj.DecryptD6E(value, _key, ref _retVal, ref _reterr, ref _retSeed))
                _retVal = _reterr;
            //throw new Exception(reterr);
            return _retVal;
        }
        public string DecryptValue(string value) {
            value = _ValidateText(value);
            if(!encObj.DecryptD6E(value, _key, ref _retVal, ref _reterr, ref _retSeed))
                _retVal = _reterr;
            //throw new Exception(reterr);
            return _retVal;
        }

        public string EncryptValue(string encryptKey, string value) {
            if(!String.Equals(encryptKey, "", StringComparison.Ordinal))
                _key = encryptKey;
            if(!encObj.EncryptD6E(value, _key, ref _retVal, ref _reterr))
                _retVal = _reterr;
            //throw new Exception(reterr);
            return _retVal;
        }
        public string EncryptValue(string value) {
            if(!encObj.EncryptD6E(value, _key, ref _retVal, ref _reterr))
                _retVal = _reterr;
            //throw new Exception(reterr);
            return _retVal;
        }

        private string _ValidateText(string text) {
            if(text.StartsWith("~") && text.Length > 1)
                return text.Substring(1);
            return "";
        }
    }
}
